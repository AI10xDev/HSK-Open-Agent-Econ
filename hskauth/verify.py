"""Strict verification of a signed conditioned message.

The gate is all-or-nothing: a signature unlocks the downstream work **if and
only if** every condition below holds. Each one is reported individually so a
caller can see exactly which condition failed.

=========================  =============================================
``schema``                 all required fields present and well-formed
``signature_format``       65-byte ``0x``-prefixed hex
``signature_recovery``     EIP-191 recovery succeeds
``signer_matches``         recovered address == the address in the message
``chain``                  chainId is the configured HSKChain network
``network``                networkName is the configured network
``domain``                 message domain == this service
``uri``                    message URI == the endpoint being unlocked
``statement``              user consented to the expected text
``address_allowed``        signer is on the allowlist (if one is configured)
``onchain``                signer has a footprint on that chain (opt-in)
``issued_at``              not issued in the future (beyond clock skew)
``not_expired``            expiration time is still in the future
``nonce_issued``           nonce was handed out by this server
``nonce_unused``           nonce has not been spent before (replay defence)
=========================  =============================================

The chain/network conditions are read from :class:`VerifierConfig` rather than
hardcoded, which is what lets the same service run against HSKChain mainnet
(177) or testnet (133) without a signature issued for one being honoured on the
other.

Note on ordering: nonce is *consumed* last, and only when every other condition
passed, so a malformed or mismatched submission never burns a nonce.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol

from eth_utils import to_checksum_address

from .message import (
    DEFAULT_CHAIN_ID,
    DEFAULT_DOMAIN,
    DEFAULT_NETWORK_NAME,
    DEFAULT_STATEMENT,
    DEFAULT_URI,
    ConditionedMessage,
    generate_nonce,
    utcnow,
)


class Condition(str, Enum):
    """The individual checks a signed message must satisfy."""

    SCHEMA = "schema"
    SIGNATURE_FORMAT = "signature_format"
    SIGNATURE_RECOVERY = "signature_recovery"
    SIGNER_MATCHES = "signer_matches"
    CHAIN = "chain"
    NETWORK = "network"
    DOMAIN = "domain"
    URI = "uri"
    STATEMENT = "statement"
    ADDRESS_ALLOWED = "address_allowed"
    ONCHAIN = "onchain"
    ISSUED_AT = "issued_at"
    NOT_EXPIRED = "not_expired"
    NONCE_ISSUED = "nonce_issued"
    NONCE_UNUSED = "nonce_unused"


@dataclass(frozen=True)
class Check:
    """One condition's outcome.

    ``skipped`` marks a condition that was never evaluated because an earlier one
    already failed. A skipped check is not a failure: it is reported so the
    caller can tell "this blocked you" apart from "we never got that far".
    """

    condition: Condition
    passed: bool
    detail: str
    skipped: bool = False

    def to_dict(self) -> dict:
        return {
            "condition": self.condition.value,
            "passed": self.passed,
            "skipped": self.skipped,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a signed conditioned message."""

    valid: bool
    checks: list[Check]
    signer: str | None = None
    chain_id: int | None = None
    nonce: str | None = None
    address: str | None = None
    expires_at: datetime | None = None

    @property
    def failures(self) -> list[Check]:
        """Conditions that were evaluated and did not hold."""
        return [c for c in self.checks if not c.passed and not c.skipped]

    @property
    def skipped(self) -> list[Check]:
        """Conditions never reached because something earlier already failed."""
        return [c for c in self.checks if c.skipped]

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "signer": self.signer,
            "chainId": self.chain_id,
            "address": self.address,
            "nonce": self.nonce,
            "expiresAt": self.expires_at.isoformat() if self.expires_at else None,
            "checks": [c.to_dict() for c in self.checks],
            "failed": [c.condition.value for c in self.failures],
            "skipped": [c.condition.value for c in self.skipped],
        }

    def reason(self) -> str:
        """A short, human-readable summary of why verification failed."""
        if self.valid:
            return "ok"
        return "; ".join(f"{c.condition.value}: {c.detail}" for c in self.failures)


class NonceStore(Protocol):
    """Tracks which nonces this server has issued and which are spent."""

    def issue(self) -> str: ...

    def known(self, nonce: str) -> bool: ...

    def consume(self, nonce: str) -> bool: ...


class InMemoryNonceStore:
    """Thread-safe single-process nonce store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._issued: dict[str, float] = {}
        self._used: set[str] = set()

    def issue(self) -> str:
        nonce = generate_nonce()
        with self._lock:
            self._issued[nonce] = time.time()
        return nonce

    def known(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._issued

    def consume(self, nonce: str) -> bool:
        """Mark a nonce spent. Returns False if it was already used."""
        with self._lock:
            if nonce in self._used:
                return False
            self._used.add(nonce)
            return True

    def reset(self) -> None:
        with self._lock:
            self._issued.clear()
            self._used.clear()


class FileNonceStore(InMemoryNonceStore):
    """Nonce store persisted to disk, so it survives restarts and extra workers."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path)
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return
        with self._lock:
            self._issued = {k: float(v) for k, v in data.get("issued", {}).items()}
            self._used = set(data.get("used", []))

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"issued": self._issued, "used": sorted(self._used)})
        )

    def issue(self) -> str:
        nonce = super().issue()
        with self._lock:
            self._flush()
        return nonce

    def consume(self, nonce: str) -> bool:
        ok = super().consume(nonce)
        if ok:
            with self._lock:
                self._flush()
        return ok


@dataclass
class VerifierConfig:
    """What a valid signature must look like for this service."""

    #: Chain the signature must be conditioned on (177 mainnet / 133 testnet).
    chain_id: int = DEFAULT_CHAIN_ID
    #: Human-readable network name the message must name. Kept alongside
    #: ``chain_id`` so failures and the signed text both name the same network.
    network_name: str = DEFAULT_NETWORK_NAME
    domain: str = DEFAULT_DOMAIN
    uri: str = DEFAULT_URI
    statement: str = DEFAULT_STATEMENT
    allowed_addresses: tuple[str, ...] = ()
    #: Tolerated skew when comparing issued-at / expiry against the server clock.
    clock_skew: timedelta = timedelta(seconds=60)
    #: How long an issued-but-unused nonce stays acceptable.
    nonce_ttl: timedelta = timedelta(minutes=15)
    #: Require the signer to have an on-chain footprint on the configured chain
    #: (non-zero nonce or balance, or deployed code). Off by default so a
    #: brand-new key still works. On testnet this is the "the faucet funded this
    #: account" check; on mainnet it means "this account has actually been used".
    require_onchain_activity: bool = False
    #: Returns truthy if the address is known to the chain. Injected so verify()
    #: stays testable without a network.
    address_probe: Callable[[str], Any] | None = None
    #: Treat a failing/absent probe as pass so an RPC outage cannot lock
    #: everyone out of an otherwise valid signature.
    onchain_failure_is_fatal: bool = False

    @classmethod
    def for_network(cls, network, **overrides) -> "VerifierConfig":
        """Build a config pinned to ``network`` (chain id + name + statement).

        The convenient, hard-to-get-wrong way to configure a deployment: one
        argument sets all three network-dependent fields consistently. Explicit
        ``overrides`` win, so a caller can still pin a different statement.
        """
        from hskfaucet.network import Network, get_network

        net = network if isinstance(network, Network) else get_network(network)
        from .message import statement_for

        params: dict = {
            "chain_id": net.chain_id,
            "network_name": net.name,
            "statement": statement_for(net),
        }
        params.update(overrides)
        return cls(**params)


class ConditionedMessageVerifier:
    """Verify signed conditioned messages against :class:`VerifierConfig`."""

    def __init__(
        self,
        config: VerifierConfig | None = None,
        nonce_store: NonceStore | None = None,
    ) -> None:
        self.config = config or VerifierConfig()
        self.nonce_store = nonce_store or InMemoryNonceStore()
        allowed = self.config.allowed_addresses
        self._allowlist = {to_checksum_address(a) for a in allowed} or None

    # ------------------------------------------------------------------ api

    def issue_nonce(self) -> str:
        return self.nonce_store.issue()

    def verify(
        self,
        payload: dict,
        *,
        signature: str | None = None,
        consume_nonce: bool = True,
    ) -> VerificationResult:
        """Verify ``payload``.

        ``payload`` is the JSON the server issued, optionally with the client's
        ``signature`` merged in (or passed separately). Nothing is consumed
        unless every condition passes.
        """
        checks: list[Check] = []

        def add(
            condition: Condition, passed: bool, detail: str, skipped: bool = False
        ) -> bool:
            checks.append(Check(condition, passed, detail, skipped))
            return passed

        # --- schema ---------------------------------------------------------
        message = ConditionedMessage.from_dict(payload)
        message_text = payload.get("message")
        add(
            Condition.SCHEMA,
            isinstance(message_text, str) and message_text == message.as_message(),
            "message text matches its own structured fields"
            if isinstance(message_text, str) and message_text == message.as_message()
            else "message text does not match the supplied fields (tampered?)",
        )

        # --- signature ------------------------------------------------------
        sig = signature or payload.get("signature")
        if not isinstance(sig, str) or not sig.startswith("0x") or len(sig) != 132:
            add(
                Condition.SIGNATURE_FORMAT,
                False,
                "signature must be 0x-prefixed 65-byte hex",
            )
            return VerificationResult(False, checks)

        from .wallet import recover_address

        try:
            recovered = recover_address(message.as_message(), sig)
        except Exception as exc:
            add(
                Condition.SIGNATURE_FORMAT,
                False,
                f"malformed signature ({exc})",
            )
            return VerificationResult(False, checks)
        add(
            Condition.SIGNATURE_FORMAT,
            True,
            f"well-formed EIP-191 signature ({sig[:10]}...{sig[-6:]})",
        )
        add(
            Condition.SIGNATURE_RECOVERY,
            True,
            f"recovered signer {recovered}",
        )

        # --- signer identity ------------------------------------------------
        add(
            Condition.SIGNER_MATCHES,
            recovered == message.address,
            f"signature was produced by {recovered}"
            if recovered == message.address
            else f"signature recovers to {recovered}, message claims {message.address}",
        )

        # --- conditioned on the configured HSKChain network ------------------
        add(
            Condition.CHAIN,
            message.chain_id == self.config.chain_id,
            f"chainId {message.chain_id} is {self.config.network_name}"
            if message.chain_id == self.config.chain_id
            else f"chainId {message.chain_id} != expected {self.config.chain_id} "
            f"({self.config.network_name})",
        )

        add(
            Condition.NETWORK,
            message.network_name == self.config.network_name,
            f"network {message.network_name!r} accepted"
            if message.network_name == self.config.network_name
            else f"network {message.network_name!r} != expected "
            f"{self.config.network_name!r}",
        )

        add(
            Condition.DOMAIN,
            message.domain == self.config.domain,
            f"domain {message.domain} accepted"
            if message.domain == self.config.domain
            else f"domain {message.domain!r} != expected {self.config.domain!r}",
        )

        add(
            Condition.URI,
            message.uri == self.config.uri,
            f"uri {message.uri} accepted"
            if message.uri == self.config.uri
            else f"uri {message.uri!r} != expected {self.config.uri!r}",
        )

        add(
            Condition.STATEMENT,
            message.statement == self.config.statement,
            "statement accepted"
            if message.statement == self.config.statement
            else "statement does not match the text the service requires",
        )

        if self._allowlist is None:
            add(
                Condition.ADDRESS_ALLOWED,
                True,
                f"{recovered} is not restricted (no allowlist configured)",
            )
        else:
            add(
                Condition.ADDRESS_ALLOWED,
                recovered in self._allowlist,
                f"{recovered} is on the allowlist"
                if recovered in self._allowlist
                else f"{recovered} is not on the allowlist",
            )

        # --- optional on-chain testnet footprint ---------------------------
        self._check_onchain(add, recovered)

        # --- validity window ------------------------------------------------
        now = utcnow()
        issued = message.issued_at
        expires = message.expiration_time

        if issued > now + self.config.clock_skew:
            add(
                Condition.ISSUED_AT,
                False,
                f"issuedAt {issued.isoformat()} is in the future",
            )
        else:
            stale = now - issued
            if stale > self.config.nonce_ttl:
                add(
                    Condition.ISSUED_AT,
                    False,
                    f"message was issued {stale} ago, beyond the "
                    f"{self.config.nonce_ttl} window",
                )
            else:
                add(
                    Condition.ISSUED_AT,
                    True,
                    f"issuedAt is within the acceptable window (age {stale})",
                )

        if expires <= now - self.config.clock_skew:
            add(
                Condition.NOT_EXPIRED,
                False,
                f"expired at {expires.isoformat()}",
            )
        else:
            add(
                Condition.NOT_EXPIRED,
                True,
                f"valid for another {expires - now}",
            )

        # --- nonce / replay -------------------------------------------------
        add(
            Condition.NONCE_ISSUED,
            self.nonce_store.known(message.nonce),
            f"nonce {message.nonce} was issued by this server"
            if self.nonce_store.known(message.nonce)
            else f"nonce {message.nonce} was not issued by this server",
        )

        # Anything already failing means we do not even try to spend the nonce.
        already_failed = any(not c.passed for c in checks)
        if already_failed:
            add(
                Condition.NONCE_UNUSED,
                False,
                "not checked: an earlier condition already failed, so the nonce "
                "was left unspent",
                skipped=True,
            )
            return self._result(False, checks, recovered, message, sig)

        if not consume_nonce:
            add(
                Condition.NONCE_UNUSED,
                True,
                f"nonce {message.nonce} unused (not consumed: consume_nonce=False)",
            )
        elif self.nonce_store.consume(message.nonce):
            add(
                Condition.NONCE_UNUSED,
                True,
                f"nonce {message.nonce} consumed on success",
            )
        else:
            add(
                Condition.NONCE_UNUSED,
                False,
                f"nonce {message.nonce} was already used (replay attempt)",
            )
        return self._result(True, checks, recovered, message, sig)

    def _check_onchain(self, add: Callable[..., bool], address: str) -> None:
        """Optionally confirm the signer actually exists on the target chain.

        This is the step that ties a funded account to the auth flow: on testnet
        the faucet gives an address a non-zero balance, whereas an address that
        has never touched the chain does not. On mainnet there is no faucet, so
        the same check instead means "this account has a footprint" (it has sent
        a transaction, holds a balance, or is a contract). It is opt-in, and a
        transport failure is non-fatal by default so an RPC outage cannot deny
        an otherwise valid signature.
        """
        if not self.config.require_onchain_activity:
            return

        probe = self.config.address_probe
        if probe is None:
            # Misconfiguration: we cannot honour the requirement we were given.
            add(
                Condition.ONCHAIN,
                False,
                "on-chain activity required but no address_probe is configured",
            )
            return

        try:
            info = probe(address)
        except Exception as exc:
            if self.config.onchain_failure_is_fatal:
                add(Condition.ONCHAIN, False, f"on-chain probe failed: {exc}")
            else:
                add(Condition.ONCHAIN, True, f"on-chain probe unavailable ({exc}); skipped")
            return

        # A definite answer from the probe is authoritative: if the caller asked
        # for on-chain activity and the chain says there is none, that is a
        # failure. `onchain_failure_is_fatal` only covers transport errors above.
        active = info if isinstance(info, bool) else bool(getattr(info, "active", False))
        detail = info.to_dict() if hasattr(info, "to_dict") else {"active": active}
        if active:
            add(
                Condition.ONCHAIN,
                True,
                f"signer is present on {self.config.network_name}: {detail}",
            )
        else:
            add(
                Condition.ONCHAIN,
                False,
                f"signer has no activity on {self.config.network_name} "
                f"(never funded or never transacted): {detail}",
            )

    def _result(
        self,
        valid: bool,
        checks: list[Check],
        signer: str,
        message: ConditionedMessage,
        signature: str,
    ) -> VerificationResult:
        return VerificationResult(
            valid=valid and all(c.passed for c in checks),
            checks=checks,
            signer=signer,
            chain_id=message.chain_id,
            nonce=message.nonce,
            address=message.address,
            expires_at=message.expiration_time,
        )


__all__ = [
    "Check",
    "Condition",
    "ConditionedMessageVerifier",
    "FileNonceStore",
    "InMemoryNonceStore",
    "NonceStore",
    "VerificationResult",
    "VerifierConfig",
]
