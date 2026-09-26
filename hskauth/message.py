"""The *conditioned message*: what a wallet is asked to sign.

This is a strict, SIWE-inspired (EIP-4361) conditioned message pinned to an
HSKChain network (mainnet `177` or testnet `133`). Every field is a condition the
verifier re-checks, so a signature is only accepted when the whole set holds:

===================  =========================================================
``domain``           host + port the request arrived on
``uri``              path of the endpoint being unlocked
``chainId``          must equal the configured network's chain id
``networkName``      must equal the configured network's name
``address``          the account being authenticated
``statement``        fixed human-readable text the user consents to
``nonce``            server-issued, high-entropy, single use (replay defence)
``issuedAt``         ISO-8601; must not be in the future
``expirationTime``   ISO-8601; must not be in the past
``requestId``        ties the message to one specific request
===================  =========================================================

The rendered text follows the EIP-4361 layout so MetaMask and other wallets
show something readable. The network name is a *field*, not baked into the
template, so a message issued for mainnet never says "testnet" and the text can
always be re-derived from the structured fields during verification.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from eth_utils import to_checksum_address

from hskfaucet.network import (
    DEFAULT_CHAIN_ID,
    DEFAULT_NETWORK,
    Network,
    get_network,
)

#: 32 hex chars (128 bits) of CSPRNG entropy, per EIP-4361.
NONCE_BYTES = 16
NONCE_ALPHABET = "0123456789abcdef"

DEFAULT_DOMAIN = "localhost:5000"
DEFAULT_URI = "/api/v1/data"
DEFAULT_EXPIRY_SECONDS = 300

#: Used when a caller builds a message without naming a network.
DEFAULT_NETWORK_NAME: str = DEFAULT_NETWORK.name

_STATEMENT_TEMPLATE = (
    "Sign in to the {network} data API. This proves you control this "
    "{network} account and authorises one API session. It moves no funds."
)


def statement_for(network: Network | str | None = None) -> str:
    """The default consent text for ``network``.

    Phrased per-network on purpose: a wallet showing "HSKChain Testnet" on a
    mainnet deployment is a real support and trust problem, and the statement is
    itself a verified condition, so the wording has to come from one place.
    """
    name = network if isinstance(network, str) else (network or DEFAULT_NETWORK).name
    return _STATEMENT_TEMPLATE.format(network=name)


def _coerce_network(network: Network | str | None) -> Network | None:
    """Normalise ``network`` to a :class:`Network`, or ``None`` for 'use default'."""
    if network is None:
        return None
    if isinstance(network, Network):
        return network
    return get_network(network)


#: Backwards-compatible alias for the default network's statement.
DEFAULT_STATEMENT = statement_for()


def generate_nonce() -> str:
    """A 32-character, high-entropy nonce from the system CSPRNG."""
    return "".join(secrets.choice(NONCE_ALPHABET) for _ in range(NONCE_BYTES * 2))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing ``Z``."""
    if not isinstance(value, str):
        raise ValueError(f"timestamp must be a string, got {type(value).__name__}")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ConditionedMessage:
    """The exact text plus the structured conditions a signer commits to."""

    domain: str = DEFAULT_DOMAIN
    uri: str = DEFAULT_URI
    chain_id: int = DEFAULT_CHAIN_ID
    address: str = ""
    statement: str = DEFAULT_STATEMENT
    nonce: str = field(default_factory=generate_nonce)
    issued_at: datetime = field(default_factory=utcnow)
    expiration_time: datetime | None = None
    request_id: str = field(default_factory=lambda: secrets.token_urlsafe(12))
    #: Which network the message is pinned to. Part of the rendered text, so it
    #: must round-trip through to_dict()/from_dict() for the schema check to
    #: hold. Optional for backwards compatibility with pre-network payloads.
    network_name: str = DEFAULT_NETWORK_NAME

    def __post_init__(self) -> None:
        if self.chain_id is None:
            raise ValueError("chain_id is required")
        if not self.address:
            raise ValueError("address is required")
        object.__setattr__(self, "address", to_checksum_address(self.address))
        if len(self.nonce) < 16 or not set(self.nonce) <= set(NONCE_ALPHABET):
            raise ValueError(
                f"nonce must be >=16 chars of 0-9a-f, got {self.nonce!r}"
            )
        if self.expiration_time is None:
            object.__setattr__(
                self, "expiration_time", self.issued_at + timedelta(seconds=DEFAULT_EXPIRY_SECONDS)
            )
        if self.expiration_time <= self.issued_at:
            raise ValueError("expiration_time must be after issued_at")

    # ------------------------------------------------------------ rendering

    def as_message(self) -> str:
        """Render the human-readable / wallet-displayed text (EIP-4361 style)."""
        address = self.address  # EIP-55 checksummed
        network = self.network_name or DEFAULT_NETWORK_NAME
        return (
            f"{self.domain} wants you to sign in with your {network} account:\n"
            f"{address}\n"
            f"\n"
            f"{self.statement}\n"
            f"\n"
            f"URI: {self.uri}\n"
            f"Version: 1\n"
            f"Chain ID: {self.chain_id}\n"
            f"Nonce: {self.nonce}\n"
            f"Issued At: {_iso(self.issued_at)}\n"
            f"Expiration Time: {_iso(self.expiration_time)}\n"
            f"Request ID: {self.request_id}\n"
        )

    def to_dict(self) -> dict:
        """JSON payload handed to the client for signing."""
        return {
            "message": self.as_message(),
            "domain": self.domain,
            "uri": self.uri,
            "chainId": self.chain_id,
            "address": self.address,
            "statement": self.statement,
            "networkName": self.network_name,
            "nonce": self.nonce,
            "issuedAt": _iso(self.issued_at),
            "expirationTime": _iso(self.expiration_time),
            "requestId": self.request_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ConditionedMessage":
        """Rebuild from a signed-message payload (strict about required keys)."""
        missing = [
            k
            for k in (
                "domain",
                "uri",
                "chainId",
                "address",
                "statement",
                "nonce",
                "issuedAt",
                "expirationTime",
                "requestId",
            )
            if k not in data
        ]
        if missing:
            raise ValueError(f"conditioned message missing fields: {missing}")
        return cls(
            domain=data["domain"],
            uri=data["uri"],
            chain_id=int(data["chainId"]),
            address=data["address"],
            statement=data["statement"],
            # Tolerated to be absent: payloads minted before the network became a
            # field. Absent -> the default network's name, which is what those
            # payloads implied.
            network_name=data.get("networkName") or DEFAULT_NETWORK_NAME,
            nonce=data["nonce"],
            issued_at=parse_iso(data["issuedAt"]),
            expiration_time=parse_iso(data["expirationTime"]),
            request_id=data["requestId"],
        )


def build_message(
    address: str,
    *,
    domain: str = DEFAULT_DOMAIN,
    uri: str = DEFAULT_URI,
    chain_id: int = DEFAULT_CHAIN_ID,
    statement: str | None = None,
    nonce: str | None = None,
    expiry_seconds: int = DEFAULT_EXPIRY_SECONDS,
    request_id: str | None = None,
    network: Network | str | None = None,
) -> ConditionedMessage:
    """Issue a fresh conditioned message for ``address``.

    ``network`` (a :class:`~hskfaucet.network.Network` or its name) pins the
    message to that chain: it sets both ``chainId`` and the network name rendered
    in the text. It defaults to the configured network, so the common case never
    has to think about chain ids. The statement defaults to the per-network
    consent text.
    """
    net = _coerce_network(network)
    net_name = net.name if net is not None else DEFAULT_NETWORK_NAME
    if net is not None:
        # An explicit network wins over the module default chain id, otherwise a
        # caller asking for testnet would silently get mainnet's 177.
        chain_id = net.chain_id

    issued = utcnow()
    kwargs: dict = {}
    if nonce is not None:
        kwargs["nonce"] = nonce
    if request_id is not None:
        kwargs["request_id"] = request_id
    return ConditionedMessage(
        domain=domain,
        uri=uri,
        chain_id=chain_id,
        address=address,
        statement=statement_for(net) if statement is None else statement,
        issued_at=issued,
        expiration_time=issued + timedelta(seconds=expiry_seconds),
        network_name=net_name,
        **kwargs,
    )


__all__ = [
    "DEFAULT_CHAIN_ID",
    "DEFAULT_DOMAIN",
    "DEFAULT_EXPIRY_SECONDS",
    "DEFAULT_NETWORK_NAME",
    "DEFAULT_STATEMENT",
    "DEFAULT_URI",
    "ConditionedMessage",
    "build_message",
    "generate_nonce",
    "parse_iso",
    "statement_for",
    "utcnow",
]
