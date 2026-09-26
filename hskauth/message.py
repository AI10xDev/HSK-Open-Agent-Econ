"""The *conditioned message*: what a wallet is asked to sign.

This is a strict, SIWE-inspired (EIP-4361) conditioned message pinned to
HSKChain Testnet. Every field is a condition the verifier re-checks, so a
signature is only accepted when the whole set holds:

===================  =========================================================
``domain``           host + port the request arrived on
``uri``              path of the endpoint being unlocked
``chainId``          must equal the HSKChain testnet chain id (133)
``address``          the account being authenticated
``statement``        fixed human-readable text the user consents to
``nonce``            server-issued, high-entropy, single use (replay defence)
``issuedAt``         ISO-8601; must not be in the future
``expirationTime``   ISO-8601; must not be in the past
``requestId``        ties the message to one specific request
===================  =========================================================

The rendered text follows the EIP-4361 layout so MetaMask and other wallets
show something readable.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from eth_utils import to_checksum_address

#: 32 hex chars (128 bits) of CSPRNG entropy, per EIP-4361.
NONCE_BYTES = 16
NONCE_ALPHABET = "0123456789abcdef"

DEFAULT_STATEMENT = (
    "Sign in to the HSKChain testnet data API. This proves you control this "
    "HSKChain Testnet account and authorises one API session. It moves no funds."
)
DEFAULT_DOMAIN = "localhost:5000"
DEFAULT_URI = "/api/v1/data"
DEFAULT_EXPIRY_SECONDS = 300


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
    chain_id: int = 133
    address: str = ""
    statement: str = DEFAULT_STATEMENT
    nonce: str = field(default_factory=generate_nonce)
    issued_at: datetime = field(default_factory=utcnow)
    expiration_time: datetime | None = None
    request_id: str = field(default_factory=lambda: secrets.token_urlsafe(12))

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
        return (
            f"{self.domain} wants you to sign in with your HSKChain Testnet account:\n"
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
    chain_id: int = 133,
    statement: str = DEFAULT_STATEMENT,
    nonce: str | None = None,
    expiry_seconds: int = DEFAULT_EXPIRY_SECONDS,
    request_id: str | None = None,
) -> ConditionedMessage:
    """Issue a fresh conditioned message for ``address``."""
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
        statement=statement,
        issued_at=issued,
        expiration_time=issued + timedelta(seconds=expiry_seconds),
        **kwargs,
    )


__all__ = [
    "ConditionedMessage",
    "DEFAULT_CHAIN_ID",
    "DEFAULT_DOMAIN",
    "DEFAULT_EXPIRY_SECONDS",
    "DEFAULT_STATEMENT",
    "DEFAULT_URI",
    "generate_nonce",
    "parse_iso",
    "utcnow",
]

DEFAULT_CHAIN_ID = 133
