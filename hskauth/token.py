"""The API token: a random, opaque string *derived from* the signed message.

Once a conditioned message has been verified the client needs something it can
put in a header on later requests. Handing back the raw 65-byte signature would
be awkward and would let a signature be replayed verbatim against any endpoint,
so instead we mint a **bearer token** that is a keyed derivative of the verified
message::

    hsk1.<b64url(payload)>.<b64url(HMAC-SHA256(server_secret, b64url_payload))>

Properties this gives us:

* **Opaque / random-looking** -- the payload carries a 256-bit CSPRNG ``sid``,
  so the token is unguessable even though its contents are deterministic.
* **Bound to the signed message** -- ``addr``, ``cid``, ``nonce``, ``rid`` and a
  hash of the signature are all inside and MAC'd, so a token is only obtainable
  by completing a valid signature flow for *that* message.
* **Tamper-evident** -- flipping any byte breaks the MAC.
* **Self-expiring** -- ``exp`` is inside the payload and checked locally.
* **Server-side revocable** -- a session id, so a token can be burned early.

The server secret is the only thing standing between an attacker and the ability
to mint tokens, so it is read from the environment and a random one is generated
for local development.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass

from hskfaucet.network import HSK_TESTNET

TOKEN_PREFIX = "hsk1"
DEFAULT_TOKEN_TTL = 900  # 15 minutes

_MISSING_SECRET = (
    "no token signing secret configured. Set HSK_TOKEN_SECRET in the "
    "environment (or pass secret=...) before issuing tokens."
)


class TokenError(RuntimeError):
    """Token minting or validation failed."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def signature_fingerprint(signature: str) -> str:
    """Short, stable id for a signature, safe to log."""
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class AccessToken:
    """A minted bearer token plus its decoded claims."""

    token: str
    session_id: str
    address: str
    chain_id: int
    nonce: str
    request_id: str
    signature_fingerprint: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "tokenType": "Bearer",
            "sessionId": self.session_id,
            "address": self.address,
            "chainId": self.chain_id,
            "expiresIn": max(0, self.expires_at - int(time.time())),
            "expiresAt": self.expires_at,
        }

    def public_dict(self) -> dict:
        """Same thing minus the secret-bearing token string."""
        data = self.to_dict()
        data.pop("token")
        return data


@dataclass
class Session:
    """Server-side record, so tokens can be inspected and revoked."""

    session_id: str
    address: str
    chain_id: int
    request_id: str
    signature_fingerprint: str
    issued_at: int
    expires_at: int
    revoked: bool = False

    def to_dict(self) -> dict:
        return {
            "sessionId": self.session_id,
            "address": self.address,
            "chainId": self.chain_id,
            "requestId": self.request_id,
            "signature": self.signature_fingerprint,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "expired": self.expires_at <= int(time.time()),
            "revoked": self.revoked,
        }


class TokenIssuer:
    """Mints and validates tokens bound to a verified conditioned message."""

    def __init__(self, secret: str | bytes | None, ttl: int = DEFAULT_TOKEN_TTL) -> None:
        if secret is None or secret == "":
            raise TokenError(_MISSING_SECRET)
        self.secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        if len(self.secret) < 16:
            raise TokenError("token secret must be at least 16 bytes")
        self.ttl = ttl
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}

    # ---------------------------------------------------------------- mint

    def _mac(self, payload_segment: str) -> str:
        digest = hmac.new(
            self.secret, payload_segment.encode("ascii"), hashlib.sha256
        ).digest()
        return _b64e(digest)

    def issue(
        self,
        *,
        address: str,
        chain_id: int = HSK_TESTNET.chain_id,
        nonce: str,
        request_id: str,
        signature: str,
        ttl: int | None = None,
    ) -> AccessToken:
        """Mint a token for a signature that has already been verified.

        Callers must run the signature through
        :class:`~hskauth.verify.ConditionedMessageVerifier` first -- this method
        trusts its inputs and performs no verification of its own.
        """
        now = int(time.time())
        expires = now + (ttl if ttl is not None else self.ttl)
        claims = {
            "sid": secrets.token_urlsafe(24),  # 192 bits of CSPRNG entropy
            "addr": address,
            "cid": int(chain_id),
            "nonce": nonce,
            "rid": request_id,
            "sig": signature_fingerprint(signature),
            "iat": now,
            "exp": expires,
        }
        segment = _b64e(
            json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        token = f"{TOKEN_PREFIX}.{segment}.{self._mac(segment)}"

        access = AccessToken(
            token=token,
            session_id=claims["sid"],
            address=address,
            chain_id=int(chain_id),
            nonce=nonce,
            request_id=request_id,
            signature_fingerprint=claims["sig"],
            issued_at=now,
            expires_at=expires,
        )
        with self._lock:
            self._sessions[access.session_id] = Session(
                session_id=access.session_id,
                address=address,
                chain_id=int(chain_id),
                request_id=request_id,
                signature_fingerprint=claims["sig"],
                issued_at=now,
                expires_at=expires,
            )
        return access

    # -------------------------------------------------------------- verify

    def validate(self, token: str) -> AccessToken:
        """Validate a bearer token and return its claims.

        Raises :class:`TokenError` if it is malformed, tampered with, expired,
        or has been revoked.
        """
        if not isinstance(token, str) or not token:
            raise TokenError("missing token")

        parts = token.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
            raise TokenError("malformed token")

        _, segment, mac = parts
        # Constant-time compare so a MAC cannot be brute-forced byte by byte.
        if not hmac.compare_digest(self._mac(segment), mac):
            raise TokenError("invalid token signature")

        try:
            claims = json.loads(_b64d(segment))
        except (ValueError, TypeError) as exc:
            raise TokenError("malformed token payload") from exc

        now = int(time.time())
        if now >= int(claims.get("exp", 0)):
            raise TokenError("token expired")

        with self._lock:
            session = self._sessions.get(claims.get("sid", ""))
        if session is None:
            raise TokenError("unknown session")
        if session.revoked:
            raise TokenError("token revoked")

        return AccessToken(
            token=token,
            session_id=session.session_id,
            address=session.address,
            chain_id=session.chain_id,
            nonce=claims.get("nonce", ""),
            request_id=session.request_id,
            signature_fingerprint=session.signature_fingerprint,
            issued_at=session.issued_at,
            expires_at=session.expires_at,
        )

    # ------------------------------------------------------------- session

    def revoke(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            session.revoked = True
            return True

    def sessions(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in sorted(
                self._sessions.values(), key=lambda s: s.issued_at, reverse=True
            )]


def secret_from_env(environ: dict | None = None, *, allow_generated: bool = True) -> str:
    """Read the token secret, generating an ephemeral one for local dev."""
    import os

    env = environ if environ is not None else os.environ
    secret = env.get("HSK_TOKEN_SECRET")
    if secret:
        return secret
    if not allow_generated:
        raise TokenError(_MISSING_SECRET)
    # Fine for `flask run` locally, useless for production: restarts invalidate
    # every outstanding token, so real deployments must set HSK_TOKEN_SECRET.
    return secrets.token_urlsafe(48)


__all__ = [
    "AccessToken",
    "DEFAULT_TOKEN_TTL",
    "Session",
    "TOKEN_PREFIX",
    "TokenError",
    "TokenIssuer",
    "secret_from_env",
    "signature_fingerprint",
]
