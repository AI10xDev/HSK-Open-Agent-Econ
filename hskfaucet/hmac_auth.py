"""HMAC request signing for the HSKChain faucet API.

The official faucet web app (https://faucet.hsk.xyz) authenticates every call to
its backend with an HMAC-SHA256 signature over a canonicalised request. The
frontend ships the scheme in ``envs.js``/``main.<hash>.js``; this module is a
faithful Python port of it so the faucet can be driven from a script.

Canonical string that gets signed::

    x-date: <UTC timestamp>
    <METHOD> <pathname><search> HTTP/1.1

which is then emitted as two headers::

    X-Timestamp: <UTC timestamp>
    X-Signature: hmac username="faucet", algorithm="hmac-sha256", \
headers="x-date request-line", signature="<base64 hmac>"

The HMAC key is the shared secret and the output is standard base64 of the raw
digest (identical to ``btoa(...)`` over the digest bytes in the browser).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from email.utils import formatdate
from urllib.parse import urlsplit

#: The faucet API edge sits behind a CDN that rejects non-browser user agents
#: with ``error code: 1010``, so send a real one. Nothing is spoofed about the
#: HMAC itself -- this only keeps us from being dropped before we reach the app.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

ALGORITHM = "hmac-sha256"
SIGNED_HEADERS = "x-date request-line"


class FaucetAuthError(RuntimeError):
    """Raised when credentials are missing or malformed."""


@dataclass(frozen=True)
class FaucetCredentials:
    """Shared HMAC credentials for the faucet API."""

    username: str
    secret: str
    #: Some deployments allow an operator to supply their own key.
    scheme: str = ALGORITHM

    def __post_init__(self) -> None:
        if not self.username or not self.secret:
            raise FaucetAuthError("faucet HMAC username and secret are required")

    @classmethod
    def from_env(cls, **environ) -> "FaucetCredentials":
        """Build credentials from environment variables, falling back to the
        public values the faucet frontend ships to every browser."""
        username = (
            environ.get("HSK_FAUCET_HMAC_USERNAME")
            or environ.get("VITE_HMAC_USERNAME")
            or "faucet"
        )
        secret = (
            environ.get("HSK_FAUCET_HMAC_SECRET")
            or environ.get("VITE_HMAC_SECRET")
            or "dce7OzR8GyYd"
        )
        return cls(username=username, secret=secret)

    @property
    def key(self) -> bytes:
        return self.secret.encode("utf-8")


def utc_timestamp() -> str:
    """``new Date().toUTCString()`` equivalent, in the RFC 7231 IMF-fixdate form."""
    # usegmt=True gives exactly the trailing "GMT" the frontend signs.
    return formatdate(usegmt=True)


def canonical_request(method: str, path_with_query: str, timestamp: str) -> str:
    """Build the string the faucet server recomputes and compares against."""
    return f"x-date: {timestamp}\n{method.upper()} {path_with_query} HTTP/1.1"


def sign(
    method: str,
    url: str,
    credentials: FaucetCredentials,
    timestamp: str | None = None,
) -> dict[str, str]:
    """Return the ``X-Timestamp``/``X-Signature`` headers for a request."""
    parts = urlsplit(url)
    path_with_query = parts.path or "/"
    if parts.query:
        path_with_query = f"{path_with_query}?{parts.query}"

    timestamp = timestamp or utc_timestamp()
    canonical = canonical_request(method, path_with_query, timestamp)

    digest = hmac.new(
        credentials.key, canonical.encode("utf-8"), hashlib.sha256
    ).digest()
    signature = base64.b64encode(digest).decode("ascii")

    return {
        "X-Timestamp": timestamp,
        "X-Signature": (
            f'hmac username="{credentials.username}", '
            f'algorithm="{credentials.scheme}", '
            f'headers="{SIGNED_HEADERS}", '
            f'signature="{signature}"'
        ),
    }
