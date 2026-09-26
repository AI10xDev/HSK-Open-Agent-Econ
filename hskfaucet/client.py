"""Client for the HSKChain **testnet** faucet REST API.

Endpoints (discovered from the official faucet bundle, see ``installer.py``):

===========================  ==================================================
``POST /api/faucet/drip``    ``{"token": <reCAPTCHA token>, "address": "0x.."}``
                             -> ``{"id": "<txId>"}`` or ``{"message": "<error>"}``
``GET  /api/faucet/query``   ``?txId=<id>``
                             -> ``{"transaction": {...} | null, "message": str}``
===========================  ==================================================

The faucet dispatches an on-chain transaction and returns a job id; the
transaction is only visible once it has been mined, so :meth:`FaucetClient.drip`
polls ``query`` exactly like the web UI does (20 retries, 2s apart).

.. warning::
   **There is no faucet on HSKChain mainnet.** The official faucet exists only on
   testnet (chain 133); mainnet HSK is real money. :class:`FaucetClient`
   therefore refuses to be constructed against a non-testnet network rather than
   trusting the caller to have picked the right chain. See
   :meth:`FaucetClient.__init__`.

.. warning::
   ``drip`` requires a genuine reCAPTCHA v2 token, which by design can only be
   obtained by a human completing the challenge at
   https://faucet.hsk.xyz/faucet. This client accepts that token as an input and
   will not attempt to solve or work around the challenge. :meth:`drip` raises
   :class:`RecaptchaRequired` when no token is supplied.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

import requests

from .hmac_auth import (
    BROWSER_USER_AGENT,
    FaucetCredentials,
    sign,
    utc_timestamp,
)
from .network import HSK_TESTNET, Network

log = logging.getLogger(__name__)

DEFAULT_API_URL = "https://faucet-api.hashkeychain.net"
DEFAULT_RECAPTCHA_SITE_KEY = "6Lfzh00qAAAAAJe7RsbZBypLTlQ6zXOpke9IKRBc"

#: Mirrors the frontend's retry budget for a drip job.
POLL_ATTEMPTS = 20
POLL_INTERVAL = 2.0

ADDRESS_RE = r"^0x[a-fA-F0-9]{40}$"


class FaucetError(RuntimeError):
    """A faucet API call failed."""

    def __init__(self, message: str, status_code: int | None = None, payload: Any = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.payload = payload


class RecaptchaRequired(FaucetError):
    """No reCAPTCHA token was provided; only a human can solve the challenge."""


@dataclass(frozen=True)
class DripResult:
    """Outcome of a faucet drip."""

    address: str
    job_id: str
    transaction_hash: str | None = None
    status: str | None = None
    created_at: str | None = None
    mined: bool = False

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "job_id": self.job_id,
            "transaction_hash": self.transaction_hash,
            "status": self.status,
            "created_at": self.created_at,
            "mined": self.mined,
        }


def _validate_address(address: str) -> str:
    import re

    if not re.match(ADDRESS_RE, address or ""):
        raise ValueError(f"not a valid EVM address: {address!r}")
    # EIP-55 checksum, so we hand the faucet a canonical address.
    from eth_utils import to_checksum_address

    return to_checksum_address(address)


class FaucetClient:
    """HMAC-authenticated client for the HSKChain faucet API.

    Refuses construction against a non-testnet network: the faucet is a
    testnet-only service, and this class dispatches real on-chain transactions.
    """

    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        credentials: FaucetCredentials | None = None,
        network: Network = HSK_TESTNET,
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        if not network.is_testnet:
            raise FaucetError(
                f"refusing to run the faucet against {network.name} (chain "
                f"{network.chain_id}): the HSK faucet is testnet-only and has no "
                f"mainnet deployment. Set HSK_NETWORK=testnet to use it."
            )
        self.api_url = api_url.rstrip("/")
        self.credentials = credentials or FaucetCredentials.from_env()
        self.network = network
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "User-Agent": BROWSER_USER_AGENT,
                "Accept": "application/json, text/plain, */*",
                "Origin": "https://faucet.hsk.xyz",
                "Referer": "https://faucet.hsk.xyz/",
            }
        )

    # ------------------------------------------------------------------ core

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
    ) -> Any:
        url = f"{self.api_url}{path}"
        headers = {
            "Content-Type": "application/json",
            **sign(method, url, self.credentials, utc_timestamp()),
        }
        try:
            response = self.session.request(
                method, url, headers=headers, json=json_body, timeout=self.timeout
            )
        except requests.RequestException as exc:  # pragma: no cover - network
            raise FaucetError(f"request to {url} failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError:
            payload = {"message": response.text[:500]}

        if not response.ok:
            message = payload.get("message") or response.text[:500]
            raise FaucetError(message, status_code=response.status_code, payload=payload)
        return payload

    # --------------------------------------------------------------- public

    @property
    def recaptcha_site_key(self) -> str:
        """Public reCAPTCHA v2 site key, useful for building a browser page."""
        return DEFAULT_RECAPTCHA_SITE_KEY

    def query(self, job_id: str) -> dict:
        """Look up a drip job. Returns the raw ``{"transaction": ...}`` payload."""
        if not job_id:
            raise ValueError("job_id is required")
        return self._request("GET", f"/api/faucet/query?txId={job_id}")

    def drip(self, address: str, recaptcha_token: str | None = None) -> DripResult:
        """Request testnet HSK for ``address``.

        ``recaptcha_token`` must come from a human solving the challenge on the
        faucet site. It is deliberately *not* optional in practice: the API
        rejects requests without one.
        """
        address = _validate_address(address)
        if not recaptcha_token:
            raise RecaptchaRequired(
                "the HSKChain faucet requires a reCAPTCHA v2 token. Solve the "
                f"challenge at {self.network.faucet_url} and pass the token as "
                "`recaptcha_token` (the client does not bypass the challenge)."
            )

        payload = self._request(
            "POST",
            "/api/faucet/drip",
            json_body={"token": recaptcha_token, "address": address},
        )
        job_id = payload.get("id")
        if not job_id:
            raise FaucetError(
                payload.get("message") or "faucet returned no job id", payload=payload
            )
        log.info("faucet accepted request %s for %s", job_id, address)
        return DripResult(address=address, job_id=job_id)

    def drip_and_wait(
        self,
        address: str,
        recaptcha_token: str | None = None,
        *,
        attempts: int = POLL_ATTEMPTS,
        interval: float = POLL_INTERVAL,
        sleep: Callable[[float], None] = time.sleep,
    ) -> DripResult:
        """Request a drip and poll until the transaction is mined (or time out)."""
        result = self.drip(address, recaptcha_token)
        for attempt in range(1, attempts + 1):
            sleep(interval)
            tx = (self.query(result.job_id) or {}).get("transaction")
            if tx and tx.get("isProcessed") and tx.get("status") == "success":
                return DripResult(
                    address=result.address,
                    job_id=result.job_id,
                    transaction_hash=tx.get("transactionHash"),
                    status=tx.get("status"),
                    created_at=tx.get("createdAt"),
                    mined=True,
                )
            log.debug("drip %s not mined yet (attempt %d)", result.job_id, attempt)
        log.warning("drip %s still pending after %d polls", result.job_id, attempts)
        return result


__all__ = [
    "DEFAULT_API_URL",
    "DEFAULT_RECAPTCHA_SITE_KEY",
    "DripResult",
    "FaucetClient",
    "FaucetError",
    "RecaptchaRequired",
]
