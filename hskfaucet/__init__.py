"""HSKChain testnet faucet: download/install tooling plus an API client.

    python -m hskfaucet.installer     # fetch + install the faucet app
    python -m hskfaucet.installer --check
"""

from .client import (
    DEFAULT_API_URL,
    DEFAULT_RECAPTCHA_SITE_KEY,
    DripResult,
    FaucetClient,
    FaucetError,
    RecaptchaRequired,
)
from .hmac_auth import FaucetCredentials, canonical_request, sign
from .network import DEFAULT_NETWORK, HSK_TESTNET, NETWORKS, Network, get_network

__version__ = "1.0.0"

__all__ = [
    "DEFAULT_API_URL",
    "DEFAULT_NETWORK",
    "DEFAULT_RECAPTCHA_SITE_KEY",
    "DripResult",
    "FaucetClient",
    "FaucetCredentials",
    "FaucetError",
    "HSK_TESTNET",
    "NETWORKS",
    "Network",
    "RecaptchaRequired",
    "canonical_request",
    "get_network",
    "sign",
]
