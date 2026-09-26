"""HSKChain networks plus the testnet-only faucet tooling.

    python -m hskfaucet.installer     # fetch + install the faucet app
    python -m hskfaucet.installer --check

The faucet (client + installer) is **testnet-only**: HSKChain mainnet has no
faucet, and :class:`FaucetClient` refuses to run against a non-testnet network.
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
from .network import (
    DEFAULT_CHAIN_ID,
    DEFAULT_NETWORK,
    HSK_MAINNET,
    HSK_TESTNET,
    NETWORKS,
    NETWORK_ENV_VAR,
    Network,
    get_network,
    resolve_network,
)

__version__ = "1.0.0"

__all__ = [
    "DEFAULT_API_URL",
    "DEFAULT_CHAIN_ID",
    "DEFAULT_NETWORK",
    "DEFAULT_RECAPTCHA_SITE_KEY",
    "DripResult",
    "FaucetClient",
    "FaucetCredentials",
    "FaucetError",
    "HSK_MAINNET",
    "HSK_TESTNET",
    "NETWORKS",
    "NETWORK_ENV_VAR",
    "Network",
    "RecaptchaRequired",
    "canonical_request",
    "get_network",
    "resolve_network",
    "sign",
]
