"""Conditioned-message authentication for the HSKChain testnet data API.

    message = build_message(wallet.address, domain=..., uri=...)
    signature = wallet.sign_message(message.as_message())
    result = verifier.verify(message.to_dict() | {"signature": signature})
    token = issuer.issue(...)
"""

from .message import (
    ConditionedMessage,
    DEFAULT_CHAIN_ID,
    DEFAULT_DOMAIN,
    DEFAULT_STATEMENT,
    DEFAULT_URI,
    build_message,
    generate_nonce,
    parse_iso,
    utcnow,
)
from .onchain import AddressProbe, RpcError, TestnetProbe
from .token import (
    AccessToken,
    TokenError,
    TokenIssuer,
    secret_from_env,
    signature_fingerprint,
)
from .verify import (
    Check,
    Condition,
    ConditionedMessageVerifier,
    FileNonceStore,
    InMemoryNonceStore,
    VerificationResult,
    VerifierConfig,
)
from .wallet import Wallet, WalletError, recover_address

__version__ = "1.0.0"

__all__ = [
    "AccessToken",
    "AddressProbe",
    "Check",
    "Condition",
    "ConditionedMessage",
    "ConditionedMessageVerifier",
    "DEFAULT_CHAIN_ID",
    "DEFAULT_DOMAIN",
    "DEFAULT_STATEMENT",
    "DEFAULT_URI",
    "FileNonceStore",
    "InMemoryNonceStore",
    "RpcError",
    "TestnetProbe",
    "TokenError",
    "TokenIssuer",
    "VerificationResult",
    "VerifierConfig",
    "Wallet",
    "WalletError",
    "build_message",
    "generate_nonce",
    "parse_iso",
    "recover_address",
    "secret_from_env",
    "signature_fingerprint",
    "utcnow",
]
