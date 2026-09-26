"""EIP-191 ``personal_sign`` primitives for HSKChain Testnet accounts."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address

from hskfaucet.network import HSK_TESTNET

WALLET_FILE = Path(os.environ.get("HSK_WALLET_FILE", "wallet.json"))


class WalletError(RuntimeError):
    pass


@dataclass
class Wallet:
    """An ephemeral testnet keypair.

    Only ever meant for HSKChain **testnet** -- the private key is written to
    disk with 0600 permissions and must never hold real value.
    """

    address: str
    private_key: str
    path: Path | None = None

    @classmethod
    def generate(cls, path: Path | None = None) -> "Wallet":
        account = Account.create(secrets.token_bytes(32))
        wallet = cls(
            address=account.address,
            private_key=account.key.hex(),
            path=Path(path) if path else None,
        )
        if wallet.path:
            wallet.save(wallet.path)
        return wallet

    @classmethod
    def load(cls, path: Path = WALLET_FILE) -> "Wallet":
        if not path.exists():
            raise WalletError(
                f"no wallet at {path}; run `python cli.py wallet --new` first"
            )
        data = json.loads(path.read_text())
        if not data.get("private_key"):
            raise WalletError(f"wallet at {path} has no private key")
        return cls(
            address=to_checksum_address(
                Account.from_key(data["private_key"]).address
            ),
            private_key=data["private_key"],
            path=path,
        )

    def save(self, path: Path | None = None) -> Path:
        target = Path(path or self.path or WALLET_FILE)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "address": self.address,
                    "private_key": self.private_key,
                    "network": HSK_TESTNET.name,
                    "chain_id": HSK_TESTNET.chain_id,
                    "warning": "TESTNET ONLY - never send real funds to this key",
                },
                indent=2,
            )
            + "\n"
        )
        target.chmod(0o600)
        self.path = target
        return target

    # ------------------------------------------------------------- signing

    def sign_message(self, message: str) -> str:
        """EIP-191 ``personal_sign``; returns a 0x-prefixed signature."""
        signable = encode_defunct(text=message)
        signed = Account.sign_message(signable, private_key=self.private_key)
        sig = signed.signature
        if isinstance(sig, bytes):
            sig = sig.hex()
        return sig if sig.startswith("0x") else "0x" + sig


def recover_address(message: str, signature: str) -> str:
    """Recover the EIP-191 signer of ``message`` from ``signature``."""
    if not isinstance(signature, str) or not signature.startswith("0x"):
        raise ValueError("signature must be a 0x-prefixed hex string")
    raw = bytes.fromhex(signature[2:])
    if len(raw) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(raw)}")
    signable = encode_defunct(text=message)
    return to_checksum_address(
        Account.recover_message(signable, signature=raw)
    )


__all__ = ["Wallet", "WalletError", "recover_address"]
