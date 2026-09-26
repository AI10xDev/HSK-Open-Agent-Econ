"""EIP-191 ``personal_sign`` primitives for HSKChain accounts.

A wallet here is a plain local keypair used to *prove control of an address*.
It never holds the service's funds and it is not a mainnet treasury: the
generated key is ephemeral, written to disk with mode 0600, and must never be
funded with anything of value.

The keypair records the network it was created for, and loading it against a
different network is refused. That guard exists because a conditioned message is
pinned to a chain id: a keypair minted for testnet (133) must not be reused to
sign a mainnet (177) session, or the same on-disk secret silently ends up
authorising two different chains.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address

from hskfaucet.network import DEFAULT_NETWORK, Network, get_network

WALLET_FILE = Path(os.environ.get("HSK_WALLET_FILE", "wallet.json"))


class WalletError(RuntimeError):
    pass


@dataclass
class Wallet:
    """An ephemeral local keypair for an HSKChain network."""

    address: str
    private_key: str
    path: Path | None = None
    #: Network this key was created for. Checked on load.
    network: Network = field(default=DEFAULT_NETWORK)

    @classmethod
    def generate(
        cls, path: Path | None = None, *, network: Network | str | None = None
    ) -> "Wallet":
        net = _coerce_network(network)
        account = Account.create(secrets.token_bytes(32))
        wallet = cls(
            address=account.address,
            private_key=account.key.hex(),
            path=Path(path) if path else None,
            # Not ``net or DEFAULT_NETWORK`` alone: a None passed explicitly
            # would override the field default and leave the wallet networkless.
            network=DEFAULT_NETWORK if net is None else net,
        )
        if wallet.path:
            wallet.save(wallet.path)
        return wallet

    @classmethod
    def load(cls, path: Path = WALLET_FILE, *, network: Network | str | None = None) -> "Wallet":
        if not path.exists():
            raise WalletError(
                f"no wallet at {path}; run `python cli.py wallet --new` first"
            )
        try:
            data = json.loads(path.read_text())
        except ValueError as exc:
            raise WalletError(f"wallet at {path} is not valid JSON: {exc}") from exc
        if not data.get("private_key"):
            raise WalletError(f"wallet at {path} has no private key")

        recorded = data.get("network") or data.get("chain_id")
        stored = _network_from_wallet_file(recorded)
        expected = _coerce_network(network)

        if stored is not None and expected is not None and stored.chain_id != expected.chain_id:
            raise WalletError(
                f"wallet at {path} is for {stored.name} (chain {stored.chain_id}) but "
                f"{expected.name} (chain {expected.chain_id}) is selected. Sign-ins are "
                f"pinned to a chain, so this key cannot be reused across networks. "
                f"Create a separate one with `--network {expected.slug}`, or point "
                f"HSK_NETWORK at {stored.slug}."
            )

        try:
            address = to_checksum_address(Account.from_key(data["private_key"]).address)
        except Exception as exc:
            raise WalletError(f"wallet at {path} has an unusable private key: {exc}") from exc

        return cls(
            address=address,
            private_key=data["private_key"],
            path=path,
            network=stored or expected or DEFAULT_NETWORK,
        )

    def save(self, path: Path | None = None) -> Path:
        target = Path(path or self.path or WALLET_FILE)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "address": self.address,
                    "private_key": self.private_key,
                    "network": self.network.name,
                    "chain_id": self.network.chain_id,
                    "warning": (
                        "Throwaway key used only to prove address control. Never send "
                        "funds to it; use a real wallet for anything that holds value."
                    ),
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


def _coerce_network(network: Network | str | None) -> Network | None:
    if network is None:
        return None
    if isinstance(network, Network):
        return network
    return get_network(network)


def _network_from_wallet_file(recorded) -> Network | None:
    """Read the network back off an existing wallet file, tolerating old files.

    Files written before networks were configurable carry ``"HSKChain Testnet"``
    or a bare chain id of 133, so the name is matched case-insensitively and a
    known chain id is accepted directly.
    """
    if recorded is None:
        return None
    if isinstance(recorded, int):
        return _network_from_chain_id(recorded)
    text = str(recorded).strip()
    if text.isdigit():
        return _network_from_chain_id(int(text))
    try:
        return get_network(text)
    except KeyError:
        return None


def _network_from_chain_id(chain_id: int) -> Network | None:
    from hskfaucet.network import HSK_MAINNET, HSK_TESTNET

    for net in (HSK_MAINNET, HSK_TESTNET):
        if net.chain_id == chain_id:
            return net
    return None


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


__all__ = ["WALLET_FILE", "Wallet", "WalletError", "recover_address"]
