"""HSKChain network parameters (verified live against the public testnet RPC)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Network:
    """An EVM network HSKChain-compatible tooling can point at."""

    name: str
    chain_id: int
    rpc_url: str
    explorer_url: str
    native_symbol: str
    faucet_url: str | None = None
    explorer_faucet_url: str | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "chain_id": self.chain_id,
            "rpc_url": self.rpc_url,
            "explorer_url": self.explorer_url,
            "native_symbol": self.native_symbol,
            "faucet_url": self.faucet_url,
            "explorer_faucet_url": self.explorer_faucet_url,
        }


#: HSKChain Testnet. Source: https://docs.hashkeychain.net/docs/Build-on-HashKey-Chain/Tools/Faucet
HSK_TESTNET = Network(
    name="HSKChain Testnet",
    chain_id=133,
    rpc_url="https://testnet.hsk.xyz",
    explorer_url="https://testnet-explorer.hsk.xyz",
    native_symbol="HSK",
    faucet_url="https://faucet.hsk.xyz/faucet",
    explorer_faucet_url="https://testnet-explorer.hsk.xyz/faucet",
)

#: The network the conditioned message in this project is pinned to.
DEFAULT_NETWORK = HSK_TESTNET

NETWORKS: dict[str, Network] = {HSK_TESTNET.name: HSK_TESTNET}


def get_network(name: str | None = None) -> Network:
    """Look a network up by name, or fall back to the HSK testnet."""
    if name is None:
        return DEFAULT_NETWORK
    if name not in NETWORKS:
        raise KeyError(
            f"unknown network {name!r}; known networks: {sorted(NETWORKS)}"
        )
    return NETWORKS[name]
