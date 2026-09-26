"""HSKChain network parameters.

Both public HSKChain networks are registered here. The chain ids were verified
live against the public RPC endpoints (``eth_chainId`` returning ``0xb1`` == 177
for mainnet and ``0x85`` == 133 for testnet):

================  ========  =======================  ================================
Network           Chain ID  RPC                      Explorer
================  ========  =======================  ================================
HSKChain Mainnet  177       https://mainnet.hsk.xyz  https://hashkey.blockscout.com
HSKChain Testnet  133       https://testnet.hsk.xyz  https://testnet-explorer.hsk.xyz
================  ========  =======================  ================================

Which one this deployment talks to is a *runtime* decision, not a code edit: set
``HSK_NETWORK=mainnet`` (the default) or ``HSK_NETWORK=testnet``. Nothing below
is allowed to assume a particular network -- callers must always read the chain
id from here, because a conditioned message pinned to the wrong chain id is a
security bug, not a cosmetic one.

The faucet only exists on **testnet**. :attr:`Network.is_testnet` is the single
flag the faucet and wallet tooling branch on, so there is exactly one place to
look when asking "is this allowed to move value?".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

#: Environment variable selecting the network.
NETWORK_ENV_VAR = "HSK_NETWORK"


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
    #: False for the real-money network. Gates anything that could move funds.
    is_testnet: bool = True
    extra: dict = field(default_factory=dict)

    @property
    def slug(self) -> str:
        """Short lowercase id used in config and on the wire (``mainnet``)."""
        return "testnet" if self.is_testnet else "mainnet"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "slug": self.slug,
            "chain_id": self.chain_id,
            "rpc_url": self.rpc_url,
            "explorer_url": self.explorer_url,
            "native_symbol": self.native_symbol,
            "is_testnet": self.is_testnet,
            "faucet_url": self.faucet_url,
            "explorer_faucet_url": self.explorer_faucet_url,
        }


#: HSKChain **mainnet** -- real value. Chain id verified live: eth_chainId 0xb1.
#: Source: https://docs.hskchain.net/docs/Build-on-HashKey-Chain/network-info
HSK_MAINNET = Network(
    name="HSKChain Mainnet",
    chain_id=177,
    rpc_url="https://mainnet.hsk.xyz",
    explorer_url="https://hashkey.blockscout.com",
    native_symbol="HSK",
    faucet_url=None,  # no faucet on mainnet, by design
    explorer_faucet_url=None,
    is_testnet=False,
)

#: HSKChain **testnet** -- throwaway value, has the official faucet.
#: Source: https://docs.hashkeychain.net/docs/Build-on-HashKey-Chain/Tools/Faucet
HSK_TESTNET = Network(
    name="HSKChain Testnet",
    chain_id=133,
    rpc_url="https://testnet.hsk.xyz",
    explorer_url="https://testnet-explorer.hsk.xyz",
    native_symbol="HSK",
    faucet_url="https://faucet.hsk.xyz/faucet",
    explorer_faucet_url="https://testnet-explorer.hsk.xyz/faucet",
    is_testnet=True,
)

#: Look a network up by display name, slug, or ``HSK_NETWORK`` value.
NETWORKS: dict[str, Network] = {
    HSK_MAINNET.name: HSK_MAINNET,
    HSK_TESTNET.name: HSK_TESTNET,
    HSK_MAINNET.slug: HSK_MAINNET,
    HSK_TESTNET.slug: HSK_TESTNET,
}

#: Same mapping, keys normalised the way :func:`get_network` normalises lookups.
#: Built once because ``NETWORKS`` mixes display names ("HSKChain Mainnet") and
#: slugs ("mainnet"), which must both resolve regardless of case and spacing.
_ALIASES: dict[str, Network] = {
    key.strip().lower().replace(" ", ""): net for key, net in NETWORKS.items()
}


def get_network(name: str | None = None) -> Network:
    """Look a network up by name or slug. Defaults to :data:`DEFAULT_NETWORK`.

    Matching is case-insensitive and ignores spaces, so ``"HSKChain Testnet"``,
    ``"testnet"`` and ``"TESTNET"`` all resolve. Raises :class:`KeyError` for an
    unknown name rather than silently falling back -- pointing the service at the
    wrong chain would be far worse than refusing to start.
    """
    if name is None:
        return DEFAULT_NETWORK
    key = name.strip().lower().replace(" ", "")
    if key not in _ALIASES:
        raise KeyError(
            f"unknown network {name!r}; known networks: "
            f"{sorted({n.slug for n in _ALIASES.values()})}"
        )
    return _ALIASES[key]


def resolve_network(environ: dict | None = None, *, default: Network | None = None) -> Network:
    """Resolve the network this process should use, from the environment.

    ``HSK_NETWORK`` wins; an empty/unset value falls back to ``default`` (or
    mainnet, the target of this project). A malformed value raises
    :class:`KeyError` -- see :func:`get_network` for why we do not default
    instead.
    """
    env = os.environ if environ is None else environ
    raw = (env.get(NETWORK_ENV_VAR) or "").strip()
    if not raw:
        return default if default is not None else HSK_MAINNET
    try:
        return get_network(raw)
    except KeyError as exc:
        raise KeyError(f"{exc.args[0]} (from {NETWORK_ENV_VAR}={raw!r})") from exc


#: The network used when nothing says otherwise. Read once at import so that
#: dataclass field defaults (which are evaluated at class-creation time) can
#: reference a real network. Deployments set ``HSK_NETWORK``; mainnet is the
#: default because this project targets a mainnet deployment.
DEFAULT_NETWORK: Network = resolve_network()

#: The network the conditioned message in this project is pinned to.
DEFAULT_CHAIN_ID: int = DEFAULT_NETWORK.chain_id

__all__ = [
    "DEFAULT_CHAIN_ID",
    "DEFAULT_NETWORK",
    "HSK_MAINNET",
    "HSK_TESTNET",
    "NETWORKS",
    "NETWORK_ENV_VAR",
    "Network",
    "get_network",
    "resolve_network",
]
