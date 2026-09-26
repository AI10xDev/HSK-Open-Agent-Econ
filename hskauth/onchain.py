"""Minimal JSON-RPC client for checking accounts on the HSKChain testnet.

Signing is off-chain (EIP-191), so the RPC is not needed to *verify* a
signature. It is needed to answer the question "is this really a HSKChain
testnet account?", which is what :meth:`TestnetProbe.assert_testnet` and
:meth:`TestnetProbe.probe_address` are for:

* :meth:`chain_id` -- confirms the endpoint really serves chain 133, so a
  signature condition bound to the testnet cannot be satisfied against a
  mis-pointed or malicious RPC.
* :meth:`probe_address` -- reports an address' on-chain footprint (nonce,
  balance, code). An account that has interacted with the testnet (i.e. one the
  faucet has funded) looks different from one that has never been seen.

Only ``eth_*`` read methods are used; nothing here can spend funds.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests
from eth_utils import to_checksum_address

from hskfaucet.network import HSK_TESTNET, Network

log = logging.getLogger(__name__)


class RpcError(RuntimeError):
    """The RPC endpoint was unreachable or returned an error."""


@dataclass(frozen=True)
class AddressProbe:
    """On-chain footprint of an address on the testnet."""

    address: str
    nonce: int
    balance_wei: int
    is_contract: bool

    @property
    def active(self) -> bool:
        """Has this address ever appeared on chain (tx sent, funded, or code)?"""
        return self.nonce > 0 or self.balance_wei > 0 or self.is_contract

    @property
    def balance_hsk(self) -> float:
        return self.balance_wei / 1e18

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "nonce": self.nonce,
            "balanceWei": str(self.balance_wei),
            "balanceHSK": f"{self.balance_hsk:.6f}",
            "isContract": self.is_contract,
            "activeOnTestnet": self.active,
        }


class TestnetProbe:
    """Read-only JSON-RPC probe for the HSKChain testnet."""

    def __init__(
        self,
        network: Network = HSK_TESTNET,
        timeout: float = 15.0,
        session: requests.Session | None = None,
    ) -> None:
        self.network = network
        self.timeout = timeout
        self.session = session or requests.Session()

    # ------------------------------------------------------------------ rpc

    def call(self, method: str, params: list | None = None) -> Any:
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        try:
            response = self.session.post(
                self.network.rpc_url, json=body, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise RpcError(f"{method} failed: {exc}") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise RpcError(f"{method}: non-JSON response from RPC") from exc
        if "error" in payload:
            raise RpcError(f"{method}: {payload['error'].get('message', payload['error'])}")
        return payload.get("result")

    # -------------------------------------------------------------- helpers

    def chain_id(self) -> int:
        return int(self.call("eth_chainId"), 16)

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def assert_testnet(self) -> int:
        """Raise unless the endpoint is serving the expected testnet chain."""
        actual = self.chain_id()
        if actual != self.network.chain_id:
            raise RpcError(
                f"RPC {self.network.rpc_url} reports chainId {actual}, "
                f"expected {self.network.chain_id}"
            )
        return actual

    def probe_address(self, address: str) -> AddressProbe:
        address = to_checksum_address(address)
        nonce = int(self.call("eth_getTransactionCount", [address, "latest"]), 16)
        balance = int(self.call("eth_getBalance", [address, "latest"]), 16)
        code = self.call("eth_getCode", [address, "latest"]) or "0x"
        return AddressProbe(
            address=address,
            nonce=nonce,
            balance_wei=balance,
            is_contract=code not in ("0x", "", "0x0"),
        )

    def network_status(self) -> dict:
        """A snapshot for the ``/api/v1/network`` endpoint."""
        try:
            chain_id = self.chain_id()
            block = self.block_number()
            reachable, error = True, None
        except RpcError as exc:
            chain_id, block, reachable, error = None, None, False, str(exc)
        return {
            "name": self.network.name,
            "chainId": chain_id,
            "expectedChainId": self.network.chain_id,
            "isTestnet": chain_id == self.network.chain_id,
            "rpcUrl": self.network.rpc_url,
            "explorerUrl": self.network.explorer_url,
            "nativeSymbol": self.network.native_symbol,
            "blockNumber": block,
            "faucetUrl": self.network.faucet_url,
            "reachable": reachable,
            "error": error,
        }


__all__ = ["AddressProbe", "RpcError", "TestnetProbe"]
