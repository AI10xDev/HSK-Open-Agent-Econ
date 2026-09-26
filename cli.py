"""Command line for the HSKChain faucet + conditioned-message flow.

    python cli.py --network testnet faucet install   # download & install the faucet
    python cli.py --network testnet faucet claim 0xABC...
    python cli.py wallet --new                       # create a local keypair
    python cli.py balance                            # on-chain HSK balance
    python cli.py sign                               # sign a conditioned message locally
    python cli.py demo                               # full flow against a running API

``--network`` selects the chain (``mainnet`` or ``testnet``) and defaults to
``HSK_NETWORK``, which in turn defaults to mainnet. The faucet commands are
testnet-only by nature -- HSKChain mainnet has no faucet -- so they always act
on testnet and say so.

Environment (see .env.example):
    HSK_NETWORK, HSK_TOKEN_SECRET, HSK_DOMAIN, HSK_ALLOWED_ADDRESSES,
    HSK_FAUCET_HMAC_*
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Load .env before anything reads it at import time: HSK_NETWORK selects the
# network and HSK_WALLET_FILE is baked into a module constant.
load_dotenv()

# A bad HSK_NETWORK makes hskfaucet.network raise at *import* time, which would
# surface as a raw traceback. Catch it here, where we can still print a sentence
# and pick a sensible exit code.
try:
    from hskfaucet import network as _network_module
except KeyError as exc:  # pragma: no cover - depends on the operator's env
    print(f"error: {exc.args[0]}", file=sys.stderr)
    raise SystemExit(1) from exc

from hskauth import (
    ChainProbe,
    ConditionedMessageVerifier,
    VerifierConfig,
    Wallet,
    WalletError,
    build_message,
    statement_for,
)
from hskauth.wallet import WALLET_FILE
from hskfaucet import FaucetClient, FaucetError, HSK_TESTNET, RecaptchaRequired
from hskfaucet import installer as faucet_installer


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _network(args: argparse.Namespace):
    """The network this invocation targets: ``--network`` else ``HSK_NETWORK``."""
    # Unset --network resolves to DEFAULT_NETWORK, which hskfaucet.network
    # already derived from HSK_NETWORK at import time.
    return _network_module.get_network(getattr(args, "network", None))


# ----------------------------------------------------------------- faucet cmd


def cmd_faucet(args: argparse.Namespace) -> int:
    # The official faucet only exists on testnet, so these commands are pinned to
    # it regardless of what the rest of the service is pointed at.
    if not HSK_TESTNET.is_testnet:  # pragma: no cover - invariant guard
        raise FaucetError("faucet network invariant broken: not a testnet")

    if args.action == "install":
        manifest = faucet_installer.install()
        print()
        print("HSKChain testnet faucet installed.")
        print(f"  web app : {manifest.faucet_web_url}")
        print(f"  api     : {manifest.faucet_api_url}")
        print(f"  chain   : {manifest.network['chain_id']} ({manifest.network['name']})")
        for artifact in manifest.artifacts:
            print(f"  - {artifact.short}")
        return 0

    if args.action == "check":
        return 0 if faucet_installer.check() else 1

    client = FaucetClient(network=HSK_TESTNET)
    if args.action == "status":
        _print(
            {
                "api": client.api_url,
                "chainId": HSK_TESTNET.chain_id,
                "faucetUrl": HSK_TESTNET.faucet_url,
                "recaptchaSiteKey": client.recaptcha_site_key,
            }
        )
        return 0

    if args.action == "query":
        _print(client.query(args.job_id))
        return 0

    # claim
    address = args.address or _load_wallet(args).address
    try:
        if args.wait:
            result = client.drip_and_wait(address, args.recaptcha_token)
        else:
            result = client.drip(address, args.recaptcha_token)
    except RecaptchaRequired as exc:
        print(f"error: {exc}\n", file=sys.stderr)
        print("Get a token by solving the challenge at", HSK_TESTNET.faucet_url, file=sys.stderr)
        print("then re-run with --recaptcha-token <token>", file=sys.stderr)
        return 2
    except (FaucetError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _print(result.to_dict())
    if result.transaction_hash:
        print(f"\nExplorer: {HSK_TESTNET.explorer_url}/tx/{result.transaction_hash}")
    return 0


# ----------------------------------------------------------------- wallet cmd


def _load_wallet(args: argparse.Namespace) -> Wallet:
    network = _network(args)
    return Wallet.load(
        Path(getattr(args, "wallet", None) or WALLET_FILE), network=network
    )


def cmd_wallet(args: argparse.Namespace) -> int:
    network = _network(args)
    if args.new:
        wallet = Wallet.generate(network=network)
        path = wallet.save(Path(args.wallet or WALLET_FILE))
        print(f"created {network.name} wallet for {wallet.address}")
        print(
            f"private key written to {path} (mode 0600) -- throwaway key, never "
            f"fund it with anything of value"
        )
        return 0

    wallet = _load_wallet(args)
    probe = ChainProbe(network)
    _print(
        {
            "address": wallet.address,
            "file": str(Path(args.wallet or WALLET_FILE)),
            "network": network.to_dict(),
            "onchain": probe.probe_address(wallet.address).to_dict(),
        }
    )
    return 0


def cmd_balance(args: argparse.Namespace) -> int:
    network = _network(args)
    address = args.address or _load_wallet(args).address
    probe = ChainProbe(network)
    _print(
        {
            "network": probe.network_status(),
            "account": probe.probe_address(address).to_dict(),
        }
    )
    return 0


# -------------------------------------------------------------------- sign cmd


def cmd_sign(args: argparse.Namespace) -> int:
    """Build a conditioned message, sign it, and (optionally) self-verify.

    Useful for producing the exact body that ``POST /api/v1/verify`` expects,
    without running a server.
    """
    network = _network(args)
    wallet = _load_wallet(args)
    statement = args.statement or statement_for(network)
    verifier = ConditionedMessageVerifier(
        VerifierConfig.for_network(
            network, domain=args.domain, uri=args.uri, statement=statement
        )
    )
    message = build_message(
        wallet.address,
        domain=args.domain,
        uri=args.uri,
        chain_id=args.chain_id or network.chain_id,
        statement=statement,
        nonce=verifier.issue_nonce(),
        expiry_seconds=args.ttl,
        network=network,
    )
    signature = wallet.sign_message(message.as_message())

    if args.verify:
        # A throwaway verifier cannot know the nonce, so only self-check the
        # cryptographic part here; the server does the authoritative check.
        from hskauth import recover_address

        recovered = recover_address(message.as_message(), signature)
        print(f"recovered signer: {recovered}")
        print(f"matches wallet  : {recovered == wallet.address}")

    _print({**message.to_dict(), "signature": signature})
    return 0


# -------------------------------------------------------------------- demo cmd


def cmd_demo(args: argparse.Namespace) -> int:
    """Full handshake against a running instance of app.py."""
    import urllib.error
    import urllib.request

    base = args.base.rstrip("/")
    wallet = _load_wallet(args)
    network = _network(args)
    if network.chain_id != _chain_id_of(base):
        print(
            f"warning: this wallet is for {network.name} (chain {network.chain_id}) "
            f"but {base} reports a different chain; verification will fail.",
            file=sys.stderr,
        )

    def post(path: str, payload: dict, token: str | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(
            base + path,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    print(f"1. POST {base}/api/v1/challenge  ({network.name}, address {wallet.address})")
    status, challenge = post("/api/v1/challenge", {"address": wallet.address})
    if status != 200:
        print(f"   -> {status} {challenge}")
        return 1
    print(f"   nonce={challenge['nonce']} chainId={challenge['chainId']} expires={challenge['expirationTime']}")

    print("\n2. sign the conditioned message (EIP-191 personal_sign)")
    signature = wallet.sign_message(challenge["message"])
    print(f"   signature={signature[:20]}...{signature[-10:]}")

    print("\n3. POST /api/v1/verify")
    status, verified = post("/api/v1/verify", {**challenge, "signature": signature})
    if status != 200:
        print(f"   -> {status} {json.dumps(verified, indent=2)}")
        return 1
    token = verified["token"]["token"]
    print(f"   verified by {verified['signer']}")
    print(f"   token={token[:40]}...")

    print("\n4. POST /api/v1/data  (the gated endpoint)")
    status, unlocked = post("/api/v1/data", {"echo": "hello"}, token=token)
    print(f"   -> HTTP {status}")
    _print(unlocked)
    return 0 if status == 200 else 1


def _chain_id_of(base: str) -> int | None:
    """Ask a running service which chain it is on; ``None`` if unreachable."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"{base.rstrip('/')}/health", timeout=5) as resp:
            return json.loads(resp.read()).get("chainId")
    except (urllib.error.URLError, ValueError, OSError):
        return None


# ----------------------------------------------------------------- entry point


def _common_parser() -> argparse.ArgumentParser:
    """Options accepted by every subcommand.

    ``SUPPRESS`` is deliberate: these are repeated on each subparser so they can
    be given *after* the verb (``cli.py sign --network testnet``) as well as
    before it (``cli.py --network testnet sign``). Without it the subparser's
    ``None`` default would clobber a value already parsed from before the verb.
    """
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-n",
        "--network",
        default=argparse.SUPPRESS,
        metavar="NAME",
        help="HSK network to use: mainnet (default) or testnet. "
        "Defaults to $HSK_NETWORK.",
    )
    parent.add_argument(
        "--wallet", default=argparse.SUPPRESS, help="path to the keypair file"
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="cli.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "-n",
        "--network",
        default=None,
        metavar="NAME",
        help="HSK network to use: mainnet (default) or testnet. "
        "Defaults to $HSK_NETWORK.",
    )
    parser.add_argument("--wallet", default=None, help="path to the keypair file")
    sub = parser.add_subparsers(dest="command", required=True)

    # faucet
    p = sub.add_parser(
        "faucet",
        parents=[common],
        help="download/install/query the HSK testnet faucet (testnet only)",
    )
    fsub = p.add_subparsers(dest="action", required=True)
    fsub.add_parser("install", help="download and install the faucet app")
    fsub.add_parser("check", help="verify installed faucet artifacts")
    fsub.add_parser("status", help="show faucet endpoints and keys")
    q = fsub.add_parser("query", help="look up a drip job by id")
    q.add_argument("job_id")
    c = fsub.add_parser("claim", help="request testnet HSK for an address")
    c.add_argument("address", nargs="?", help="defaults to the local wallet")
    c.add_argument(
        "--recaptcha-token",
        default=os.environ.get("HSK_RECAPTCHA_TOKEN"),
        help="reCAPTCHA v2 token solved by a human at the faucet site",
    )
    c.add_argument("--wait", action="store_true", help="poll until the tx is mined")
    c.add_argument("--wallet", default=None)
    p.set_defaults(func=cmd_faucet)

    # wallet
    w = sub.add_parser("wallet", parents=[common], help="create or show a local keypair")
    w.add_argument("--new", action="store_true", help="generate a fresh keypair")
    w.set_defaults(func=cmd_wallet)

    # balance
    b = sub.add_parser("balance", parents=[common], help="on-chain balance / activity")
    b.add_argument("address", nargs="?")
    b.set_defaults(func=cmd_balance)

    # sign
    s = sub.add_parser("sign", parents=[common], help="build + sign a conditioned message")
    s.add_argument("--domain", default=os.environ.get("HSK_DOMAIN", "localhost:5000"))
    s.add_argument("--uri", default=os.environ.get("HSK_URI", "/api/v1/data"))
    s.add_argument(
        "--chain-id",
        type=int,
        default=None,
        help="override the chain id (defaults to the selected network)",
    )
    s.add_argument(
        "--statement",
        default=os.environ.get("HSK_STATEMENT"),
        help="override the consent text (defaults to the per-network text)",
    )
    s.add_argument("--ttl", type=int, default=300)
    s.add_argument("--verify", action="store_true", help="also recover the signer")
    s.set_defaults(func=cmd_sign)

    # demo
    d = sub.add_parser("demo", parents=[common], help="run the whole handshake against a live API")
    d.add_argument("--base", default=os.environ.get("HSK_API_BASE", "http://127.0.0.1:5000"))
    d.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)-7s %(message)s",
    )
    try:
        return args.func(args)
    except WalletError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    sys.exit(main())
