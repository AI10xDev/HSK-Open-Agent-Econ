"""Command line for the HSKChain testnet faucet + conditioned-message flow.

    python cli.py faucet install          # download & install the faucet
    python cli.py faucet check
    python cli.py faucet claim 0xABC...   # needs a human-solved reCAPTCHA token
    python cli.py wallet --new            # create a testnet keypair
    python cli.py balance                 # on-chain HSK balance on the testnet
    python cli.py sign                    # sign a conditioned message locally
    python cli.py demo                    # full flow against a running API

Environment (see .env.example):
    HSK_TOKEN_SECRET, HSK_DOMAIN, HSK_ALLOWED_ADDRESSES, HSK_FAUCET_HMAC_*
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from hskauth import (
    ConditionedMessageVerifier,
    TestnetProbe,
    VerifierConfig,
    Wallet,
    WalletError,
    build_message,
)
from hskauth.wallet import WALLET_FILE
from dotenv import load_dotenv

from hskfaucet import FaucetClient, FaucetError, HSK_TESTNET, RecaptchaRequired
from hskfaucet import installer as faucet_installer

load_dotenv()


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


# ----------------------------------------------------------------- faucet cmd


def cmd_faucet(args: argparse.Namespace) -> int:
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

    client = FaucetClient()
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
    return Wallet.load(Path(getattr(args, "wallet", None) or WALLET_FILE))


def cmd_wallet(args: argparse.Namespace) -> int:
    if args.new:
        wallet = Wallet.generate()
        path = wallet.save(Path(args.wallet or WALLET_FILE))
        print(f"created testnet wallet for {wallet.address}")
        print(f"private key written to {path} (mode 0600) -- TESTNET ONLY, never fund with real value")
        return 0

    wallet = _load_wallet(args)
    probe = TestnetProbe()
    _print(
        {
            "address": wallet.address,
            "file": str(Path(args.wallet or WALLET_FILE)),
            "onchain": probe.probe_address(wallet.address).to_dict(),
        }
    )
    return 0


def cmd_balance(args: argparse.Namespace) -> int:
    address = args.address or _load_wallet(args).address
    probe = TestnetProbe()
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
    wallet = _load_wallet(args)
    verifier = ConditionedMessageVerifier(
        VerifierConfig(
            chain_id=args.chain_id,
            domain=args.domain,
            uri=args.uri,
            statement=args.statement,
        )
    )
    message = build_message(
        wallet.address,
        domain=args.domain,
        uri=args.uri,
        chain_id=args.chain_id,
        statement=args.statement,
        nonce=verifier.issue_nonce(),
        expiry_seconds=args.ttl,
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

    print(f"1. POST {base}/api/v1/challenge  (address {wallet.address})")
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


# ----------------------------------------------------------------- entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    # faucet
    p = sub.add_parser("faucet", help="download/install/query the HSK testnet faucet")
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

    # wallet
    w = sub.add_parser("wallet", help="create or show the testnet keypair")
    w.add_argument("--new", action="store_true", help="generate a fresh keypair")
    w.add_argument("--wallet", default=None)
    w.set_defaults(func=cmd_wallet)

    # balance
    b = sub.add_parser("balance", help="on-chain balance / activity on the testnet")
    b.add_argument("address", nargs="?")
    b.add_argument("--wallet", default=None)
    b.set_defaults(func=cmd_balance)

    # sign
    s = sub.add_parser("sign", help="build + sign a conditioned message")
    s.add_argument("--wallet", default=None)
    s.add_argument("--domain", default=os.environ.get("HSK_DOMAIN", "localhost:5000"))
    s.add_argument("--uri", default=os.environ.get("HSK_URI", "/api/v1/data"))
    s.add_argument("--chain-id", type=int, default=HSK_TESTNET.chain_id)
    s.add_argument(
        "--statement",
        default=os.environ.get(
            "HSK_STATEMENT",
            "Sign in to the HSKChain testnet data API. This proves you control this "
            "HSKChain Testnet account and authorises one API session. It moves no funds.",
        ),
    )
    s.add_argument("--ttl", type=int, default=300)
    s.add_argument("--verify", action="store_true", help="also recover the signer")
    s.set_defaults(func=cmd_sign)

    # demo
    d = sub.add_parser("demo", help="run the whole handshake against a live API")
    d.add_argument("--base", default=os.environ.get("HSK_API_BASE", "http://127.0.0.1:5000"))
    d.add_argument("--wallet", default=None)
    d.set_defaults(func=cmd_demo)

    p.set_defaults(func=cmd_faucet)
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
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    sys.exit(main())
