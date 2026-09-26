"""Flask API whose POST data endpoint is unlocked by a signed conditioned
message from an HSKChain Testnet account.

The three-step handshake:

1. ``POST /api/v1/challenge``  -- server issues a conditioned message pinned to
   HSKChain Testnet (chain 133) for the caller's address, with a fresh
   single-use nonce.
2. ``POST /api/v1/verify``     -- the caller returns the message plus their
   ``personal_sign`` signature. If **every** condition holds, a bearer token is
   minted; otherwise the response is 403 with a per-condition breakdown.
3. ``POST /api/v1/data``       -- the protected POST endpoint. It requires
   ``Authorization: Bearer <token>``; the token is the random, MAC'd derivative
   of the signed message. With a valid token the payload is computed and
   returned, and only then.

Run it::

    python app.py                     # http://127.0.0.1:5000
    gunicorn -w 1 app:app              # single worker: nonce/session state is in RAM
"""

from __future__ import annotations

import logging
import os
import time
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request

load_dotenv()

from hskauth import (
    ConditionedMessageVerifier,
    FileNonceStore,
    InMemoryNonceStore,
    TestnetProbe,
    TokenError,
    TokenIssuer,
    VerifierConfig,
    build_message,
    secret_from_env,
)
from hskfaucet.network import HSK_TESTNET
from hskauth.message import DEFAULT_STATEMENT

log = logging.getLogger(__name__)

API = "/api/v1"
DATA_URI = f"{API}/data"


# --------------------------------------------------------------------- config


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_list(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(a.strip() for a in raw.split(",") if a.strip())


def build_config() -> dict:
    """Read service configuration out of the environment."""
    nonce_store_path = os.environ.get("HSK_NONCE_STORE")
    from hskfaucet.client import DEFAULT_API_URL

    return {
        # Host+port the client connects to; part of the signed conditions.
        "domain": os.environ.get("HSK_DOMAIN", "localhost:5000"),
        # The endpoint the token unlocks.
        "uri": os.environ.get("HSK_URI", DATA_URI),
        "statement": os.environ.get("HSK_STATEMENT", DEFAULT_STATEMENT),
        "chain_id": _env_int("HSK_CHAIN_ID", HSK_TESTNET.chain_id),
        "allowed_addresses": _env_list("HSK_ALLOWED_ADDRESSES"),
        "token_secret": secret_from_env(),
        "token_ttl": _env_int("HSK_TOKEN_TTL", 900),
        "message_ttl": _env_int("HSK_MESSAGE_TTL", 300),
        "require_onchain": _env_bool("HSK_REQUIRE_ONCHAIN", False),
        "onchain_fatal": _env_bool("HSK_ONCHAIN_FATAL", False),
        "faucet_api_url": os.environ.get("HSK_FAUCET_API_URL", DEFAULT_API_URL),
        "nonce_store": FileNonceStore(nonce_store_path)
        if nonce_store_path
        else InMemoryNonceStore(),
    }


# ----------------------------------------------------------------- app factory


def create_app(config: dict | None = None) -> Flask:
    config = config or build_config()

    app = Flask(__name__)
    app.json.sort_keys = False
    app.config["HSK"] = config

    probe = TestnetProbe(HSK_TESTNET)
    verifier = ConditionedMessageVerifier(
        VerifierConfig(
            chain_id=config["chain_id"],
            domain=config["domain"],
            uri=config["uri"],
            statement=config["statement"],
            allowed_addresses=config["allowed_addresses"],
            require_onchain_activity=config["require_onchain"],
            address_probe=probe.probe_address if config["require_onchain"] else None,
            onchain_failure_is_fatal=config["onchain_fatal"],
        ),
        nonce_store=config["nonce_store"],
    )
    issuer = TokenIssuer(config["token_secret"], ttl=config["token_ttl"])
    app.extensions["hsk"] = {
        "verifier": verifier,
        "issuer": issuer,
        "probe": probe,
        "config": config,
    }

    # ------------------------------------------------------------- helpers

    def require_token(fn):
        """Reject the request unless it carries a valid bearer token."""

        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                return (
                    jsonify(
                        {
                            "error": "missing_token",
                            "message": (
                                f"Send the token from POST {config['uri']} as "
                                "'Authorization: Bearer <token>'."
                            ),
                            "howToGetOne": [
                                f"POST {API}/challenge",
                                "sign the returned message with your HSKChain Testnet account",
                                f"POST {API}/verify",
                            ],
                        }
                    ),
                    401,
                    {"WWW-Authenticate": "Bearer"},
                )
            try:
                access = issuer.validate(token.strip())
            except TokenError as exc:
                return (
                    jsonify({"error": "invalid_token", "message": str(exc)}),
                    401,
                    {"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
            g.access = access
            return fn(*args, **kwargs)

        return wrapper

    def json_body() -> dict:
        body = request.get_json(silent=True)
        return body if isinstance(body, dict) else {}

    def error(message: str, status: int, code: str = "bad_request", **extra):
        return jsonify({"error": code, "message": message, **extra}), status

    # -------------------------------------------------------------- routes

    @app.get("/")
    def index():
        return jsonify(
            {
                "service": "HSKChain testnet conditioned-message data API",
                "network": HSK_TESTNET.to_dict(),
                "flow": {
                    "challenge": f"POST {API}/challenge",
                    "verify": f"POST {API}/verify",
                    "data": f"POST {config['uri']}  (requires Bearer token)",
                },
                "documentation": "/README.md",
            }
        )

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "time": int(time.time())})

    @app.get(f"{API}/network")
    def network():
        """Live check that we are pointed at the HSKChain testnet."""
        status = probe.network_status()
        status["faucetApi"] = config.get("faucet_api_url")
        return jsonify(status), (200 if status["reachable"] else 503)

    @app.post(f"{API}/challenge")
    def challenge():
        """Issue a conditioned message bound to the HSKChain testnet."""
        body = json_body()
        address = body.get("address")
        if not address:
            return error("`address` is required", 400, "address_required")

        try:
            message = build_message(
                address,
                domain=config["domain"],
                uri=config["uri"],
                chain_id=config["chain_id"],
                statement=config["statement"],
                nonce=verifier.issue_nonce(),
                expiry_seconds=config["message_ttl"],
            )
        except ValueError as exc:
            return error(str(exc), 400, "bad_address")

        return jsonify(
            {
                **message.to_dict(),
                # Echoed so the caller knows which signing scheme to use.
                "signingScheme": "EIP-191 personal_sign (eth_sign) over `message`",
            }
        )

    @app.post(f"{API}/verify")
    def verify():
        """Verify the signed conditioned message; mint a token only if valid."""
        body = json_body()
        signature = body.get("signature")
        if not signature:
            return error("`signature` is required", 400, "signature_required")

        try:
            from hskauth.message import ConditionedMessage

            message = ConditionedMessage.from_dict(body)
        except (ValueError, TypeError) as exc:
            return error(f"malformed conditioned message: {exc}", 400, "bad_message")

        result = verifier.verify(message.to_dict() | {"signature": signature})

        if not result.valid:
            return (
                jsonify(
                    {
                        "error": "conditions_not_met",
                        "message": "the signed message did not meet the conditions",
                        **result.to_dict(),
                    }
                ),
                403,
            )

        access = issuer.issue(
            address=result.signer,
            chain_id=result.chain_id,
            nonce=result.nonce,
            request_id=message.request_id,
            signature=signature,
        )
        return jsonify(
            {
                "verified": True,
                "signer": result.signer,
                "chainId": result.chain_id,
                "checks": [c.to_dict() for c in result.checks],
                "token": access.to_dict(),
                "usage": {
                    "header": "Authorization",
                    "scheme": "Bearer",
                    "example": f"curl -X POST http://{config['domain']}{config['uri']} "
                    f"-H 'Authorization: Bearer {access.token}' -H 'Content-Type: application/json' -d '{{}}'",
                },
            }
        )

    @app.post(config["uri"])
    @require_token
    def data():
        """The protected POST endpoint. Runs only with a valid signed-message token."""
        access = g.access
        body = json_body()

        # Optional echo-style check so the POST body is genuinely used.
        expected_echo = body.get("echo")
        if expected_echo is not None and not isinstance(expected_echo, str):
            return error("`echo` must be a string", 400, "bad_echo")

        return jsonify(
            {
                "granted": True,
                "reason": "signed conditioned message verified against HSKChain Testnet",
                "authorizedBy": {
                    "address": access.address,
                    "chainId": access.chain_id,
                    "sessionId": access.session_id,
                    "requestId": access.request_id,
                    "signature": access.signature_fingerprint,
                },
                "network": {
                    "name": HSK_TESTNET.name,
                    "chainId": HSK_TESTNET.chain_id,
                    "rpcUrl": HSK_TESTNET.rpc_url,
                },
                # The data that was being withheld until the token checked out.
                "data": {
                    "dataset": "hsk-testnet-blocks",
                    "generatedAt": int(time.time()),
                    "records": [
                        {
                            "id": f"blk-{n}",
                            "height": 33_000_000 + n,
                            "chainId": HSK_TESTNET.chain_id,
                            "hash": f"0x{(abs(hash((n, access.session_id))) % (1 << 64)):016x}",
                            "gasUsed": 21_000 * n,
                        }
                        for n in range(1, 4)
                    ],
                    "count": 3,
                },
                "echo": expected_echo,
            }
        )

    @app.get(f"{API}/session")
    def session_info():
        return jsonify({"sessions": issuer.sessions()})

    @app.delete(f"{API}/session")
    @require_token
    def revoke_session():
        """Burn a token early, e.g. on logout.

        Requires the bearer token, and only ever revokes the session that token
        belongs to -- otherwise anyone who learned a session id could kill
        someone else's session.
        """
        access = g.access
        requested = json_body().get("sessionId")
        if requested and requested != access.session_id:
            return error(
                "a token may only revoke its own session", 403, "forbidden_session"
            )
        if not issuer.revoke(access.session_id):
            return error("unknown session", 404, "unknown_session")
        return jsonify({"revoked": True, "sessionId": access.session_id})

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "not_found", "message": "no such endpoint"}), 404

    @app.errorhandler(405)
    def bad_method(_):
        return (
            jsonify({"error": "method_not_allowed", "message": "wrong HTTP method"}),
            405,
        )

    return app


app = create_app()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    log.info("HSKChain testnet = %s (chainId %d)", HSK_TESTNET.name, HSK_TESTNET.chain_id)
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
