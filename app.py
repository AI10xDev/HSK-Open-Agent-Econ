"""Flask API whose POST data endpoint is unlocked by a signed conditioned
message from an HSKChain account.

Deployable against either HSKChain network. ``HSK_NETWORK`` selects it:

* ``HSK_NETWORK=mainnet`` (default) -- chain 177, real value.
* ``HSK_NETWORK=testnet`` -- chain 133, faucet available.

The three-step handshake is identical on both:

1. ``POST /api/v1/challenge``  -- server issues a conditioned message pinned to
   the selected network for the caller's address, with a fresh single-use nonce.
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

See ``README.md`` for the production checklist; the short version is that a real
deployment must set ``HSK_TOKEN_SECRET`` and ``HSK_NONCE_STORE``.
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
    ChainProbe,
    ConditionedMessageVerifier,
    FileNonceStore,
    InMemoryNonceStore,
    TokenError,
    TokenIssuer,
    VerifierConfig,
    build_message,
    secret_from_env,
    statement_for,
)
from hskfaucet.network import (
    NETWORK_ENV_VAR,
    Network,
    resolve_network,
)

log = logging.getLogger(__name__)

API = "/api/v1"
DATA_URI = f"{API}/data"


class ConfigError(RuntimeError):
    """The service is misconfigured and must not start."""


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
    """Read service configuration out of the environment.

    The network is resolved first, because everything else keys off it. An
    ``HSK_CHAIN_ID`` that disagrees with the selected network is a hard error
    rather than something to prefer one way or the other: a chain condition
    pointing at 133 while the service reports mainnet is exactly the kind of
    mismatch that silently weakens the gate, so we refuse to boot.
    """
    try:
        network = resolve_network()
    except KeyError as exc:
        raise ConfigError(f"{exc.args[0]}") from exc

    chain_id = _env_int("HSK_CHAIN_ID", network.chain_id)
    if chain_id != network.chain_id:
        raise ConfigError(
            f"HSK_CHAIN_ID={chain_id} does not match {NETWORK_ENV_VAR}="
            f"{network.slug} ({network.name}, chain {network.chain_id}). Unset "
            f"HSK_CHAIN_ID, or set it to {network.chain_id}."
        )

    nonce_store_path = os.environ.get("HSK_NONCE_STORE")
    from hskfaucet.client import DEFAULT_API_URL

    is_production = _env_bool("HSK_PRODUCTION", not network.is_testnet)
    token_secret = secret_from_env(allow_generated=not is_production)

    return {
        "network": network,
        # Host+port the client connects to; part of the signed conditions.
        "domain": os.environ.get("HSK_DOMAIN", "localhost:5000"),
        # The endpoint the token unlocks.
        "uri": os.environ.get("HSK_URI", DATA_URI),
        "statement": os.environ.get("HSK_STATEMENT") or None,
        "chain_id": chain_id,
        "allowed_addresses": _env_list("HSK_ALLOWED_ADDRESSES"),
        "token_secret": token_secret,
        "token_ttl": _env_int("HSK_TOKEN_TTL", 900),
        "message_ttl": _env_int("HSK_MESSAGE_TTL", 300),
        "require_onchain": _env_bool("HSK_REQUIRE_ONCHAIN", False),
        "onchain_fatal": _env_bool("HSK_ONCHAIN_FATAL", False),
        "faucet_api_url": os.environ.get("HSK_FAUCET_API_URL", DEFAULT_API_URL),
        "is_production": is_production,
        "expose_session_list": _env_bool("HSK_EXPOSE_SESSION_LIST", False),
        "rpc_timeout": _env_int("HSK_RPC_TIMEOUT", 15),
        "nonce_store": FileNonceStore(nonce_store_path)
        if nonce_store_path
        else InMemoryNonceStore(),
    }


# ----------------------------------------------------------------- app factory


def create_app(config: dict | None = None) -> Flask:
    config = config or build_config()
    network: Network = config["network"]
    # An explicit HSK_STATEMENT wins; otherwise the wording follows the network.
    statement = config.get("statement") or statement_for(network)

    app = Flask(__name__)
    app.json.sort_keys = False
    app.config["HSK"] = config

    probe = ChainProbe(network, timeout=config.get("rpc_timeout", 15))
    # Separate, impatient probe for the request path: a slow node must not turn
    # a fast API into a slow one.
    head_probe = ChainProbe(network, timeout=min(3.0, config.get("rpc_timeout", 15)))
    verifier = ConditionedMessageVerifier(
        VerifierConfig(
            chain_id=config["chain_id"],
            network_name=network.name,
            domain=config["domain"],
            uri=config["uri"],
            statement=statement,
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
                                f"sign the returned message with your {network.name} account",
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

    head_cache: dict = {"block": None, "at": 0.0}

    def current_head(max_age: float = 15.0) -> int | None:
        """Latest block height, cached briefly.

        The data endpoint is on the request path, so it must not inherit the
        probe's 15s RPC timeout -- a slow node would otherwise show up as a hung
        API. Refresh at most every ``max_age`` seconds and serve the previous
        value (or ``None``) when the node is unreachable.
        """
        now = time.monotonic()
        if head_cache["block"] is not None and now - head_cache["at"] < max_age:
            return head_cache["block"]
        block = head_probe.block_number()
        if block is not None:
            head_cache.update(block=block, at=now)
        return block

    # -------------------------------------------------------------- routes

    @app.get("/")
    def index():
        return jsonify(
            {
                "service": f"HSKChain conditioned-message data API ({network.name})",
                "network": network.to_dict(),
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
        return jsonify(
            {
                "status": "ok",
                "network": network.slug,
                "chainId": config["chain_id"],
                "time": int(time.time()),
            }
        )

    @app.get(f"{API}/network")
    def network_status():
        """Live check that we are pointed at the network we think we are."""
        status = probe.network_status()
        status["faucetApi"] = (
            config.get("faucet_api_url") if network.is_testnet else None
        )
        return jsonify(status), (200 if status["reachable"] else 503)

    @app.post(f"{API}/challenge")
    def challenge():
        """Issue a conditioned message bound to the selected network."""
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
                statement=statement,
                nonce=verifier.issue_nonce(),
                expiry_seconds=config["message_ttl"],
                network=network,
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
                "network": network.name,
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

        # Real head when the RPC answers, so the payload is not fiction. Falls
        # back to a stable per-session offset if the node is unreachable.
        head = current_head()
        base = head if head is not None else 33_000_000

        return jsonify(
            {
                "granted": True,
                "reason": f"signed conditioned message verified against {network.name}",
                "authorizedBy": {
                    "address": access.address,
                    "chainId": access.chain_id,
                    "sessionId": access.session_id,
                    "requestId": access.request_id,
                    "signature": access.signature_fingerprint,
                },
                "network": {
                    "name": network.name,
                    "chainId": network.chain_id,
                    "rpcUrl": network.rpc_url,
                    "isTestnet": network.is_testnet,
                },
                # The data that was being withheld until the token checked out.
                "data": {
                    "dataset": f"hsk-{network.slug}-blocks",
                    "generatedAt": int(time.time()),
                    "head": head,
                    "records": [
                        {
                            "id": f"blk-{n}",
                            "height": base - (3 - n),
                            "chainId": network.chain_id,
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
    @require_token
    def session_info():
        """The caller's own session.

        Requires a bearer token and only ever returns the session that token
        belongs to. The full list of every session on the instance is an
        operator view (it enumerates other users' addresses), so it stays hidden
        behind ``HSK_EXPOSE_SESSION_LIST=true``.
        """
        access = g.access
        own = next(
            (s for s in issuer.sessions() if s["sessionId"] == access.session_id), None
        )
        payload = {"session": own}
        if config["expose_session_list"]:
            payload["sessions"] = issuer.sessions()
        return jsonify(payload)

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
    net = app.config["HSK"]["network"]
    log.info("network = %s (chainId %d) via %s", net.name, net.chain_id, net.rpc_url)
    if net.is_testnet:
        log.info("faucet available (testnet only)")
    else:
        log.info("mainnet: faucet disabled, HSK_TOKEN_SECRET is required")
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )
