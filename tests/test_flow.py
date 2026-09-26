"""Tests proving each condition of the signed message actually gates execution.

Run with::

    .venv/bin/python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hskauth import (  # noqa: E402
    ConditionedMessageVerifier,
    FileNonceStore,
    InMemoryNonceStore,
    TokenError,
    TokenIssuer,
    VerifierConfig,
    Wallet,
    build_message,
    recover_address,
)
from hskauth.message import ConditionedMessage, generate_nonce  # noqa: E402
from hskfaucet.hmac_auth import FaucetCredentials, canonical_request, sign  # noqa: E402
from hskfaucet.network import HSK_TESTNET  # noqa: E402

TEST_SECRET = "unit-test-secret-0123456789abcdef"


def make_verifier(**overrides) -> tuple[ConditionedMessageVerifier, Wallet]:
    wallet = Wallet.generate()
    config = VerifierConfig(
        domain="localhost:5000",
        uri="/api/v1/data",
        **overrides,
    )
    return ConditionedMessageVerifier(config), wallet


def signed(v: ConditionedMessageVerifier, wallet: Wallet, **overrides) -> tuple[dict, str]:
    """Issue + sign a message. ``overrides`` deliberately break conditions."""
    fields = {
        "domain": v.config.domain,
        "uri": v.config.uri,
        "chain_id": v.config.chain_id,
        "statement": v.config.statement,
    }
    fields.update(overrides)
    message = build_message(wallet.address, nonce=v.issue_nonce(), **fields)
    signature = wallet.sign_message(message.as_message())
    return {**message.to_dict(), "signature": signature}, signature


class TestFaucetInstall(unittest.TestCase):
    def test_manifest_is_installed_and_intact(self):
        from hskfaucet import installer

        self.assertTrue(
            installer.check(Path(installer.INSTALL_DIR), quiet=True),
            "faucet install is corrupt",
        )

    def test_manifest_pins_testnet_133(self):
        from hskfaucet import installer

        manifest = installer.InstallManifest.load(
            Path(installer.INSTALL_DIR) / "install-manifest.json"
        )
        self.assertEqual(manifest.network["chain_id"], 133)
        self.assertEqual(manifest.network["name"], "HSKChain Testnet")
        self.assertIn("/api/faucet/drip", manifest.endpoints.values())

    def test_canonical_request_matches_frontend_format(self):
        canonical = canonical_request("post", "/api/faucet/drip", "Mon, 01 Jan 2024 00:00:00 GMT")
        self.assertEqual(
            canonical,
            "x-date: Mon, 01 Jan 2024 00:00:00 GMT\nPOST /api/faucet/drip HTTP/1.1",
        )

    def test_signature_is_deterministic_for_a_fixed_timestamp(self):
        creds = FaucetCredentials("faucet", "dce7OzR8GyYd")
        a = sign("GET", "https://faucet-api.hashkeychain.net/api/faucet/query?txId=1", creds, "Mon, 01 Jan 2024 00:00:00 GMT")
        b = sign("GET", "https://faucet-api.hashkeychain.net/api/faucet/query?txId=1", creds, "Mon, 01 Jan 2024 00:00:00 GMT")
        self.assertEqual(a, b)
        self.assertIn('algorithm="hmac-sha256"', a["X-Signature"])
        # A different query string must produce a different signature.
        c = sign("GET", "https://faucet-api.hashkeychain.net/api/faucet/query?txId=2", creds, "Mon, 01 Jan 2024 00:00:00 GMT")
        self.assertNotEqual(a["X-Signature"], c["X-Signature"])

    def test_faucet_client_refuses_without_recaptcha(self):
        from hskfaucet import FaucetClient, RecaptchaRequired

        client = FaucetClient()
        with self.assertRaises(RecaptchaRequired):
            client.drip("0x" + "11" * 20, None)


class TestConditionedMessage(unittest.TestCase):
    def test_defaults_are_pinned_to_hsk_testnet(self):
        wallet = Wallet.generate()
        message = build_message(wallet.address)
        self.assertEqual(message.chain_id, 133)
        self.assertEqual(HSK_TESTNET.chain_id, 133)

    def test_rendered_message_contains_all_conditions(self):
        wallet = Wallet.generate()
        text = build_message(wallet.address, domain="api.test:443", uri="/x").as_message()
        for fragment in ("api.test:443", "/x", "Chain ID: 133", "Nonce:", "Issued At:", "Expiration Time:"):
            self.assertIn(fragment, text)

    def test_nonce_is_unique_and_well_formed(self):
        nonces = {generate_nonce() for _ in range(500)}
        self.assertEqual(len(nonces), 500)
        for n in nonces:
            self.assertEqual(len(n), 32)
            self.assertTrue(set(n) <= set("0123456789abcdef"))

    def test_roundtrip(self):
        wallet = Wallet.generate()
        message = build_message(wallet.address)
        again = ConditionedMessage.from_dict(message.to_dict())
        self.assertEqual(again.as_message(), message.as_message())

    def test_from_dict_rejects_missing_fields(self):
        wallet = Wallet.generate()
        payload = build_message(wallet.address).to_dict()
        del payload["chainId"]
        with self.assertRaises(ValueError):
            ConditionedMessage.from_dict(payload)

    def test_expiration_must_follow_issued_at(self):
        with self.assertRaises(ValueError):
            ConditionedMessage(
                address="0x" + "11" * 20,
                nonce=generate_nonce(),
                expiration_time=ConditionedMessage(address="0x" + "11" * 20, nonce=generate_nonce()).issued_at,
            )


class TestVerificationConditions(unittest.TestCase):
    """One test per condition, proving it really blocks."""

    def test_valid_signature_passes_every_condition(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        result = v.verify(payload)
        self.assertTrue(result.valid, result.reason())
        self.assertEqual(result.signer, wallet.address)
        self.assertTrue(all(c.passed for c in result.checks))

    def test_wrong_signer_is_rejected(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        other = Wallet.generate()
        # Re-sign the *same* text with a different key.
        payload["signature"] = other.sign_message(
            ConditionedMessage.from_dict(payload).as_message()
        )
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("signer_matches", [c.condition.value for c in result.failures])

    def test_tampered_message_text_is_rejected(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        payload["message"] = payload["message"].replace("moves no funds", "moves all funds")
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("schema", [c.condition.value for c in result.failures])

    def test_wrong_chain_is_rejected(self):
        """A signature made for another chain must not unlock the testnet."""
        v, wallet = make_verifier()
        message = build_message(
            wallet.address, domain=v.config.domain, uri=v.config.uri, chain_id=1
        )
        signature = wallet.sign_message(message.as_message())
        result = v.verify({**message.to_dict(), "signature": signature})
        self.assertFalse(result.valid)
        failed = [c.condition.value for c in result.failures]
        self.assertIn("chain", failed)

    def test_wrong_domain_is_rejected(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet, domain="evil.example:443")
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("domain", [c.condition.value for c in result.failures])

    def test_wrong_uri_is_rejected(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet, uri="/api/v1/admin")
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("uri", [c.condition.value for c in result.failures])

    def test_wrong_statement_is_rejected(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet, statement="Sign in to something else entirely.")
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("statement", [c.condition.value for c in result.failures])

    def test_expired_message_is_rejected(self):
        v, wallet = make_verifier()
        message = build_message(
            wallet.address, domain=v.config.domain, uri=v.config.uri, chain_id=v.config.chain_id,
            nonce=v.issue_nonce(), expiry_seconds=1,
        )
        signature = wallet.sign_message(message.as_message())
        # Pretend it was signed two hours ago and has already lapsed.
        stale = message.to_dict()
        stale["issuedAt"] = (message.issued_at - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        stale["expirationTime"] = (message.issued_at - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        result = v.verify({**stale, "signature": signature}, consume_nonce=False)
        self.assertFalse(result.valid)
        self.assertIn("not_expired", [c.condition.value for c in result.failures])

    def test_future_issued_at_is_rejected(self):
        v, wallet = make_verifier()
        message = build_message(
            wallet.address, domain=v.config.domain, uri=v.config.uri, chain_id=v.config.chain_id,
            nonce=v.issue_nonce(),
        )
        signature = wallet.sign_message(message.as_message())
        payload = message.to_dict()
        payload["issuedAt"] = (message.issued_at + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        payload["expirationTime"] = (message.issued_at + timedelta(hours=3)).isoformat().replace("+00:00", "Z")
        result = v.verify({**payload, "signature": signature}, consume_nonce=False)
        self.assertFalse(result.valid)
        self.assertIn("issued_at", [c.condition.value for c in result.failures])

    def test_unknown_nonce_is_rejected(self):
        v, wallet = make_verifier()
        message = build_message(
            wallet.address, domain=v.config.domain, uri=v.config.uri, chain_id=v.config.chain_id,
            nonce=generate_nonce(),  # never issued by this server
        )
        signature = wallet.sign_message(message.as_message())
        result = v.verify({**message.to_dict(), "signature": signature})
        self.assertFalse(result.valid)
        self.assertIn("nonce_issued", [c.condition.value for c in result.failures])

    def test_replay_is_rejected(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        self.assertTrue(v.verify(payload).valid)
        second = v.verify(payload)
        self.assertFalse(second.valid)
        self.assertIn("nonce_unused", [c.condition.value for c in second.failures])

    def test_failed_verification_does_not_burn_the_nonce(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        bad = dict(payload, signature="0x" + "11" * 65)
        self.assertFalse(v.verify(bad).valid)
        # The legitimate signature must still work afterwards.
        self.assertTrue(v.verify(payload).valid)

    def test_allowlist_blocks_other_addresses(self):
        allowed = Wallet.generate()
        v, wallet = make_verifier(allowed_addresses=(allowed.address,))
        payload, _ = signed(v, wallet)
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("address_allowed", [c.condition.value for c in result.failures])

    def test_allowlist_admits_listed_address(self):
        wallet = Wallet.generate()
        v, _ = make_verifier(allowed_addresses=(wallet.address,))
        payload, _ = signed(v, wallet)
        result = v.verify(payload)
        self.assertTrue(result.valid, result.reason())
        self.assertIn("address_allowed", [c.condition.value for c in result.checks])

    def test_malformed_signature_is_rejected(self):
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        result = v.verify(dict(payload, signature="0xdeadbeef"))
        self.assertFalse(result.valid)
        self.assertIn("signature_format", [c.condition.value for c in result.failures])

    def test_onchain_requirement_can_be_enforced(self):
        v, wallet = make_verifier(require_onchain_activity=True, address_probe=lambda a: False)
        payload, _ = signed(v, wallet)
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("onchain", [c.condition.value for c in result.failures])

    def test_onchain_probe_failure_is_not_fatal_by_default(self):
        def boom(_addr):
            raise RuntimeError("rpc down")

        v, wallet = make_verifier(require_onchain_activity=True, address_probe=boom)
        payload, _ = signed(v, wallet)
        self.assertTrue(v.verify(payload).valid)


class TestNonceStore(unittest.TestCase):
    def test_consume_is_single_use(self):
        store = InMemoryNonceStore()
        nonce = store.issue()
        self.assertTrue(store.known(nonce))
        self.assertTrue(store.consume(nonce))
        self.assertFalse(store.consume(nonce))

    def test_file_store_persists_across_instances(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nonces.json"
            first = FileNonceStore(path)
            nonce = first.issue()
            first.consume(nonce)

            second = FileNonceStore(path)
            self.assertTrue(second.known(nonce))
            self.assertFalse(second.consume(nonce))  # already spent


class TestToken(unittest.TestCase):
    def setUp(self):
        self.issuer = TokenIssuer(TEST_SECRET, ttl=300)
        self.wallet = Wallet.generate()
        self.v, _ = make_verifier()

    def mint(self, **kwargs):
        defaults = dict(
            address=self.wallet.address,
            chain_id=133,
            nonce=generate_nonce(),
            request_id="req-1",
            signature="0x" + "ab" * 65,
        )
        defaults.update(kwargs)
        return self.issuer.issue(**defaults)

    def test_token_is_opaque_and_random_looking(self):
        token = self.mint().token
        self.assertTrue(token.startswith("hsk1."))
        self.assertGreater(len(token), 80)
        # Not the raw signature, and not the address.
        self.assertNotIn(self.wallet.address[2:].lower(), token.lower())

    def test_token_binds_the_signed_message(self):
        a = self.mint(nonce="a" * 32, request_id="r1")
        b = self.mint(nonce="b" * 32, request_id="r1")
        self.assertNotEqual(a.token, b.token)

    def test_validate_roundtrip(self):
        access = self.mint()
        validated = self.issuer.validate(access.token)
        self.assertEqual(validated.address, self.wallet.address)
        self.assertEqual(validated.chain_id, 133)
        self.assertEqual(validated.session_id, access.session_id)

    def test_tampered_token_is_rejected(self):
        token = self.mint().token
        prefix, payload, mac = token.split(".")
        flipped = payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1]
        with self.assertRaises(TokenError):
            self.issuer.validate(f"{prefix}.{flipped}.{mac}")

    def test_forged_token_without_secret_is_rejected(self):
        access = self.mint()
        attacker = TokenIssuer("a-different-secret-000000", ttl=300)
        with self.assertRaises(TokenError):
            attacker.validate(access.token)

    def test_expired_token_is_rejected(self):
        issuer = TokenIssuer(TEST_SECRET, ttl=-1)
        with self.assertRaises(TokenError) as ctx:
            issuer.validate(issuer.issue(
                address=self.wallet.address, chain_id=133, nonce="n", request_id="r",
                signature="0x" + "ab" * 65,
            ).token)
        self.assertIn("expired", str(ctx.exception))

    def test_revocation(self):
        access = self.mint()
        self.assertTrue(self.issuer.revoke(access.session_id))
        with self.assertRaises(TokenError):
            self.issuer.validate(access.token)
        self.assertFalse(self.issuer.revoke("nope"))

    def test_malformed_tokens_rejected(self):
        for bad in ("", "abc", "hsk1.abc", "hsk1.a.b.c", "notatoken"):
            with self.assertRaises(TokenError):
                self.issuer.validate(bad)

    def test_short_secret_rejected(self):
        with self.assertRaises(TokenError):
            TokenIssuer("tooshort")


class TestWallet(unittest.TestCase):
    def test_sign_and_recover(self):
        wallet = Wallet.generate()
        message = build_message(wallet.address)
        signature = wallet.sign_message(message.as_message())
        self.assertEqual(recover_address(message.as_message(), signature), wallet.address)

    def test_save_and_load(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "w.json"
            created = Wallet.generate()
            created.save(path)
            self.assertEqual(oct(path.stat().st_mode)[-3:], "600")
            self.assertEqual(Wallet.load(path).address, created.address)

    def test_load_missing_wallet_raises(self):
        from hskauth import WalletError

        with self.assertRaises(WalletError):
            Wallet.load(Path("/nonexistent/wallet.json"))


class TestFlaskApi(unittest.TestCase):
    """End-to-end through the HTTP layer, with the network mocked out."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("HSK_TOKEN_SECRET", TEST_SECRET)
        os.environ["HSK_NONCE_STORE"] = "/tmp/hsk-test-nonces.json"
        Path(os.environ["HSK_NONCE_STORE"]).unlink(missing_ok=True)
        import app as app_module

        cls.wallet = Wallet.generate()
        cls.app = app_module.create_app()
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        Path(os.environ["HSK_NONCE_STORE"]).unlink(missing_ok=True)

    def handshake(self) -> str:
        res = self.client.post("/api/v1/challenge", json={"address": self.wallet.address})
        self.assertEqual(res.status_code, 200, res.get_json())
        challenge = res.get_json()
        signature = self.wallet.sign_message(challenge["message"])
        res = self.client.post(
            "/api/v1/verify", json={**challenge, "signature": signature}
        )
        self.assertEqual(res.status_code, 200, res.get_json())
        return res.get_json()["token"]["token"]

    def test_data_requires_a_token(self):
        res = self.client.post("/api/v1/data", json={})
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.get_json()["error"], "missing_token")
        self.assertIn("WWW-Authenticate", res.headers)

    def test_data_rejects_a_forged_token(self):
        res = self.client.post(
            "/api/v1/data", json={}, headers={"Authorization": "Bearer hsk1.aaa.bbb"}
        )
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.get_json()["error"], "invalid_token")

    def test_full_flow_returns_data(self):
        token = self.handshake()
        res = self.client.post(
            "/api/v1/data",
            json={"echo": "ping"},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertTrue(body["granted"])
        self.assertEqual(body["authorizedBy"]["address"], self.wallet.address)
        self.assertEqual(body["authorizedBy"]["chainId"], 133)
        self.assertEqual(body["data"]["count"], 3)
        self.assertEqual(body["echo"], "ping")

    def test_challenge_requires_address(self):
        res = self.client.post("/api/v1/challenge", json={})
        self.assertEqual(res.status_code, 400)

    def test_challenge_rejects_bad_address(self):
        res = self.client.post("/api/v1/challenge", json={"address": "0x123"})
        self.assertEqual(res.status_code, 400)

    def test_verify_requires_signature(self):
        res = self.client.post("/api/v1/verify", json={})
        self.assertEqual(res.status_code, 400)

    def test_verify_rejects_wrong_signer_with_403_and_breakdown(self):
        res = self.client.post("/api/v1/challenge", json={"address": self.wallet.address})
        challenge = res.get_json()
        impostor = Wallet.generate()
        signature = impostor.sign_message(challenge["message"])
        res = self.client.post(
            "/api/v1/verify", json={**challenge, "signature": signature}
        )
        self.assertEqual(res.status_code, 403)
        body = res.get_json()
        self.assertEqual(body["error"], "conditions_not_met")
        self.assertFalse(body["valid"])
        self.assertIn("signer_matches", body["failed"])
        self.assertNotIn("token", body)

    def test_verify_rejects_a_replayed_signature(self):
        res = self.client.post("/api/v1/challenge", json={"address": self.wallet.address})
        challenge = res.get_json()
        signature = self.wallet.sign_message(challenge["message"])
        body = {**challenge, "signature": signature}
        first = self.client.post("/api/v1/verify", json=body)
        self.assertEqual(first.status_code, 200)
        second = self.client.post("/api/v1/verify", json=body)
        self.assertEqual(second.status_code, 403)
        self.assertIn("nonce_unused", second.get_json()["failed"])

    def test_session_revocation_requires_a_token(self):
        res = self.client.delete("/api/v1/session", json={})
        self.assertEqual(res.status_code, 401)

    def test_revoking_burns_the_token(self):
        token = self.handshake()
        res = self.client.delete(
            "/api/v1/session", json={}, headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res.status_code, 200, res.get_json())
        res = self.client.post(
            "/api/v1/data", json={}, headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("revoked", res.get_json()["message"])

    def test_cannot_revoke_someone_elses_session(self):
        token = self.handshake()
        res = self.client.delete(
            "/api/v1/session",
            json={"sessionId": "somebody-elses-session"},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.get_json()["error"], "forbidden_session")

    def test_each_condition_appears_exactly_once_in_the_report(self):
        """A duplicated condition name would make `failed` ambiguous."""
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        names = [c.condition.value for c in v.verify(payload).checks]
        self.assertEqual(len(names), len(set(names)), f"duplicated conditions: {names}")

    def test_unknown_endpoint_404(self):
        self.assertEqual(self.client.get("/nope").status_code, 404)

    def test_health(self):
        self.assertEqual(self.client.get("/health").status_code, 200)


class TestLiveTestnet(unittest.IsolatedAsyncioTestCase):
    """Talks to the real HSKChain testnet RPC. Skipped if unreachable."""

    def setUp(self):
        from hskauth import RpcError, TestnetProbe

        self.probe = TestnetProbe()
        try:
            self.probe.assert_testnet()
        except RpcError as exc:
            self.skipTest(f"HSKChain testnet RPC unreachable: {exc}")

    def test_rpc_serves_testnet_133(self):
        self.assertEqual(self.probe.chain_id(), 133)

    def test_probe_reports_an_address(self):
        wallet = Wallet.generate()
        probe = self.probe.probe_address(wallet.address)
        self.assertEqual(probe.address, wallet.address)
        self.assertFalse(probe.active)  # a brand new key has no footprint
        self.assertFalse(probe.is_contract)


if __name__ == "__main__":
    unittest.main(verbosity=2)
