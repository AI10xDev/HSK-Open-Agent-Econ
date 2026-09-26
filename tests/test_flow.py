"""Tests proving each condition of the signed message actually gates execution.

Network-agnostic by construction: the same conditions must hold on HSKChain
mainnet (chain 177) and testnet (chain 133), and a signature made for one must
never unlock the other. Both are exercised here.

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
    ChainProbe,
    ConditionedMessageVerifier,
    FileNonceStore,
    InMemoryNonceStore,
    TokenError,
    TokenIssuer,
    VerifierConfig,
    Wallet,
    WalletError,
    build_message,
    recover_address,
    statement_for,
)
from hskauth.message import ConditionedMessage, generate_nonce  # noqa: E402
from hskfaucet.hmac_auth import FaucetCredentials, canonical_request, sign  # noqa: E402
from hskfaucet.network import (  # noqa: E402
    DEFAULT_NETWORK,
    HSK_MAINNET,
    HSK_TESTNET,
    get_network,
    resolve_network,
)

TEST_SECRET = "unit-test-secret-0123456789abcdef"

#: The two networks a deployment can target.
BOTH_NETWORKS = (HSK_MAINNET, HSK_TESTNET)


def make_verifier(network=DEFAULT_NETWORK, **overrides) -> tuple[ConditionedMessageVerifier, Wallet]:
    wallet = Wallet.generate(network=network)
    config = VerifierConfig.for_network(
        network, domain="localhost:5000", uri="/api/v1/data", **overrides
    )
    return ConditionedMessageVerifier(config), wallet


def signed(v: ConditionedMessageVerifier, wallet: Wallet, **overrides) -> tuple[dict, str]:
    """Issue + sign a message. ``overrides`` deliberately break conditions."""
    fields = {
        "domain": v.config.domain,
        "uri": v.config.uri,
        "chain_id": v.config.chain_id,
        "statement": v.config.statement,
        "network": v.config.network_name,
    }
    fields.update(overrides)
    message = build_message(wallet.address, nonce=v.issue_nonce(), **fields)
    signature = wallet.sign_message(message.as_message())
    return {**message.to_dict(), "signature": signature}, signature


class TestNetworkRegistry(unittest.TestCase):
    """The mainnet refactor's foundation: which chain are we even talking to?"""

    def test_mainnet_params_are_correct(self):
        # Chain id verified live: eth_chainId on mainnet.hsk.xyz returns 0xb1.
        self.assertEqual(HSK_MAINNET.chain_id, 177)
        self.assertEqual(HSK_MAINNET.rpc_url, "https://mainnet.hsk.xyz")
        self.assertEqual(HSK_MAINNET.name, "HSKChain Mainnet")
        self.assertEqual(HSK_MAINNET.native_symbol, "HSK")
        self.assertFalse(HSK_MAINNET.is_testnet)

    def test_testnet_params_are_correct(self):
        self.assertEqual(HSK_TESTNET.chain_id, 133)
        self.assertEqual(HSK_TESTNET.rpc_url, "https://testnet.hsk.xyz")
        self.assertTrue(HSK_TESTNET.is_testnet)

    def test_the_two_networks_do_not_collide(self):
        self.assertNotEqual(HSK_MAINNET.chain_id, HSK_TESTNET.chain_id)
        self.assertNotEqual(HSK_MAINNET.rpc_url, HSK_TESTNET.rpc_url)

    def test_only_testnet_has_a_faucet(self):
        self.assertIsNotNone(HSK_TESTNET.faucet_url)
        self.assertIsNone(HSK_MAINNET.faucet_url)

    def test_lookup_by_name_slug_and_case(self):
        for label in ("mainnet", "MAINNET", "HSKChain Mainnet", "hskchain mainnet"):
            self.assertIs(get_network(label), HSK_MAINNET, label)
        for label in ("testnet", "TestNet", "HSKChain Testnet"):
            self.assertIs(get_network(label), HSK_TESTNET, label)

    def test_unknown_network_raises_instead_of_defaulting(self):
        """Silently falling back would point a mainnet deploy at the wrong chain."""
        with self.assertRaises(KeyError):
            get_network("goerli")

    def test_resolve_network_reads_the_env(self):
        self.assertIs(resolve_network({"HSK_NETWORK": "testnet"}), HSK_TESTNET)
        self.assertIs(resolve_network({"HSK_NETWORK": "mainnet"}), HSK_MAINNET)
        # Unset -> mainnet, the deployment target.
        self.assertIs(resolve_network({}), HSK_MAINNET)

    def test_default_network_follows_the_environment(self):
        """With HSK_NETWORK unset the default is mainnet; if set, it is honoured."""
        from hskfaucet.network import resolve_network as _resolve

        expected = _resolve(dict(os.environ))
        self.assertIs(DEFAULT_NETWORK, expected)
        # Env-independent assertion of the actual default.
        self.assertIs(_resolve({}), HSK_MAINNET)

    def test_statement_follows_the_network(self):
        self.assertIn("HSKChain Mainnet", statement_for(HSK_MAINNET))
        self.assertIn("HSKChain Testnet", statement_for(HSK_TESTNET))
        self.assertNotEqual(statement_for(HSK_MAINNET), statement_for(HSK_TESTNET))

    def test_slug_round_trips(self):
        for net in BOTH_NETWORKS:
            self.assertIs(get_network(net.slug), net)
            self.assertEqual(net.to_dict()["slug"], net.slug)


class TestVerifierConfigForNetwork(unittest.TestCase):
    def test_one_argument_sets_all_network_fields(self):
        for net in BOTH_NETWORKS:
            config = VerifierConfig.for_network(net)
            self.assertEqual(config.chain_id, net.chain_id)
            self.assertEqual(config.network_name, net.name)
            self.assertEqual(config.statement, statement_for(net))

    def test_explicit_overrides_win(self):
        config = VerifierConfig.for_network(HSK_MAINNET, statement="custom text")
        self.assertEqual(config.statement, "custom text")
        self.assertEqual(config.chain_id, HSK_MAINNET.chain_id)

    def test_accepts_a_network_name(self):
        self.assertEqual(
            VerifierConfig.for_network("testnet").chain_id, HSK_TESTNET.chain_id
        )


class TestFaucetIsTestnetOnly(unittest.TestCase):
    """The faucet dispatches real transactions; it must never point at mainnet."""

    def test_faucet_client_refuses_mainnet(self):
        from hskfaucet import FaucetClient, FaucetError

        with self.assertRaises(FaucetError) as ctx:
            FaucetClient(network=HSK_MAINNET)
        self.assertIn("testnet-only", str(ctx.exception))

    def test_faucet_client_still_works_on_testnet(self):
        from hskfaucet import FaucetClient

        self.assertEqual(FaucetClient(network=HSK_TESTNET).network.chain_id, 133)


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
    def test_defaults_are_pinned_to_the_default_network(self):
        wallet = Wallet.generate()
        message = build_message(wallet.address)
        self.assertEqual(message.chain_id, DEFAULT_NETWORK.chain_id)
        self.assertEqual(message.network_name, DEFAULT_NETWORK.name)

    def test_message_can_be_pinned_to_either_network(self):
        wallet = Wallet.generate()
        for net in BOTH_NETWORKS:
            message = build_message(wallet.address, network=net)
            self.assertEqual(message.chain_id, net.chain_id)
            self.assertEqual(message.network_name, net.name)
            self.assertIn(f"Chain ID: {net.chain_id}", message.as_message())

    def test_rendered_message_names_only_its_own_network(self):
        """A mainnet wallet must never be shown the word 'testnet' (or vice versa)."""
        wallet = Wallet.generate()
        for net in BOTH_NETWORKS:
            text = build_message(wallet.address, network=net).as_message()
            self.assertIn(f"your {net.name} account", text)
            other = HSK_TESTNET if net is HSK_MAINNET else HSK_MAINNET
            self.assertNotIn(other.name, text)

    def test_rendered_message_contains_all_conditions(self):
        wallet = Wallet.generate()
        text = build_message(
            wallet.address, domain="api.test:443", uri="/x", network=HSK_MAINNET
        ).as_message()
        for fragment in (
            "api.test:443",
            "/x",
            f"Chain ID: {HSK_MAINNET.chain_id}",
            "Nonce:",
            "Issued At:",
            "Expiration Time:",
        ):
            self.assertIn(fragment, text)

    def test_nonce_is_unique_and_well_formed(self):
        nonces = {generate_nonce() for _ in range(500)}
        self.assertEqual(len(nonces), 500)
        for n in nonces:
            self.assertEqual(len(n), 32)
            self.assertTrue(set(n) <= set("0123456789abcdef"))

    def test_roundtrip(self):
        wallet = Wallet.generate()
        for net in BOTH_NETWORKS:
            message = build_message(wallet.address, network=net)
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
        """A signature made for another chain must not unlock this service."""
        v, wallet = make_verifier()
        message = build_message(
            wallet.address, domain=v.config.domain, uri=v.config.uri, chain_id=1
        )
        signature = wallet.sign_message(message.as_message())
        result = v.verify({**message.to_dict(), "signature": signature})
        self.assertFalse(result.valid)
        failed = [c.condition.value for c in result.failures]
        self.assertIn("chain", failed)

    def test_a_signature_from_the_other_hsk_network_is_rejected(self):
        """The core mainnet property: testnet and mainnet keys are not interchangeable.

        The message is built *and correctly signed* for the other network, so the
        only thing standing between it and a token is the chain/network condition.
        """
        for target, other in (
            (HSK_MAINNET, HSK_TESTNET),
            (HSK_TESTNET, HSK_MAINNET),
        ):
            with self.subTest(service=target.name, signed_for=other.name):
                v, wallet = make_verifier(target)
                message = build_message(
                    wallet.address,
                    domain=v.config.domain,
                    uri=v.config.uri,
                    network=other,
                )
                self.assertEqual(message.chain_id, other.chain_id)
                signature = wallet.sign_message(message.as_message())
                result = v.verify({**message.to_dict(), "signature": signature})
                self.assertFalse(result.valid)
                failed = [c.condition.value for c in result.failures]
                self.assertIn("chain", failed)
                self.assertIn("network", failed)

    def test_wrong_network_name_is_rejected(self):
        v, wallet = make_verifier(HSK_MAINNET)
        payload, _ = signed(v, wallet, network=HSK_TESTNET.name)
        result = v.verify(payload)
        self.assertFalse(result.valid)
        self.assertIn("network", [c.condition.value for c in result.failures])

    def test_a_valid_signature_passes_on_both_networks(self):
        for net in BOTH_NETWORKS:
            with self.subTest(network=net.name):
                v, wallet = make_verifier(net)
                payload, _ = signed(v, wallet)
                result = v.verify(payload)
                self.assertTrue(result.valid, result.reason())
                self.assertEqual(result.chain_id, net.chain_id)

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
        with self.assertRaises(WalletError):
            Wallet.load(Path("/nonexistent/wallet.json"))

    def test_generated_wallet_records_its_network(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            for net in BOTH_NETWORKS:
                with self.subTest(network=net.name):
                    path = Path(tmp) / f"{net.slug}.json"
                    created = Wallet.generate(path, network=net)
                    self.assertEqual(created.network.chain_id, net.chain_id)
                    self.assertEqual(
                        Wallet.load(path, network=net).network.chain_id, net.chain_id
                    )

    def test_a_key_cannot_be_reused_across_networks(self):
        """A testnet key must not silently start authorising mainnet sessions."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            main = Wallet.generate(Path(tmp) / "main.json", network=HSK_MAINNET)
            with self.assertRaises(WalletError) as ctx:
                Wallet.load(Path(tmp) / "main.json", network=HSK_TESTNET)
            self.assertIn("chain", str(ctx.exception).lower())

            test = Wallet.generate(Path(tmp) / "test.json", network=HSK_TESTNET)
            with self.assertRaises(WalletError):
                Wallet.load(Path(tmp) / "test.json", network=HSK_MAINNET)
            # Loading for the right network is still fine.
            self.assertEqual(
                Wallet.load(Path(tmp) / "test.json", network=HSK_TESTNET).address,
                test.address,
            )
            self.assertEqual(main.network.chain_id, HSK_MAINNET.chain_id)

    def test_old_wallet_files_without_a_network_still_load(self):
        """Backwards compatibility: pre-network files recorded only a chain id."""
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            created = Wallet.generate(path, network=HSK_TESTNET)
            data = json.loads(path.read_text())
            data.pop("network")
            data["chain_id"] = 133
            data["network"] = "HSKChain Testnet"
            path.write_text(json.dumps(data))
            self.assertEqual(
                Wallet.load(path, network=HSK_TESTNET).address, created.address
            )

    def test_wallet_file_without_network_info_loads_unbound(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bare.json"
            created = Wallet.generate(path, network=HSK_MAINNET)
            data = json.loads(path.read_text())
            data.pop("network")
            data.pop("chain_id")
            path.write_text(json.dumps(data))
            # Nothing recorded -> nothing to contradict, so it loads.
            self.assertEqual(Wallet.load(path, network=HSK_TESTNET).address, created.address)

    def test_wallet_never_claims_to_hold_value(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "w.json"
            Wallet.generate(path, network=HSK_MAINNET)
            data = json.loads(path.read_text())
            self.assertIn("never send", data["warning"].lower())
            self.assertNotIn("TESTNET ONLY", data["warning"])


class TestDeploymentConfig(unittest.TestCase):
    """The config rules a mainnet deployment depends on."""

    def build(self, **env):
        import app as app_module
        from unittest import mock

        clean = {
            "HSK_NETWORK": None,
            "HSK_CHAIN_ID": None,
            "HSK_TOKEN_SECRET": None,
            "HSK_PRODUCTION": None,
            "HSK_STATEMENT": None,
            "HSK_NONCE_STORE": None,
        }
        with mock.patch.dict(os.environ, {k: v for k, v in env.items() if v}, clear=False):
            for key in clean:
                if env.get(key) is None:
                    os.environ.pop(key, None)
            return app_module.build_config()

    def test_defaults_to_mainnet(self):
        config = self.build(HSK_TOKEN_SECRET=TEST_SECRET)
        self.assertEqual(config["network"], HSK_MAINNET)
        self.assertEqual(config["chain_id"], 177)
        self.assertTrue(config["is_production"])

    def test_testnet_is_opt_in(self):
        config = self.build(HSK_NETWORK="testnet", HSK_TOKEN_SECRET=TEST_SECRET)
        self.assertEqual(config["network"], HSK_TESTNET)
        self.assertEqual(config["chain_id"], 133)
        self.assertFalse(config["is_production"])

    def test_chain_id_disagreeing_with_the_network_is_fatal(self):
        """A chain condition pointing at the wrong chain is the bug this prevents."""
        import app as app_module

        with self.assertRaises(app_module.ConfigError) as ctx:
            self.build(HSK_NETWORK="mainnet", HSK_CHAIN_ID="133", HSK_TOKEN_SECRET=TEST_SECRET)
        self.assertIn("133", str(ctx.exception))
        self.assertIn("177", str(ctx.exception))

    def test_matching_chain_id_is_accepted(self):
        config = self.build(HSK_NETWORK="testnet", HSK_CHAIN_ID="133", HSK_TOKEN_SECRET=TEST_SECRET)
        self.assertEqual(config["chain_id"], 133)

    def test_unknown_network_is_fatal(self):
        import app as app_module

        with self.assertRaises(app_module.ConfigError):
            self.build(HSK_NETWORK="goerli", HSK_TOKEN_SECRET=TEST_SECRET)

    def test_mainnet_refuses_to_boot_without_a_token_secret(self):
        """A generated secret would silently invalidate every session on restart."""
        with self.assertRaises(TokenError):
            self.build(HSK_NETWORK="mainnet")

    def test_testnet_tolerates_a_missing_secret_for_local_dev(self):
        config = self.build(HSK_NETWORK="testnet")
        self.assertTrue(config["token_secret"])
        self.assertFalse(config["is_production"])

    def test_production_flag_can_require_the_secret_on_testnet(self):
        with self.assertRaises(TokenError):
            self.build(HSK_NETWORK="testnet", HSK_PRODUCTION="true")

    def test_dev_mode_can_relax_the_secret_on_mainnet(self):
        config = self.build(HSK_NETWORK="mainnet", HSK_PRODUCTION="false")
        self.assertTrue(config["token_secret"])
        self.assertFalse(config["is_production"])

    def test_statement_defaults_to_the_network_wording(self):
        config = self.build(HSK_NETWORK="mainnet", HSK_TOKEN_SECRET=TEST_SECRET)
        self.assertIsNone(config["statement"])  # resolved per-network in create_app

    def test_session_list_is_hidden_by_default(self):
        config = self.build(HSK_TOKEN_SECRET=TEST_SECRET)
        self.assertFalse(config["expose_session_list"])


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
        self.assertEqual(
            body["authorizedBy"]["chainId"], self.app.config["HSK"]["chain_id"]
        )
        self.assertEqual(body["data"]["count"], 3)
        self.assertEqual(body["echo"], "ping")

    def test_full_flow_runs_on_the_configured_network(self):
        """The payload and the signed text must both name the selected network."""
        net = self.app.config["HSK"]["network"]
        res = self.client.post("/api/v1/challenge", json={"address": self.wallet.address})
        challenge = res.get_json()
        self.assertEqual(challenge["chainId"], net.chain_id)
        self.assertEqual(challenge["networkName"], net.name)
        self.assertIn(f"Chain ID: {net.chain_id}", challenge["message"])

        token = self.handshake()
        body = self.client.post(
            "/api/v1/data", json={}, headers={"Authorization": f"Bearer {token}"}
        ).get_json()
        self.assertEqual(body["network"]["chainId"], net.chain_id)
        self.assertEqual(body["network"]["name"], net.name)
        self.assertEqual(body["network"]["isTestnet"], net.is_testnet)
        self.assertEqual(body["data"]["dataset"], f"hsk-{net.slug}-blocks")
        for record in body["data"]["records"]:
            self.assertEqual(record["chainId"], net.chain_id)

    def other_network(self):
        """The HSK network this service is *not* pointed at."""
        net = self.app.config["HSK"]["network"]
        return HSK_TESTNET if net is HSK_MAINNET else HSK_MAINNET

    def test_challenge_is_pinned_to_the_configured_network(self):
        """A challenge must never name the chain this service is not on."""
        net = self.app.config["HSK"]["network"]
        res = self.client.post("/api/v1/challenge", json={"address": self.wallet.address})
        challenge = res.get_json()
        self.assertEqual(challenge["chainId"], net.chain_id)
        self.assertNotIn(self.other_network().name, challenge["message"])

    def test_a_signature_from_the_other_network_cannot_unlock_this_service(self):
        """End-to-end cross-network replay, through the HTTP layer.

        The message is built *and correctly signed* for the other network, so
        the chain/network conditions are the only thing rejecting it.
        """
        other = self.other_network()
        message = build_message(
            self.wallet.address,
            domain=self.app.config["HSK"]["domain"],
            uri=self.app.config["HSK"]["uri"],
            network=other,
        )
        self.assertEqual(message.chain_id, other.chain_id)
        signature = self.wallet.sign_message(message.as_message())
        res = self.client.post(
            "/api/v1/verify", json={**message.to_dict(), "signature": signature}
        )
        self.assertEqual(res.status_code, 403)
        body = res.get_json()
        self.assertIn("chain", body["failed"])
        self.assertIn("network", body["failed"])
        self.assertNotIn("token", body)

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

    def test_session_listing_requires_a_token(self):
        """It enumerates other users' addresses, so it must never be public."""
        res = self.client.get("/api/v1/session")
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.get_json()["error"], "missing_token")

    def test_session_listing_only_shows_your_own_session(self):
        token = self.handshake()
        res = self.client.get(
            "/api/v1/session", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertNotIn("sessions", body)  # full list is opt-in
        self.assertEqual(body["session"]["address"], self.wallet.address)

    def test_each_condition_appears_exactly_once_in_the_report(self):
        """A duplicated condition name would make `failed` ambiguous."""
        v, wallet = make_verifier()
        payload, _ = signed(v, wallet)
        names = [c.condition.value for c in v.verify(payload).checks]
        self.assertEqual(len(names), len(set(names)), f"duplicated conditions: {names}")

    def test_unknown_endpoint_404(self):
        self.assertEqual(self.client.get("/nope").status_code, 404)

    def test_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertEqual(body["chainId"], self.app.config["HSK"]["chain_id"])

    def test_index_reports_the_configured_network(self):
        body = self.client.get("/").get_json()
        net = self.app.config["HSK"]["network"]
        self.assertEqual(body["network"]["chain_id"], net.chain_id)
        self.assertEqual(body["network"]["name"], net.name)


class TestLiveNetworks(unittest.TestCase):
    """Talks to the real HSKChain RPCs. Each network is skipped if unreachable."""

    def probe_for(self, network):
        from hskauth import RpcError

        probe = ChainProbe(network)
        try:
            probe.assert_expected_chain()
        except RpcError as exc:
            self.skipTest(f"{network.name} RPC unreachable: {exc}")
        return probe

    def test_rpc_serves_the_expected_chain_id(self):
        """Guards the constants this whole deployment is built on."""
        for net in BOTH_NETWORKS:
            with self.subTest(network=net.name):
                self.assertEqual(self.probe_for(net).chain_id(), net.chain_id)

    def test_assert_expected_chain_catches_a_mispointed_probe(self):
        """Pointing mainnet at a testnet RPC must fail loudly, not silently."""
        from hskauth import RpcError

        mispointed = ChainProbe(HSK_MAINNET, session=_FakeSession(HSK_TESTNET))
        with self.assertRaises(RpcError):
            mispointed.assert_expected_chain()

    def test_probe_reports_an_address(self):
        for net in BOTH_NETWORKS:
            with self.subTest(network=net.name):
                probe = self.probe_for(net)
                wallet = Wallet.generate(network=net)
                info = probe.probe_address(wallet.address)
                self.assertEqual(info.address, wallet.address)
                self.assertFalse(info.active)  # a brand new key has no footprint
                self.assertFalse(info.is_contract)

    def test_network_status_flags_the_expected_network(self):
        for net in BOTH_NETWORKS:
            with self.subTest(network=net.name):
                status = self.probe_for(net).network_status()
                self.assertTrue(status["reachable"])
                self.assertTrue(status["isExpectedNetwork"])
                self.assertEqual(status["chainId"], net.chain_id)
                self.assertEqual(status["isTestnet"], net.is_testnet)


class _FakeSession:
    """Minimal requests.Session stand-in that answers eth_chainId from a network."""

    def __init__(self, network) -> None:
        self._network = network
        self.headers: dict = {}

    def post(self, url, json=None, timeout=None):
        outer = self._network

        class Response:
            status_code = 200

            @staticmethod
            def json():
                return {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": hex(outer.chain_id),
                }

        return Response()


if __name__ == "__main__":
    unittest.main(verbosity=2)
