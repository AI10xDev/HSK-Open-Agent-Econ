# HSKChain — Faucet + Signed-Message Gated API

A small Python project that does four things against an **HSKChain** network:

1. **Downloads and installs the official HSK testnet faucet.** *(testnet only)*
2. **Issues a conditioned message** pinned to the selected network and verifies
   the wallet's signature on it.
3. **Gates execution on every condition holding** — a signature unlocks the
   downstream work if and only if all checks pass.
4. **Serves a Flask API** whose `POST` data endpoint only returns data when the
   request carries the random token derived from that signed message.

The same code deploys to either public network. One variable decides which:

| `HSK_NETWORK` | Chain id | RPC                        | Explorer                      | Faucet |
| ------------- | -------- | -------------------------- | ----------------------------- | ------ |
| `mainnet` (default) | `177` | `https://mainnet.hsk.xyz` | `hashkey.blockscout.com`      | none   |
| `testnet`             | `133` | `https://testnet.hsk.xyz` | `testnet-explorer.hsk.xyz`    | yes    |

No private infrastructure is needed either way. Nothing in the codebase hardcodes
a chain id: the message, the verifier condition, the RPC probe and the consent
wording all read from the selected network.

---

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
echo "HSK_TOKEN_SECRET=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" >> .env

# 0. pick the network (mainnet is the default; add HSK_NETWORK=testnet for testnet)
echo "HSK_NETWORK=mainnet" >> .env

# 1. download + install the faucet -- TESTNET ONLY, skip on mainnet
HSK_NETWORK=testnet .venv/bin/python -m hskfaucet.installer

# 2. create a local keypair for that network
.venv/bin/python cli.py wallet --new

# 3. run the API
.venv/bin/python app.py          # http://127.0.0.1:5000
```

Then, in another shell, drive the whole handshake:

```bash
.venv/bin/python cli.py demo
```

```
1. POST /api/v1/challenge  (HSKChain Mainnet, address 0x745a...e8E)
   nonce=b2328889976639d3a8cd63bc2540f9a6 chainId=177 expires=2026-09-26T03:43:45Z
2. sign the conditioned message (EIP-191 personal_sign)
   signature=0x9ef5e0f1ed7bfa7b00...870650581b
3. POST /api/v1/verify
   verified by 0x745a955AdA130f8556f1359fC3830ef77C638e8E
   token=hsk1.eyJhZGRyIjoiMHg3NDVhOTU1QWRBMTMwZjg...
4. POST /api/v1/data  (the gated endpoint)
   -> HTTP 200
```

The demo warns if the local keypair's network does not match the one the running
service reports, which is the most common deployment mistake.

---

## Deploying to mainnet

```bash
HSK_NETWORK=mainnet \
HSK_TOKEN_SECRET=<48+ random bytes> \
HSK_DOMAIN=api.your-domain.tld \
HSK_NONCE_STORE=/var/lib/hsk/nonces.json \
HOST=0.0.0.0 gunicorn -w 1 -b 0.0.0.0:8000 app:app
```

What changes versus testnet:

* **Chain id `177`.** Verified live: `eth_chainId` on `mainnet.hsk.xyz` returns
  `0xb1`. The `chain` and `network` conditions reject anything signed for `133`.
* **No faucet.** HSKChain mainnet has none, and `FaucetClient` raises rather than
  run against a non-testnet network. The faucet tooling is inert on mainnet.
* **`HSK_TOKEN_SECRET` is mandatory.** On mainnet the service refuses to start
  without it, because a generated secret would invalidate every outstanding
  session on each restart. Set `HSK_PRODUCTION=false` to opt out locally.
* **`HSK_CHAIN_ID` must agree with `HSK_NETWORK`.** A mismatch is a startup error,
  not a warning, so a stale `HSK_CHAIN_ID=133` cannot leave you verifying against
  the wrong chain.
* **Set `HSK_ALLOWED_ADDRESSES`.** Mainnet means real accounts; the default
  "anyone with a valid signature" is rarely what you want in public.

Check what you actually deployed:

```bash
curl -s localhost:8000/api/v1/network | python3 -m json.tool
# {"name": "HSKChain Mainnet", "chainId": 177, "expectedChainId": 177,
#  "isExpectedNetwork": true, "isTestnet": false, "blockNumber": 28024448, ...}
```

`isExpectedNetwork` is the one to look at: it is `true` only when the live RPC
agrees with the network the service believes it is configured for.

---

## 1. The faucet

> **Testnet only.** HSKChain mainnet has no faucet — there is nothing to install
> and nothing to claim. `FaucetClient` raises rather than construct against a
> non-testnet network, and the installer always targets testnet regardless of
> `HSK_NETWORK`. A mainnet deployment skips this whole section.

### What it is

The faucet ships as a JavaScript single-page app, not a binary release, so
"installing" it means fetching the deployed bundle, recording its digests, and
extracting the API contract so it can be driven from a script.

```bash
.venv/bin/python -m hskfaucet.installer          # download + install
.venv/bin/python -m hskfaucet.installer --check  # verify what is on disk
```

Installed into `hskfaucet/vendor/`:

| artifact | sha256 (first 12) | size |
|---|---|---|
| `envs.js` | `9e0d04522fa8` | 225 B |
| `config.js` | `15f9fb5eeca9` | 285 B |
| `js/main.B5DtnSgu.js` | `10c40bf15502` | 310 749 B |

plus `install-manifest.json` with the pinned chain, endpoints and digests.
`--check` re-hashes everything and refuses to call it healthy if a byte moved.

### The API it exposes

Decoded from the bundle (`hskfaucet/client.py`):

| endpoint | purpose |
|---|---|
| `POST /api/faucet/drip` | `{token: <reCAPTCHA>, address: "0x.."}` → `{id}` |
| `GET /api/faucet/query?txId=` | job status → `{transaction: {...}}` |

Every call is HMAC-SHA256 signed (`hskfaucet/hmac_auth.py`) over:

```
x-date: <UTC timestamp>
<METHOD> <pathname><search> HTTP/1.1
```

emitted as `X-Timestamp` + `X-Signature: hmac username="faucet", ...`. The
`drip` call returns a job id; the transaction only appears once mined, so the
client polls `query` like the web UI does (20 attempts, 2 s apart).

Verified working against the real API:

```bash
.venv/bin/python cli.py faucet status
.venv/bin/python cli.py faucet query 00000000-0000-0000-0000-000000000000
# -> {"transaction": null, "message": "No transaction found with ID: ..."}
```

### Claiming testnet HSK

`POST /api/faucet/drip` requires a **reCAPTCHA v2 token**, which by design only
a human can obtain. This project accepts that token as an input and does not
attempt to solve, bypass, or work around the challenge:

```bash
# 1. open https://faucet.hsk.xyz/faucet, solve the challenge, copy the token
.venv/bin/python cli.py faucet claim 0xYourAddress --recaptcha-token <token> --wait
```

Without a token the client refuses up front rather than firing a doomed request:

```
error: the HSKChain faucet requires a reCAPTCHA v2 token. Solve the challenge
at https://faucet.hsk.xyz/faucet and pass the token as `recaptcha_token`
(the client does not bypass the challenge).
```

`cli.py balance` then shows the on-chain result:

```json
{ "nonce": 0, "balanceHSK": "0.000000", "isContract": false, "activeOnChain": false }
```

> **The faucet is not required for the auth flow.** Signing is EIP-191
> `personal_sign`, which is entirely off-chain and needs no gas. Funding is only
> needed if you want the account to be *active* on the chain — which is what the
> optional `HSK_REQUIRE_ONCHAIN` check looks for.

---

## 2 & 3. The conditioned message, and what gates on it

The message is SIWE-inspired (EIP-4361) and pinned to the selected network
(`hskauth/message.py`) — shown for testnet; a mainnet deployment renders
`HSKChain Mainnet` and `Chain ID: 177` instead:

```
localhost:5000 wants you to sign in with your HSKChain Testnet account:
0x745a955AdA130f8556f1359fC3830ef77C638e8E

Sign in to the HSKChain Testnet data API. This proves you control this
HSKChain Testnet account and authorises one API session. It moves no funds.

URI: /api/v1/data
Version: 1
Chain ID: 133
Nonce: b2328889976639d3a8cd63bc2540f9a6
Issued At: 2026-09-26T03:38:45Z
Expiration Time: 2026-09-26T03:43:45Z
Request ID: f8mo2OKlEBtqTtOo
```

The network name is a *field* on the message, not a string baked into the
template, so a mainnet deployment can never show a wallet the word "testnet",
and the text is always re-derivable from the structured fields during
verification.

`hskauth/verify.py` re-checks every condition. The gate is all-or-nothing — each
one must hold, and every result is reported so you can see exactly what failed.
Fourteen run by default; `onchain` is the opt-in fifteenth:

| condition | what it proves |
|---|---|
| `schema` | the text matches its own structured fields (no tampering) |
| `signature_format` | 65-byte `0x` hex |
| `signature_recovery` | EIP-191 recovery succeeded |
| `signer_matches` | recovered address == the address in the message |
| `chain` | `chainId` is the configured network (177 / 133) |
| `network` | `networkName` is the configured network |
| `domain` | message domain == this service |
| `uri` | message URI == the endpoint being unlocked |
| `statement` | user consented to the expected text |
| `address_allowed` | signer is on the allowlist (if configured) |
| `onchain` | signer has a footprint on that chain *(opt-in)* |
| `issued_at` | not future-dated or stale |
| `not_expired` | still inside the validity window |
| `nonce_issued` | nonce was handed out by this server |
| `nonce_unused` | nonce not already spent — **replay defence** |

Two design points worth calling out:

* **The nonce is consumed last, and only on success.** A malformed or mismatched
  submission never burns a nonce, so an attacker cannot lock a victim out by
  burning their nonce with garbage.
* **`chain` is what makes the deployment network-specific.** A valid signature
  over `chainId: 1` (Ethereum mainnet) is cryptographically fine but is rejected
  here, and so is a correctly signed HSKChain *testnet* message presented to a
  *mainnet* service. A signature is bound to exactly one chain's conditions,
  which is what makes this safe to point at either network.

### The on-chain check

`hskauth/onchain.py` is a read-only JSON-RPC client (only `eth_*` reads, it
cannot spend). It confirms the endpoint really serves the configured chain — so
a signature condition bound to mainnet cannot be satisfied against a
mis-pointed or malicious RPC — and reports an address' on-chain footprint.

```bash
$ curl -s localhost:5000/api/v1/network
{"name":"HSKChain Mainnet","chainId":177,"expectedChainId":177,
 "isExpectedNetwork":true,"isTestnet":false,"blockNumber":28024448,
 "reachable":true, ...}
```

Set `HSK_REQUIRE_ONCHAIN=true` to additionally demand that the signer is an
account with a real footprint on that chain (non-zero nonce or balance, or
deployed code) — on testnet effectively "the faucet funded it", on mainnet "this
account is not brand new". It is **off by default** so a brand-new key still
works, and an RPC outage is non-fatal by default so a flaky node cannot deny an
otherwise valid signature (`HSK_ONCHAIN_FATAL=true` to change that).

---

## 4. The Flask API

```
POST /api/v1/challenge   → issue a conditioned message + fresh nonce
POST /api/v1/verify      → verify the signature; mint a token only if valid
POST /api/v1/data        → the protected endpoint (Authorization: Bearer <token>)
GET  /api/v1/network     → live status of the configured network
GET  /api/v1/session     → your own session (requires the bearer token)
DELETE /api/v1/session   → revoke your own token (requires the bearer token)
GET  /health, GET /
```

### The random token

The brief was "a random token (being the signed message)". Handing back the raw
65-byte signature would be awkward and would let it be replayed verbatim at any
endpoint, so instead the token is a **keyed derivative of the verified message**
(`hskauth/token.py`):

```
hsk1.<b64url(claims)>.<b64url(HMAC-SHA256(server_secret, b64url(claims)))>

claims = {sid, addr, cid, nonce, rid, sig, iat, exp}
```

* **Opaque / random-looking** — the payload carries a 192-bit CSPRNG `sid`.
* **Bound to the signed message** — `addr`, `cid`, `nonce`, `rid` and a hash of
  the signature are inside and MAC'd, so it is only obtainable by completing a
  valid signature flow *for that message*.
* **Tamper-evident** — flipping any byte breaks the MAC, compared in constant
  time.
* **Self-expiring** — `exp` is inside the payload.
* **Revocable** — the server keeps the session, so a token can be burned early.

### Gate in action

No token:

```console
$ curl -i -X POST localhost:5000/api/v1/data -d '{}'
HTTP/1.1 401 UNAUTHORIZED
WWW-Authenticate: Bearer

{"error":"missing_token",
 "message":"Send the token from POST /api/v1/data as 'Authorization: Bearer <token>'.",
 "howToGetOne":["POST /api/v1/challenge",
                "sign the returned message with your HSKChain Mainnet account",
                "POST /api/v1/verify"]}
```

Wrong signer — 403, and the payload shows *which* condition broke:

```console
$ curl -X POST localhost:5000/api/v1/verify -d @forged.json
HTTP/1.1 403 FORBIDDEN

{"error":"conditions_not_met","valid":false,
 "failed":["signer_matches"],
 "checks":[{"condition":"signer_matches","passed":false,
            "detail":"signature recovers to 0xAAAA..., message claims 0x745a..."}],
 ...}
```

Replay of a good signature:

```json
{"error":"conditions_not_met","valid":false,
 "failed":["nonce_unused"],"skipped":[],
 "checks":[...,{"condition":"nonce_unused","passed":false,
                "detail":"nonce b232... was already used (replay attempt)"}]}
```

`failed` lists conditions that were *evaluated and did not hold*; `skipped`
lists ones never reached because something earlier already failed. So a
`signer_matches` failure reports `failed: ["signer_matches"]` and
`skipped: ["nonce_unused"]` — distinct from a genuine replay, where
`nonce_unused` really was evaluated and really did fail.

With a valid token — data returned:

```json
{"granted":true,
 "reason":"signed conditioned message verified against HSKChain Mainnet",
 "authorizedBy":{"address":"0x745a...e8E","chainId":177,
                 "sessionId":"aU4U2o37Df4HYD1pGhQwy3PCYmVwwIgr",
                 "signature":"6981d54fcb6d5fd9"},
 "network":{"name":"HSKChain Mainnet","chainId":177,"isTestnet":false},
 "data":{"dataset":"hsk-mainnet-blocks","count":3,"head":28024448,
         "records":[{"id":"blk-1","height":28024446,"chainId":177, ...}]},
 "echo":"hello"}
```

`head` and the record heights are the real chain head when the RPC answers
(cached for 15s, and never allowed to block a request for more than 3s).

### Verified behaviour

Every one of these was exercised against a running instance:

| attempt | result |
|---|---|
| valid signature → token → data | `200` |
| signature from a different key | `403` `failed: ["signer_matches"]`, no token |
| valid signature for `chainId: 1` | `403` `failed: ["chain"]` |
| valid **testnet** signature at the **mainnet** service | `403` `failed: ["chain", "network", ...]` |
| valid signature at a service on the *other* network | `403`, no token |
| replaying a good signature | `403` `failed: ["nonce_unused"]` |
| `POST /api/v1/data` with no token | `401` `missing_token` |
| token with three characters flipped | `401` `invalid_token: invalid token signature` |
| token minted with a different server secret | `401` |
| `GET /api/v1/session` without a token | `401` |
| `DELETE /api/v1/session` without a token | `401` |
| revoking another session's id | `403` `forbidden_session` |
| revoking your own token, then reusing it | `401` `token revoked` |
| faucet client pointed at mainnet | raises `FaucetError` |
| reusing a mainnet keypair on testnet | `WalletError` |

---

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -t . -v
```

**102 tests, all passing.** They cover the faucet's HMAC canonicalisation and
install integrity, the network registry (mainnet/testnet params, lookup, and
that the two never collide), every condition (each with a test proving it
actually blocks), cross-network rejection in both directions, token
forgery/tamper/expiry/revocation, the wallet's network binding, the deployment
config rules (mandatory secret, chain-id mismatch), the full HTTP handshake, and
tests against the **live** mainnet and testnet RPCs.

---

## Layout

```
hskfaucet/          networks + the testnet-only faucet
  network.py          mainnet (177) + testnet (133) parameters, env resolution
  hmac_auth.py        HMAC-SHA256 request signing
  client.py           drip() / query() with polling; refuses non-testnet
  installer.py        download + install + verify
  vendor/             installed bundle + install-manifest.json
hskauth/             conditioned-message auth
  message.py          the conditioned message (SIWE-style, network-derived)
  wallet.py           keypair + EIP-191 sign / recover, bound to a network
  verify.py           the 15 conditions
  token.py            the random signed-message token
  onchain.py          read-only JSON-RPC probe
app.py              the Flask API
cli.py              faucet / wallet / sign / demo
tests/test_flow.py  102 tests
```

---

## Security notes

* `HSK_TOKEN_SECRET` is **required** on mainnet and whenever `HSK_PRODUCTION=true`
  — the service refuses to start without it. Without it a random secret is
  generated at boot and every restart invalidates outstanding tokens, which is
  fine for local testnet work and useless in production.
* `HSK_CHAIN_ID` must match `HSK_NETWORK` or the service will not start. A stale
  `HSK_CHAIN_ID=133` left over from a testnet setup is the failure this catches.
* The faucet is **testnet-only by construction**: `FaucetClient` raises against a
  non-testnet network, and mainnet carries no `faucet_url`. There is no code path
  from this project that can request real HSK.
* `wallet.json` holds a private key at mode `0600`. It is a throwaway key for
  proving address control and must never hold value. It records the network it
  was made for and refuses to load against a different one, so a testnet key
  cannot start authorising mainnet sessions.
* Without `HSK_NONCE_STORE`, nonces live in RAM: restarts lose them (fail-closed)
  and gunicorn **must** run a single worker. Set `HSK_NONCE_STORE=./var/nonces.json`
  for multiple workers.
* Set `HSK_ALLOWED_ADDRESSES` to restrict which accounts may obtain tokens —
  strongly recommended on a public mainnet deployment.
* `GET /api/v1/session` requires a bearer token and returns only your own
  session. The instance-wide list stays hidden unless
  `HSK_EXPOSE_SESSION_LIST=true`, since it contains other users' addresses.
* `HSK_DOMAIN` is part of the signed conditions — changing it invalidates
  in-flight challenges, so don't treat it as a mutable setting.
* There is no rate limiting on `/challenge` or `/verify`. Put a reverse proxy in
  front of a public deployment.
