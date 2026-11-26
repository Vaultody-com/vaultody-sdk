# Vaultody SDK

The official Vaultody SDKs for Node.js, Python and PHP, in one repository, with the test vectors every
language must agree on.

**This version has the foundation, the transports and the API methods of all three languages.** The
foundation is the verification module (signed responses, request signing, webhook signatures, addresses
against the vault xpub), the pieces every client is built from (typed errors, retry decisions, paging, the
request target, network error classification, the vault xpub pin model), the shared vectors that pin them,
and the check that every documented API operation has a method. The clients (`Vaultody` in Node.js and PHP,
`Vaultody` and `AsyncVaultody` in Python) sign, verify, pin vault xpubs, check addresses, retry and page.
The first release candidate is `0.9.0-rc.1`: `npm install @vaultody-com/sdk@next`, `pip install --pre vaultody-sdk`,
`composer require "vaultody/sdk:^0.9@RC"`. Until the production root key is embedded, a release candidate accepts
unsigned responses and marks vault pins unverified (trust on first use); see [docs/RELEASING.md](docs/RELEASING.md).

The API methods: one per documented operation of API version `2026-03-20` (32: the 31 published and
`listApiKeySigningKeys`, still pending in the docs), grouped and named as the API reference groups and names
them. The arguments are the API's own field names, path, query and body together, checked before anything
is sent against the operation's documented fields, types and values for the pinned API version; answers are
read leniently (an unknown field or value passes through). The methods are the only way in: the low-level
request and paging calls are internal.

- **Node.js**: `vaultody.<group>.<operationId>(params, options)`, such as
  `vaultody.transactions.createSingleTransfer({ ... })`. One item is a promise of `{ item, meta }`; a list is
  a promise of its first page that is also an async iterable over every item. JSDoc typedefs for every
  params object and result. `null` is refused.
- **Python**: the same methods in snake_case on `Vaultody` and `AsyncVaultody`, with keyword arguments
  (`client.transactions.create_single_transfer(vaultId=..., ...)`). One item is an `Item`; a list is
  `Pages` (`AsyncPages`), fetched as it is iterated. `TypedDict` models in `vaultody_sdk.models` and
  `py.typed`; CI type-checks the public API with `mypy --strict`. `None` leaves an optional argument out.
- **PHP**: `$vaultody-><group>-><operationId>($params, $options)`. Answers are typed readonly models
  (`Vaultody\Sdk\Model\*`, the object as it came in `raw`); a list is a `Model\Page` that iterates every
  item. A `null` optional param is left out.

## Layout

| Directory | Package | Runtime | What |
|---|---|---|---|
| [`node/packages/verify/`](node/packages/verify/README.md) | `@vaultody-com/verify` | Node.js 22+, no dependencies | Verification only, no network or storage: signed responses, request signing (HMAC v2 and key pairs), P1363 → DER, webhook signatures, addresses against the vault xpub, request-signing key pairs and the signing-keys answer |
| [`node/packages/sdk/`](node/packages/sdk/README.md) | `@vaultody-com/sdk` | Node.js 22+, depends on `@vaultody-com/verify` | The SDK: the client, its transport, a method for each of the 32 documented operations, and the `vaultody` command line: `npx @vaultody-com/sdk keys ...` for request-signing keys, `npx @vaultody-com/sdk vault-keys accept` to re-pin a vault in the shared pin file (Python and PHP users run it with npx too) |
| [`python/vaultody-verify/`](python/vaultody-verify/README.md) | `vaultody-verify` (import `vaultody_verify`) | Python 3.10+, `cryptography` | The verification module, as in Node, with the address check against the vault xpub |
| [`python/vaultody-sdk/`](python/vaultody-sdk/README.md) | `vaultody-sdk` (import `vaultody_sdk`) | Python 3.10+, `vaultody-verify`, `httpx` | The SDK: `Vaultody` and `AsyncVaultody` over one core without I/O, each with a method for each of the 32 documented operations |
| [`php/`](php/README.md) | `vaultody/sdk` (namespace `Vaultody\Sdk\`, verification in `Vaultody\Sdk\Verify\`) | PHP 8.2+, built-in extensions only (curl, json, openssl, sodium) | The verification module (with the address check against the vault xpub), the transport, and a method for each of the 32 documented operations |
| `test-vectors/` | | | The shared vectors (below), and their generators in `test-vectors/tools/` |
| [`conformance/mock-gateway/`](conformance/mock-gateway/README.md) | | Node.js 22+, no dependencies | A mock API gateway every SDK's pipeline tests run against: its own signature checks, replay protection, signed answers, faults |
| [`conformance/interop/`](conformance/interop/run.mjs) | | Node.js 22+, Python 3.10+, PHP 8.2+ | The pin file across languages: written by each SDK, read by the other two; identical bytes; concurrent writers in all three languages on one file (CI job `vault-keys-interop`) |
| [`conformance/live/`](conformance/live/README.md) | | Node.js 22+, Python 3.10+, PHP 8.2+ (or Docker) | The same cases through all four clients against a real, non-production Vaultody API (`run.sh`): reads, safe writes, paging, typed results, address statuses, refusals before sending. Run by hand, never in this repository's CI |
| `contract/` | | | The published OpenAPI document and what the SDKs need beside it (below) |
| `scripts/` | | | `coverage.mjs`, `check-vectors.mjs`, `secret-scan.sh`, `version.mjs` (the one version: `check`, `set`), `release/` (the release guard, packing and package checks, the PHP mirror push) |

One version number for every package: [`VERSION`](VERSION), set with `node scripts/version.mjs set <version>`
(Python writes a release candidate the PEP 440 way, `0.9.0rc1`). Releases: [`docs/RELEASING.md`](docs/RELEASING.md).
Every SDK pins the API version it is written
for (`x-api-version: 2026-03-20`, `info.version` of `contract/openapi.json`) in one constant: Node
`API_VERSION` (`@vaultody-com/sdk`), Python `vaultody_sdk.API_VERSION`, PHP `Vaultody\Sdk\Version::API_VERSION`.

## One behaviour in every language

The SDKs share more than the vectors below ([`docs/vault-keys-file.md`](docs/vault-keys-file.md)):

- **The pin file** (`VAULTODY_VAULT_KEYS_FILE`): one layout, `vaultody vault keys v1`, with the vault xpub pins
  and the response-signature latch per API origin; the same refusals, the same bytes written, the same lock
  file, so clients in different languages can share it.
- **Security events**: the same seven types with the same fields
  (`test-vectors/security-events-v1.json`), among them `unsigned_response_accepted` `{ type, origin, operationId }`,
  once per client with one warning, when a client accepts its first unsigned response (`when-present` mode,
  before the latch).
- **The response-signature mode** (`test-vectors/response-mode-v1.json`): strict (`required`) whenever
  response-signing roots are configured (the `roots` option, or a stable release that embeds the root), a
  `when-present` given then ignored with one warning; the latch set by the first answer that carries any signature
  header, verified or not (`rootId` `null` when it did not verify); one signed read before the first write of a client
  with roots whose origin is not latched yet. The build defaults `DEFAULT_RESPONSE_SIGNATURE` and
  `ADDRESS_PATHS_PUBLIC` are the same in every language, and a stable release needs them at `required` and `true`
  (`scripts/release/guard.mjs`).
- **Address checks** `{ vaultId, address, status }` on every answer that returns vault addresses, and a vault list
  that lists a vault under the other type refused (`ApiError`). With `requireAddressPaths` on, a
  `generateDepositAddress` answer without its derivation path for a vault with MPC keys is refused (`path_missing`).
- **Per-vault pin results** on every `listVaults` page: `{ vaultId, status, outcome }` (Node `meta.vaultKeys`,
  Python `meta.vault_keys`, PHP `$page->meta->vaultKeys`).
- **Pins given in configuration** (Node and PHP `pinnedVaultKeys`, Python `pinned_vault_keys`): a list of
  `{ vaultId, type, keys: { ECDSA, EDDSA } }` that counts as verified, is still compared with every vault list (any
  difference is the alarm), is never written to the store and takes the place of the stored pin of its vault.
- **Refused until re-pinned**: an xpub changed or gone, a key a pinned vault did not have, a vault type change
  (`VaultKeyChangedError`). The client confirms the change with Vaultody and re-pins the vault:
  `npx @vaultody-com/sdk vault-keys accept --vault-id <vaultId>` shows the old and new fingerprints and replaces the pin
  with `--yes --expect <the fingerprints it showed>`.
- **One nonce per write**: every retry of a write keeps its `x-api-nonce` and body (re-signed with a fresh
  timestamp, or resent as it was), so the gateway's idempotency per API key and nonce sees one
  operation; a read signed again gets a new nonce
  (`retry-v1.json`, `nonce`). The one exception: the single immediate retry after `address_derivation_conflict`
  or `vault_accounts_creation_failed`, where nothing was executed, gets a new nonce and the same body.
- **The same error classes**: every one a `VaultodyError`, exported where `ApiError` is, with the same fields:
  `ParameterError` `code` and `param`, `WebhookSignatureError` `reason`, `WebhookPayloadError`
  (`envelope-errors-v1.json`, `sdkErrors`).

## Test vectors

Every language must give every case its expected result. A set gets a Node, a Python and a PHP runner when
it is added (`scripts/check-vectors.mjs` fails otherwise); `PENDING` in that script lists the runners still
being ported, and must shrink to zero. The Python sets that describe what a client does run through both
`Vaultody` and `AsyncVaultody` (`python/vaultody-sdk/tests/test_client_*`).

| File | Cases | What it pins | Source |
|---|---|---|---|
| `v1.json` | 76 | Signed API responses: certificate, signature, request binding, every refusal (a certificate valid for more than 3600 seconds among them) | the API gateway's own vector file, copied |
| `request-keypair-v1.json` | 35 (+6 public keys) | The string signed for `x-api-keypair-sign` (the tag, the `x-api-key`, then the HMAC v2 fields), fingerprints | the API gateway's own vector file, copied |
| `keypair-challenge-v1.json` | 10 (+9 formats) | The proof of possession at key registration | the API gateway's own vector file, copied |
| `request-hmac-v2.json` | 19 | `x-api-sign` version 2: the signed string and HMAC; the API secrets refused | `generate-gateway-vectors.js`, from the API gateway's signing code |
| `request-full-v1.json` | 8 | Every authentication header of a request, with and without a key pair | `generate-gateway-vectors.js`; the gateway's own checks accept each case |
| `signing-keys-v1.json` | 11 | Signed answers of `GET /api-keys/current/signing-keys`: active, not listed, refused, tampered | `generate-gateway-vectors.js`, signed with the gateway's response-signing code and checked with its reference verifier |
| `vault-key-pins-v1.json` | 28 (32 steps, +16 address checks) | Vault xpub pins: verified or unverified (trust on first use), upgrade, alarm (a new key and a type change refused), not verifiable, pins given in configuration; the address check, with `requireAddressPaths` (`path_missing`) | `generate-gateway-vectors.js`, signed with the gateway's response-signing code and checked with its reference verifier |
| `address-v1.json` | 511 (+13 refused) | Addresses derived from a vault xpub at m/account/isChange/index, 17 chains, every network and address format | the vault service's own derivation code, copied (it names the path flag `change`; the API field is `isChange`) |
| `webhook-v1.json` | 18 | `X-Signature` on webhook deliveries: case, rotation, tampering, format | `generate-sdk-vectors.js`, with the algorithm Vaultody signs webhook deliveries with |
| `path-encoding-v1.json` | 18 | Path and query parameters → the exact request target | `generate-sdk-vectors.js` |
| `p1363-der-v1.json` | 18 | P-256 signatures from IEEE P1363 r‖s to DER; a signer's 64-byte output is P1363 even when it starts like DER | `generate-sdk-vectors.js`, checked with node:crypto and openssl |
| `envelope-errors-v1.json` | 87 (+10 `sdkErrors`) | Response envelope → item, page or typed error, for every catalogued error code and `api_nonce_reused`; `sdkErrors`: the errors raised with no answer, their classes and fields | `generate-sdk-vectors.js` from `contract/errors.json` |
| `pagination-v1.json` | 17 | Pages → requests made, items yielded, why it stopped (cursor and offset) | `generate-sdk-vectors.js` from `contract/overlay.json` |
| `retry-v1.json` | 55 | One attempt's outcome → retry (re-signed or resent, and whether the nonce is kept), return, fail, or outcome unknown | `generate-sdk-vectors.js` |
| `transport-errors-v1.json` | 23 Node, 15 Python, 9 PHP | A network error → whether the request may have been sent | `generate-sdk-vectors.js` |
| `security-events-v1.json` | 7 events, 2 result entries | The security events' names and exact fields, and the entries of `addressChecks` and `vaultKeys` | `generate-sdk-vectors.js` |
| `vault-keys-file-v1.json` | 11 valid, 55 refused, 8 file cases, 6 canonical | The pin file every SDK shares ([`docs/vault-keys-file.md`](docs/vault-keys-file.md)): what parses, what is refused and with which code, file modes and links, the exact bytes a writer writes | `generate-sdk-vectors.js` (schema: [`docs/vault-keys-file-v1.schema.json`](docs/vault-keys-file-v1.schema.json)) |
| `response-mode-v1.json` | 14 configurations, 17 answers | The response-signature mode in force (roots configured, a release candidate or a stable build, the option) and what one answer does: accepted, refused, and the latch set on any signed answer | `generate-sdk-vectors.js`, the answers are `v1.json` cases |

Every key, secret and signature in these files is TEST-ONLY and public on purpose.

To refresh them:

```sh
# the gateway's sets and contract/errors.json, from a checkout of the API gateway (Vaultody internal, read only)
node test-vectors/tools/generate-gateway-vectors.js --gateway <gateway checkout>
# the SDK's own sets; CI runs this with --check
node test-vectors/tools/generate-sdk-vectors.js
```

The three gateway files and `address-v1.json` are copied from the server side's test fixtures when they
change (`v1.json` ← `response-signing-v1.json`), with only their `regeneration` and `source` text reworded so
that it names no internal repository or code; the cases are not touched.

## Contract and coverage

`contract/` holds the source of truth for what the SDKs must cover, copied and recorded with its commit and
SHA-256 in `contract/source.json` (which also says what was removed from a copy):

- `openapi.json` and `published.json`: the OpenAPI document of the published API reference
  (developers.vaultody.com), API version 2026-03-20, 31 operations, with the internal routing extension
  `x-route-key` removed;
- `pending/`: documented operations not published on production yet (`listApiKeySigningKeys`);
- `overlay.json`: per operation, what the SDKs need that the document does not say (retry class, cursor
  field);
- `errors.json`: every error code with its status, documented and the gateway's own (generated).

`node scripts/coverage.mjs --surface node.json --surface python.json --surface php.json` compares each
SDK's surface (the methods its client exposes, found by reflection, and its operation table) with the 32
operations, and CI fails on any difference: a missing, extra or misplaced method, a wrong method, path or
parameter, a pinned API version that differs from the contract, or a contract copy that no longer matches
`source.json`. Every client must have every method; there is no allow-list. A pending docs file lists no
parameters, so the script declares them (`PENDING_PARAMS`: `listApiKeySigningKeys` takes none) and holds
every SDK's operation table to that.

## Tests

```sh
cd node && npm ci && npm test
cd python/vaultody-verify && python3 -m venv .venv && .venv/bin/pip install -e '.[requests]' -e ../vaultody-sdk pytest && .venv/bin/pytest -q
cd python/vaultody-sdk && ../vaultody-verify/.venv/bin/pytest -q
php php/tests/run.php
python3 -m venv /tmp/types && /tmp/types/bin/pip install ./python/vaultody-verify ./python/vaultody-sdk mypy==2.4.1 && /tmp/types/bin/mypy --strict python/vaultody-sdk/tests/typecheck/
node --test scripts/coverage.test.mjs scripts/version.test.mjs scripts/release/guard.test.mjs && node scripts/check-vectors.mjs
VAULTODY_INTEROP_PYTHON=/tmp/types/bin/python node conformance/interop/run.mjs   # needs php; or VAULTODY_INTEROP_PHP=docker:php:8.4-cli
scripts/secret-scan.sh    # gitleaks over the whole history, in docker
node scripts/release/guard.mjs --report   # what a release of this commit would refuse
scripts/release/pack.sh dist && node scripts/release/check-packages.mjs dist   # every package, as a release builds it (needs composer)
```

CI (`.github/workflows/test.yml`) runs Node 22, 24 and 26, Python 3.10 to 3.15 and PHP 8.2 to 8.5, the
Python type check (`mypy --strict` on 3.10 and 3.15), the pin file across the three languages
(`node conformance/interop/run.mjs`), the coverage check and the vector checks; `secret-scan.yml` runs the history scan;
`release-dry-run.yml` builds and checks every package as a release would. `release.yml` publishes, by hand
([`docs/RELEASING.md`](docs/RELEASING.md)). Security reports: [`SECURITY.md`](SECURITY.md).

## Licence

Apache License 2.0 ([`LICENSE`](LICENSE)); every package ships the same file.
