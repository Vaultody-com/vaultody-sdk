# @vaultody-com/sdk

The official Vaultody SDK for Node.js. Node.js 22+, built-in `fetch` and `node:crypto`, no dependencies outside
this repository.

**This version has the transport and a method for every documented operation** of API version
`2026-03-20`: 32 methods in the groups of the API reference (below). Release candidate: `npm install @vaultody-com/sdk@next`.

```js
const { Vaultody, fileSigner } = require('@vaultody-com/sdk');

const vaultody = new Vaultody({
    apiKey: process.env.VAULTODY_API_KEY,
    apiSecret: process.env.VAULTODY_API_SECRET,
    passphrase: process.env.VAULTODY_PASSPHRASE,
    signer: fileSigner('private.pem'),          // optional: a request-signing key pair
});

const { item, meta } = await vaultody.assetsAddresses.generateDepositAddress({
    vaultId, blockchain: 'bitcoin', network: 'mainnet', vaultAccountId, label: 'Alice',
});
meta.signature;      // 'verified' or 'absent' (response not signed yet)
meta.addressChecks;  // [{ vaultId, address, status: 'verified' | 'unverified' | 'not_verifiable' }]

for await (const vault of vaultody.vaults.listVaults({ networkType: 'main' })) { /* every vault, page by page */ }
```

In an ES module, `import { Vaultody, fileSigner } from '@vaultody-com/sdk'`: every export (the client, every error class,
the stores, the signers, the webhook helpers) is also a named ESM export.

The package also ships the `vaultody` command line for request-signing keys (`npx @vaultody-com/sdk keys ...`) and for
re-pinning a vault (`npx @vaultody-com/sdk vault-keys accept ...`)
([below](#request-signing-keys)).

## API methods

`vaultody.<group>.<operationId>(params, options)`: the method names are the operationIds of the API reference,
grouped as its pages are.

- **`params`**: one flat object with the operation's path, query and body fields together; the SDK puts each
  where it belongs. Before anything is sent, every field is checked against the API reference: required fields
  present, the documented type (amounts are strings), one of the documented values where it lists them, page
  sizes from 1 to 50. A field the operation does not have is refused at any depth, and `null` is refused. A
  refusal is a `ParameterError` with `code` (`missing_param`, `invalid_param`, `unknown_param`) and `param`
  (such as `recipients[0].amount`). Values are never converted.
- **`options`**: `context` (returned unchanged in `meta.context`) and `signal` (an `AbortSignal`).
- **One item**: a promise of `{ item, meta }`. `item` is `data.item` of the answer.
- **A list**: a promise of its first page (`items`, `hasMore`, `meta`, `nextPage()`, `autoPaging()`) that is
  also an async iterable over every item, page after page. The first page is asked for once either way.
- **Models**: every params object and result is described as a JSDoc typedef in `src/api/` (`ListVaultsParams`,
  `ListVaultsResult`, ...), which editors show. `test/contract.test.js` holds them to the published OpenAPI
  document. Response fields are all optional (the document marks none required), and fields the API adds later
  pass through.
- **Writes and reads**: every write (the transfers, `generateDepositAddress`, `createVaultAccount`, ...) follows
  the write retry rules below; `validateAddress`, `validateUtxoTransfer` and `estimateTransactionFeeByAssetId`
  change nothing and are retried like reads.
- **The methods are the only way in.** The client has no call by operationId: everything goes through the
  check above. (The low-level call the methods are built on is internal to the package, for its own tests.)

### vaults

| Method | Endpoint | Example |
|---|---|---|
| `listVaults` | `GET /vaults/{networkType}` (list) | `for await (const vault of vaultody.vaults.listVaults({ networkType: 'main' })) {}` |
| `listVaultsByAssetId` | `GET /assets/{assetId}/{blockchain}/vaults/{networkType}` | `await vaultody.vaults.listVaultsByAssetId({ assetId, blockchain: 'ethereum', networkType: 'main' })` |
| `listAssetsByVault` | `GET /vaults/{vaultId}/assets` | `await vaultody.vaults.listAssetsByVault({ vaultId })` |
| `listTransactionsByVault` | `GET /vaults/{vaultId}/transactions` (list) | `await vaultody.vaults.listTransactionsByVault({ vaultId, limit: 10 })` |

### vaultAccounts

| Method | Endpoint | Example |
|---|---|---|
| `createVaultAccount` | `POST /vaults/{vaultId}/vault-account` (write) | `await vaultody.vaultAccounts.createVaultAccount({ vaultId, name: 'User Alice', color: '#00C7E6', isHiddenInDashboard: false })` |
| `listVaultAccounts` | `GET /vaults/{vaultId}/vault-accounts/details` (list) | `await vaultody.vaultAccounts.listVaultAccounts({ vaultId, isHideEmpty: true })` |
| `getVaultAccountById` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/details` | `await vaultody.vaultAccounts.getVaultAccountById({ vaultId, vaultAccountId })` |
| `updateVaultAccount` | `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit` (write) | `await vaultody.vaultAccounts.updateVaultAccount({ vaultId, vaultAccountId, name: 'User Alice' })` |
| `addAssetToVaultAccount` | `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset` (write, address checked) | `await vaultody.vaultAccounts.addAssetToVaultAccount({ vaultId, vaultAccountId, assetId, label: 'Alice deposit' })` |
| `listAssetsByVaultAccountId` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets` (list) | `await vaultody.vaultAccounts.listAssetsByVaultAccountId({ vaultId, vaultAccountId })` |
| `listTransactionsByVaultAccount` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions` (list) | `await vaultody.vaultAccounts.listTransactionsByVaultAccount({ vaultId, vaultAccountId })` |

### assetsAddresses

| Method | Endpoint | Example |
|---|---|---|
| `generateDepositAddress` | `POST /vaults/{vaultId}/{blockchain}/{network}/addresses` (write, address checked) | `await vaultody.assetsAddresses.generateDepositAddress({ vaultId, blockchain: 'ethereum', network: 'mainnet', vaultAccountId, label: 'Alice' })` |
| `getAddressBalance` | `GET /vaults/{vaultId}/addresses/{address}/balance` (list, one page at a time) | `await vaultody.assetsAddresses.getAddressBalance({ vaultId, address, blockchain: 'ethereum' })` |
| `listAddressesByVaultAccountId` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses` (list, addresses checked) | `await vaultody.assetsAddresses.listAddressesByVaultAccountId({ vaultId, vaultAccountId, blockchain: 'bitcoin' })` |
| `listSupportedAssets` | `GET /supported-assets` (list) | `await vaultody.assetsAddresses.listSupportedAssets({ blockchain: 'ethereum', networkType: 'main' })` |
| `validateAddress` | `POST /info/{blockchain}/{network}/addresses/validate` | `await vaultody.assetsAddresses.validateAddress({ blockchain: 'bitcoin', network: 'mainnet', address })` |
| `encodeXrpAddress` | `GET /utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}` | `await vaultody.assetsAddresses.encodeXrpAddress({ network: 'mainnet', classicAddress, addressTag: '123' })` |
| `decodeXrpAddress` | `GET /utils/xrp/{network}/addresses/decode/{xAddress}` | `await vaultody.assetsAddresses.decodeXrpAddress({ network: 'mainnet', xAddress })` |
| `tronResourceOverview` | `GET /vaults/{vaultId}/{blockchain}/{network}/{address}/overview` | `await vaultody.assetsAddresses.tronResourceOverview({ vaultId, blockchain: 'tron', network: 'mainnet', address })` |
| `tronResourceManagement` | `POST /vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource` (write) | `await vaultody.assetsAddresses.tronResourceManagement({ vaultId, blockchain: 'tron', network: 'mainnet', fromAddress, resource: 'energy', type: 'freeze', amount: '3' })` |

### transactions

| Method | Endpoint | Example |
|---|---|---|
| `createSingleTransfer` | `POST /vaults/{vaultId}/transaction-requests/single-transfer` (write) | `await vaultody.transactions.createSingleTransfer({ vaultId, vaultAccountId, assetId, fromAddress, toAddress, amount: '0.001', feePriority: 'standard', note: 'Order 1842' })` |
| `createMultipleTransfer` | `POST /vaults/{vaultId}/transaction-requests/multiple-transfer` (write) | `await vaultody.transactions.createMultipleTransfer({ vaultId, vaultAccountId, assetId, feePriority: 'standard', prepareStrategy: 'optimize-size', recipients: [{ address, amount: '0.001' }], note: 'Payouts' })` |
| `createUtxoTransfer` | `POST /vaults/{vaultId}/transaction-requests/utxo-transfer` (write) | `await vaultody.transactions.createUtxoTransfer({ vaultId, assetId, feePriority: 'standard', senders: [{ utxoId }], recipients: [{ address, amount: '0.001' }], note: 'Consolidate' })` |
| `validateUtxoTransfer` | `POST /vaults/{vaultId}/transaction-requests/utxo-transfer/validate` | `await vaultody.transactions.validateUtxoTransfer({ vaultId, assetId, feePriority: 'standard', senders: [{ utxoId }], recipients: [{ address, amount: '0.001' }] })` |
| `createBatchTransactionRequest` | `POST /vaults/{vaultId}/transaction-requests/batch` (write) | `await vaultody.transactions.createBatchTransactionRequest({ vaultId, fromAddress, feePayer: { address: payer, assetId }, recipients: [{ address, amount: '0.001', assetId }], note: 'Batch' })` |
| `gasSponsorshipTransfer` | `POST /vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer` (write) | `await vaultody.transactions.gasSponsorshipTransfer({ vaultId, vaultAccountId, assetId, fromAddress, toAddress, feePayer: payer, amount: '5', note: 'Sponsored' })` |
| `createTronContractInteractionRequest` | `POST /vaults/{vaultId}/transaction-requests/contract-interaction` (write) | `await vaultody.transactions.createTronContractInteractionRequest({ vaultId, vaultAccountId, assetId, fromAddress, feePayer: payer, method: 'approve', note: 'Approve the fee payer' })` |
| `estimateTransactionFeeByAssetId` | `POST /vaults/{vaultId}/approximate-fee` | `await vaultody.transactions.estimateTransactionFeeByAssetId({ vaultId, vaultAccountId, transactionType: 'single', assetId, fromAddress, toAddress, amount: '0.001' })` |
| `getTransactionDetails` | `GET /vaults/{vaultId}/{blockchain}/transactions/{transactionId}` | `await vaultody.transactions.getTransactionDetails({ vaultId, blockchain: 'ethereum', transactionId })` |
| `getTransactionRequestDetails` | `GET /transaction-requests/{transactionRequestId}` | `await vaultody.transactions.getTransactionRequestDetails({ transactionRequestId })` |
| `listUtxos` | `GET /vaults/{vaultId}/utxos` (list) | `await vaultody.transactions.listUtxos({ vaultId, isSpent: false })` |

### apiKeys

| Method | Endpoint | Example |
|---|---|---|
| `listApiKeySigningKeys` | `GET /api-keys/current/signing-keys` (list in one page; no params; pending in the docs) | `await vaultody.apiKeys.listApiKeySigningKeys()` |

`getAddressBalance` is a list whose cursor field the API reference does not name, so it is not paged
automatically: iterating it throws `PaginationError` (`cursor_unknown`); pass `startingAfter` yourself.

## What every call goes through

check → build → rate limit → sign → send → verify the response → read the envelope → typed error → retry or return

| Step | What | Where |
|---|---|---|
| Check | The API methods: every field against the API reference (required, type, documented values), unknown fields refused at any depth | `params.js`, `operations.js` (`test/contract.test.js`) |
| Build | One flat `params` object; the operation table puts each field in the path, query or `{ context?, data: { item } }` body. An unknown param is refused, never dropped. Body ≤ 1 MiB. | `operations.js`, `requestBuilder.js`, `requestTarget.js` (`path-encoding-v1.json`) |
| Rate limit | Token bucket, 5 requests/s, bursts of 5, per client (`maxRequestsPerSecond`) | `rateLimiter.js` |
| Sign | HMAC v2 with the passphrase and a fresh 16-byte nonce; `x-api-version: 2026-03-20` sent and signed; with a signer, `x-api-keypair-sign` / `x-api-keypair-id` | `@vaultody-com/verify` keys, `signer.js` (`request-full-v1.json`, `request-hmac-v2.json`) |
| Send | `fetch`, https only (plain http only to localhost), redirects never followed, answer ≤ 10 MiB, `timeoutMs` per attempt | `transport.js` |
| Verify | Before a byte is parsed, error answers included. A failure throws `ResponseVerificationError` and is never retried | `responseVerification.js` (`v1.json`) |
| Read | Item, page or typed error (`ApiError` and its subclasses, branch on `code`) | `errors.js` (`envelope-errors-v1.json`) |
| Pins and addresses | Every `listVaults` answer is compared with the vault xpub pins; addresses are checked on the operations that return them | `addressGuard.js`, `vaultKeyStore.js` (`vault-key-pins-v1.json`, `address-v1.json`) |
| Retry | Reads retried and re-signed; a write never re-signed once it may have run | `retry.js`, `transport.js` (`retry-v1.json`, `transport-errors-v1.json`) |

### Response signatures

The rules are the same in every language ([`test-vectors/response-mode-v1.json`](../../../test-vectors/response-mode-v1.json)).

- **Roots configured means strict.** With `roots` given, or in a stable release (no `-rc.N`) that embeds the
  production root, `responseSignature` is `'required'` from the first answer, so a signature stripped on the way is
  caught from the start. A `'when-present'` given then (the option or `VAULTODY_RESPONSE_SIGNATURE`) is ignored with
  one `logger.warn`. `client.responseSignature` reports the mode in force.
- `responseSignature: 'when-present'` (the default for release candidates, or `VAULTODY_RESPONSE_SIGNATURE`):
  - an unsigned answer is accepted, marked `signature: 'absent'`; the first one a client accepts raises `onSecurityEvent({ type: 'unsigned_response_accepted', origin, operationId })` and then one `logger.warn`, once per client (the same event in Python and PHP);
  - a signed answer is always checked, and a failure throws and is never retried;
  - a partly stripped signature always fails.
  - A release candidate that embeds the root stays `'when-present'`: it bridges to signing through the latch.
- **The latch.** The first answer from an API origin that carries a response signature (any of the four
  `x-api-response-*` headers), whether it verifies or not, turns the client strict for that origin, before its error
  is thrown, and is stored with the pins, so a restart keeps it: `{ latchedAt, rootId }`, `rootId` `null` when the
  answer did not verify. `onSecurityEvent({ type: 'response_signature_latched', origin, rootId, latchedAt })` comes
  first. Strict clients latch too, so a release candidate sharing their pin file is strict as well.
- **A signed read before the first write.** A client whose roots are configured and whose origin is not latched yet
  asks `GET /api-keys/current/signing-keys` once before its first write (with a signer, the key-pair check is that
  read). Against an origin that does not sign, the read is refused and the write is never sent.
- `responseSignature: 'required'`: every answer must be signed. 1.0 makes this the default (`DEFAULT_RESPONSE_SIGNATURE`).
- `roots`: the response-signing root keys to trust instead of the embedded ones, which are empty until the production root exists. A signed answer with no root to check it fails closed (`ConfigurationError` `no_root_keys`), and latches the origin.

### Vault xpub pins and addresses

- **Where pins come from.** From `GET /vaults/{main|test}` (`listVaults`), or from your configuration.
  - A vault seen for the first time is pinned: `verified` from a signed answer, `unverified` (trust on first use) from an unsigned one.
  - `pinnedVaultKeys: [{ vaultId, type: 'main' | 'test', keys: { ECDSA: xpub | null, EDDSA: xpub | null } }]` gives pins you confirmed yourself, for this client's API origin. Each counts as `verified`. It is still compared with every `listVaults` answer, signed or not, and any difference is the alarm. It is never written to the store and takes the place of the stored pin of its vault. A malformed entry is a `ConfigurationError` (`invalid_option`). Python (`pinned_vault_keys`) and PHP (`pinnedVaultKeys`) take the same list.
  - An unverified pin becomes verified when a signed answer shows the same xpubs. When an address answer is signed and its vault's pin is not, the client lists the vaults again to confirm it.
  - A vault without MPC keys (SMART, AUTOMATION) has nothing to pin: its addresses are `not_verifiable`, never verified.
- **The alarm.** Any difference from a pin: an xpub changed or gone (`xpub_changed`, `xpub_missing`), an algorithm added to a pinned vault (`xpub_added`), a vault type changed (`type_changed`).
  - `onSecurityEvent({ type: 'vault_key_changed', origin, alarms })` is called first.
  - Then `VaultKeyChangedError` is thrown. The pin is not touched and nothing is returned.
  - Alarms carry short hashes (the first 16 hex characters of the SHA-256 of each xpub), never an xpub.
  - Nothing re-pins by itself. When the change is legitimate (confirm it with Vaultody first), re-pin the vault: `npx @vaultody-com/sdk vault-keys accept --vault-id <vaultId>` shows the pinned and the new fingerprints and replaces the pin with `--yes --expect <fingerprints>` (below), or call `store.replace()` on a custom store. A configured pin is changed in your configuration.
- **Per-vault results.** Every `listVaults` page has `meta.vaultKeys`: one `{ vaultId, status, outcome }` per vault, in answer order. `status` is the vault's pin after the answer (`verified`, `unverified`) or `not_verifiable` (no MPC keys); `outcome` is `pinned`, `unchanged`, `upgraded` or `not_verifiable`. Python (`meta.vault_keys`) and PHP (`meta->vaultKeys`) report the same.
- **Which addresses are checked.** On `generateDepositAddress`, `listAddressesByVaultAccountId` and `addAssetToVaultAccount`.
  - An address with its path (`accountIndex`, `isChange`, `addressIndex`) must derive from the pinned xpub (`@vaultody-com/verify/address`). Otherwise the whole answer is refused with `AddressVerificationError`.
  - An address without the path is `not_verifiable`. That is every address today, because the API hides the fields until the SDK ships.
  - `requireAddressPaths: true` (the default once the API returns the paths, `ADDRESS_PATHS_PUBLIC`): a
    `generateDepositAddress` answer without the path, for a vault with MPC keys on a chain the SDK can derive, is
    refused with `AddressVerificationError` `path_missing` (after the `address_verification_failed` event). Lists and
    `addAssetToVaultAccount` may return older rows without a path: they stay `not_verifiable`. Python
    (`require_address_paths`) and PHP (`requireAddressPaths`) take the same option.
  - A vault that is not in the list fails closed (`unknown_vault`), and so does an address with a path but no chain (`unsupported`).
  - An item that names another network than the one asked for is refused with `network_mismatch`, another chain with `mismatch` (the same codes in Python and PHP).
- **Security events.** `onSecurityEvent(event)` gets the seven events of `SECURITY_EVENTS` with exactly their fields ([`docs/vault-keys-file.md`](../../../docs/vault-keys-file.md)). Without it, each event is logged once through `logger.warn` as `Vaultody security event: {json}`, as Python and PHP do.
- **Store.** `~/.vaultody/vault-keys.json` (or `VAULTODY_VAULT_KEYS_FILE`, or `vaultKeysFile`).
  - The file is the `vaultody vault keys v1` document the Python and PHP SDKs read and write too ([`docs/vault-keys-file.md`](../../../docs/vault-keys-file.md)): one file can be shared across languages.
  - The file is mode 0600 in a 0700 directory, written only on a change, in canonical form, and replaced atomically under `<file>.lock` (created exclusively, the protocol every language uses), so processes can share it.
  - A file that can't be read, that others can write, that is a symbolic link, or that does not match the layout exactly fails closed (`VaultKeyStoreError` with the shared codes: `not_json`, `unknown_format`, `malformed`, `insecure_permissions`, `not_regular_file`, `too_large`).
  - If the default location can't be written, pins stay in memory, with a warning. An explicit file must be writable.
  - `vaultKeyStore` takes a custom store (the interface is in `vaultKeyStore.js`), for example a shared one for containers.

### Retries

| Outcome | Read (GET, validateAddress, estimateTransactionFeeByAssetId, validateUtxoTransfer) | Write, key pair confirmed active | Write, legacy key or unconfirmed |
|---|---|---|---|
| Not sent (refused, DNS, TLS) | re-signed after a backoff | the same signed request again | the same signed request again |
| Sent, no answer / 5xx | re-signed after a backoff | resent once at once within 2.5 s, else `RequestOutcomeUnknownError` | `RequestOutcomeUnknownError` |
| 429 | backoff, re-signed | backoff, the same request while it is under 25 s old | same |
| Answer replayed (`x-api-replayed`) | | returned; a replayed 5xx is outcome unknown | |
| 409 in progress / 401 duplicate after a resend | | `RequestOutcomeUnknownError` (`inProgress`) | |
| 409 `api_nonce_reused` | | `RequestSigningError`, never retried | same |
| Verification failure, other 4xx | never | never | never |

- **Backoff.** Full jitter, 1 s doubling to 8 s, 5 attempts, a 30 s deadline, and `Retry-After` when sent.
- **Key-pair mode.** The key pair counts as confirmed only when `listApiKeySigningKeys` lists it as active in a signed answer. The client asks before the first write and again every 10 minutes (`confirmSigningKey()`).
- **One nonce per write.** Every retry of a write keeps its `x-api-nonce` and body, so the gateway's idempotency (per API key and nonce) sees one operation. A resend is the same signed request; a write signed again (its signature too old to resend) gets a fresh `x-api-timestamp` and fresh signatures over the same nonce. A read signed again gets a new nonce (`retry-v1.json`, `nonce`).
  - The one exception: `address_derivation_conflict` and `vault_accounts_creation_failed` say that nothing was executed, so their one immediate retry is signed again with a new nonce and the same body (with the same nonce the gateway would only replay the 409). Later retries of that call keep the new nonce. A second conflict reaches you as `ConflictError` (`retryable: true`).
- **`RequestOutcomeUnknownError`.** It carries the nonce and timestamp of the request that may have run. Check `getTransactionRequestDetails` before you send it again.

### Signers

A signer is `{ algorithm: 'ed25519' | 'p-256', publicKeyPem, sign(message) → bytes, digestOnly? }`, so the private key
can stay in a KMS or HSM.

| Signer | What it sends | What it gets back |
|---|---|---|
| `fileSigner(path)`, `pemSigner(pem)` | Signs in this process. | |
| `awsKmsSigner({ keyId, algorithm, publicKeyPem, sign })` | P-256: the digest, as `DIGEST` / `ECDSA_SHA_256`. Ed25519: the message, as `RAW` / `ED25519_SHA_512`, at most 4096 bytes. | DER (P-256) |
| `gcpKmsSigner({ name, algorithm, publicKeyPem, asymmetricSign })` | P-256: the digest. Ed25519: the data, at most 64 KiB. | DER (P-256) |
| `vaultTransitSigner({ keyName, mount, algorithm, publicKeyPem, write })` | P-256: `prehashed`, `sha2-256`, `asn1`. | The `vault:vN:` prefix is removed. |

- **No cloud dependency.** Each adapter shapes the request and the answer around a function you pass, for example `sign: params => kms.send(new SignCommand(params))`.
- **Normalised output.** A 64-byte P-256 signature (IEEE P1363 r‖s, from Web Crypto or Azure) is converted to DER (`p1363-der-v1.json`). An Ed25519 signature must be 64 bytes.
- **Local check.** Every signature is checked against `publicKeyPem` before sending (`verifySignerLocally`, on by default).

### Errors

| Class | When |
|---|---|
| `ApiError` | An error answer. Subclasses: `AuthenticationError`, `RequestSigningError`, `PermissionDeniedError`, `NotFoundError`, `InvalidRequestError`, `ConflictError`, `DuplicateTransferError`, `RateLimitError`, `ServerError`. Fields: `status`, `code`, `message`, `details`, `requestId`, `apiVersion`, `replayed`, `retryable`, `signature`. |
| `ResponseVerificationError` | The response signature check failed; `reason` says why. |
| `AddressVerificationError` | An address failed its check; `code` says why. |
| `VaultKeyChangedError` | A vault's xpub differs from its pin; `alarms` lists them. |
| `RequestOutcomeUnknownError` | A write may or may not have run. |
| `TransportError` | A network failure; `sent` is `false` or `'unknown'`. |
| `ParameterError` | A call that can't become a request; `code` says why, and `param` names the field (`recipients[0].amount`), never its value. |
| `PaginationError` | A list that can't be paged safely. |
| `ConfigurationError` | The client is set up wrongly. |
| `VaultKeyStoreError` | The pin store can't be read or written. |
| `WebhookSignatureError`, `WebhookPayloadError` | A webhook delivery that fails its check (`reason`: `missing`, `malformed`, `mismatch`), or that isn't an event. |

The API secret, passphrase and API key never appear in `util.inspect`, JSON or an error.

### Paging and webhooks

- **Paging.**
  - A list method's promise is an async iterator over every item; `page.nextPage()` and `page.autoPaging({ maxItems })` continue from a page you already have. After an `autoPaging()` loop, `stop` says why it ended (`pagination-v1.json`).
  - A cursor seen twice throws.
  - `getAddressBalance` is not paged automatically, because its cursor field isn't documented.
- **Webhooks.**
  - `vaultody.webhooks.verify(rawBody, headers, secrets?)` checks `X-Signature` against every secret in constant time; several secrets cover a rotation. Then it returns `{ event, known, item, inclusion, idempotencyKey, webhookId, ... }` (`webhook-v1.json`).
  - An unknown event comes back with `known: false`, not as an error.
  - The scheme has no timestamp, and Vaultody may deliver the same event more than once. Before you act on an event, check whether you already acted on it, keyed on what the event is about, as the developer docs' Webhook Notifications page says:
    - outgoing transaction events: `item.requestId` and `event`;
    - incoming transaction events: `item.transactionId`, `item.address`, `event` and `item.currentConfirmations`. An internal transfer has no `transactionId`: use `item.parentTransactionId` and `item.operationId` in its place.
  - The SDK stores nothing.

## Command line

### Request-signing keys

An API key can hold up to two public keys of your own. Once it holds one, every request made with it must also be
signed with the matching private key (`x-api-keypair-sign`). The `vaultody keys` command makes those keys, prints
their fingerprint, signs the challenge the dashboard shows when you register a key, and checks that a key is
registered. It ships with this package: `npx @vaultody-com/sdk keys ...` (always the scoped name: an unscoped
`npx vaultody` would run whatever is published under that name). From a checkout, `node bin/vaultody.js keys ...`
in this directory does the same.

| Command | What it does |
|---|---|
| `vaultody keys generate --algorithm ed25519 --out private.pem --public-out public.pem [--force]` | Makes a key pair (`ed25519` or `p-256`) and prints its fingerprint. The private key is PKCS#8 PEM with mode 0600, the public key SPKI PEM with 0644. An existing file is never overwritten without `--force`. |
| `vaultody keys fingerprint --key public.pem` | Prints the fingerprint of a public or private key: `SHA256:` and the unpadded base64 SHA-256 of the public key's SPKI DER, a P-256 point uncompressed. The dashboard shows the same value. |
| `vaultody keys prove --key private.pem --api-key-id <apiKeyId> --challenge <challenge>` | Signs `vaultody-keypair-challenge-v1\n<apiKeyId>\n<fingerprint>\n<challenge>` and prints only the base64 signature (Ed25519: the raw 64 bytes; P-256: DER). The challenge must be exactly `vk-chal-` and 64 lowercase hex characters. |
| `vaultody keys verify --key private.pem [--root <url>] [--api-version <YYYY-MM-DD>] [--allow-unsigned]` | Calls `listApiKeySigningKeys` (`GET /api-keys/current/signing-keys`) through this SDK's client: signed with HMAC v2 and the key pair, the response signature verified (the `x-api-keypair-sign` line included), retried as any read. Then it checks that the key is listed and active. An unsigned response exits 4 unless `--allow-unsigned` is given. |

- `verify` reads the API credentials only from the environment: `VAULTODY_API_KEY`, `VAULTODY_API_SECRET`
  and `VAULTODY_PASSPHRASE`. They are never taken from arguments, and the secret is never sent. It keeps nothing:
  no pin file, no latch.
- `--root` points `verify` at another environment; the default is `https://rest.vaultody.com`. It must be
  https: the request carries the passphrase, so plain http is refused (exit 2) except to localhost, for a
  port-forward. `--api-version` sets the `x-api-version` sent and signed with the request; the default is
  `2026-03-20`, the version the endpoint was introduced in. `--response-root-key <root.pem>` (repeatable) trusts
  that environment's response-signing root instead of the embedded ones, which are not filled in yet.
- Without `--allow-unsigned`, `verify` exits 0 only when the response is signed, its signature verifies and
  the key is listed and active. An unsigned response proves nothing: whatever removed the signature could
  also have put your own fingerprint into the list. It exits 4 and prints what the unverified answer said.
- `--allow-unsigned` is for as long as Vaultody does not sign responses yet: an unsigned response then
  gives the usual 0 or 1, with a warning. It is ignored when response-signing root keys are configured
  (embedded, or `--response-root-key`): then an unsigned response always exits 4.
- Exit codes:

  | Code | Meaning |
  |---|---|
  | 0 | The response is signed and verified, and the key is registered and active. With `--allow-unsigned`, also an unsigned response that lists the key as active |
  | 1 | The API refused the request, the key is not listed or not active, or the response failed its signature check |
  | 2 | A usage error: arguments, key files, environment |
  | 3 | A network error or an unexpected answer |
  | 4 | The response was not signed, so the answer could not be verified |

- Nothing is ever printed of a private key, the API secret, the passphrase or the API key.
- Python and PHP users run it with `npx` too; the key formats are the same in every language
  (`keypair-challenge-v1.json`, `request-keypair-v1.json`).

### Vault key pins: `vault-keys accept`

The SDKs refuse a vault whose xpub changed, that gained a key, or whose type changed (`VaultKeyChangedError`), until
you re-pin it. Confirm the change with Vaultody first, then:

```
npx @vaultody-com/sdk vault-keys accept --vault-id <vaultId> [--file vault-keys.json] [--root <url>] [--key private.pem]
                                   [--yes --expect type=<main|test>,ECDSA=<fingerprint|->,EDDSA=<fingerprint|->]
```

- It reads the credentials from the environment, as `keys verify` does, and asks `GET /vaults/main` and
  `GET /vaults/test` through this SDK's client (the vault's pinned type first) for what the vault holds now.
- It prints the pinned and the new type and fingerprints side by side: the fingerprints of the alarm, the first 16 hex
  characters of the SHA-256 of each xpub. Without `--yes` nothing is written (exit 1), and it prints the
  `--yes --expect type=…,ECDSA=…,EDDSA=…` options that accept exactly what it showed (`-` for no key).
- With `--yes` it reads the vault list again and replaces the pin only when that list shows exactly the type and
  fingerprints of `--expect`, the ones you confirmed with Vaultody; otherwise nothing is written (exit 1). `--yes`
  without `--expect` is a usage error. It replaces the pin in the pin file (`--file`, else `VAULTODY_VAULT_KEYS_FILE`,
  else `~/.vaultody/vault-keys.json`; the file Python and PHP share) and records the change in the file's audit list.
  The new pin is `verified` when the vault list was signed.
- An unsigned list exits 4, unless `--allow-unsigned` is given while Vaultody does not sign responses yet (the new pin is
  then `unverified`). `--allow-unsigned` is ignored once root keys are configured or the pin file has seen a signed
  answer from that API.
- `--key` signs the requests with the private key registered on the API key, when it has one; `--root` and
  `--response-root-key` work as for `keys verify`.
- Exit codes: 0 re-pinned, or the pin already matches; 1 not re-pinned (no `--yes`, the API shows other keys than
  `--expect`, no pin to replace, the vault is not listed or has no MPC keys, the API refused, or the signature check
  failed); 2 usage error (`--yes` without `--expect` among them); 3 network or unexpected error; 4 the vault list was
  not signed.

## Tests

```sh
cd node && npm ci && npm test
```

`test/cli.test.js` runs the command line as a separate process (with the dashboard's openssl commands when
OpenSSL 3 is on `PATH`), and `test/cli-verify.test.js` runs `keys verify` against a local stand-in for the API.
`test/package-exports.test.js` imports every export with `require()` and with ESM `import`.

`test/methods.test.js` runs every method against the mock gateway with the API reference's own examples: the
request on the wire, the answer back, every documented error, the retry class, the param checks, paging, and the
address checks. Every vector set runs through the real pipeline against the mock gateway in
[`../../../conformance/mock-gateway`](../../../conformance/mock-gateway/README.md). The mock checks every
signature with its own code, and its checks are held to the gateway's own vectors.
