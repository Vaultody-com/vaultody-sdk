# vaultody/sdk (PHP)

The official Vaultody SDK for PHP, namespace `Vaultody\Sdk\`. PHP 8.2+, built-in extensions only: curl,
json, openssl, sodium (and hash). No Composer runtime dependencies.

One method for every documented operation of API version `2026-03-20` (32, `listApiKeySigningKeys`
still pending in the docs), grouped and named as the docs group and name them.

## Calling the API

```php
$vaultody = new Vaultody\Sdk\Vaultody([
    'apiKey' => getenv('VAULTODY_API_KEY'),
    'apiSecret' => getenv('VAULTODY_API_SECRET'),
    'passphrase' => getenv('VAULTODY_PASSPHRASE'),
    'vaultKeysFile' => '/var/lib/vaultody/vault-keys.json',
]);

// One flat array of params (path, query and body fields by their documented names), then call options.
$request = $vaultody->transactions->createSingleTransfer([
    'vaultId' => '60c9d9921c38030006675ff6',
    'vaultAccountId' => '60c9d9921c38030006675ff7',
    'assetId' => '6523e058a06ebf1322d7dd6e',
    'fromAddress' => '0x...',
    'toAddress' => '0x...',
    'amount' => '0.001',            // amounts are strings, never floats
    'note' => 'Invoice 7',
], ['context' => 'order-7']);
$request->transactionRequestId;     // a typed model; $request->raw has the object as it came
$request->meta->requestId;          // and what the SDK knows about the answer

// A list returns its first page; iterating it reaches every item, fetching the next pages as needed.
foreach ($vaultody->vaults->listVaults(['networkType' => 'main']) as $vault) {
    echo $vault->id, ' ', $vault->name, "\n";
}
$page = $vaultody->transactions->listUtxos(['vaultId' => '...', 'limit' => 10]);
$page->items; $page->hasMore; $next = $page->nextPage();
```

- **Params are checked against the documented contract before anything is sent**
  (`Exception\ParameterError`): an undocumented param or option, at any depth of a body object, is refused
  (`unknown_param`, `unknown_option`); a missing required one is refused (`missing_param`); a value of the
  wrong JSON type is refused (`invalid_param`), and `limit` must be 1 to the operation's maximum. A param
  with a documented list of values (`blockchain`, `network`, `networkType`, `feePriority`, ...) takes
  exactly one of the values that operation documents for the pinned API version, case included (`MAIN` is
  refused); the error names the field (`$error->param`, nested ones as `recipients[0].amount`, as in Node and
  Python), never the value. Each operation has its own list: `prepareStrategy` is
  `minimize-dust` in `createMultipleTransfer` and `minimize_dust` in `estimateTransactionFeeByAssetId`. A
  `null` optional param is left out. Answers are not checked this way: an enum value the API adds later
  reads as it came.
- **The one call option is `context`**, a string the API returns unchanged (`$result->meta->context`).
- **Answers are typed models** (`Vaultody\Sdk\Model\*`): each documented field a readonly property,
  `$model->raw` the object exactly as it came (undocumented fields too). A field missing or of another JSON
  type than documented is `null` in its property (a list: `[]`) and stays in `raw`; reading never throws.
  `$model->meta` (on the object a method returns): `requestId`, `apiVersion`, `context`, `replayed`,
  `signature` (`verified` or `absent`) and `addressChecks`.
- **Lists return a `Model\Page`**: `items`, `hasMore`, `meta`, `nextPage()`, and iteration over every item
  from that page on, each page an ordinary verified call. The page size is the operation's maximum unless
  `limit` is given; `startingAfter` starts after a given item. A list the SDK can't continue on its own
  throws `PaginationError` `cannot_continue` rather than stop quietly: `getAddressBalance` (the docs don't
  name its cursor field: page it with `startingAfter`) and `listApiKeySigningKeys` (no paging params; at
  most two keys, always on one page).
- **Writes are never sent twice by a retry.** A transfer whose answer is lost throws
  `RequestOutcomeUnknownError`: look it up (`getTransactionRequestDetails`, the Dashboard) before sending it
  again. Reads, and the three POSTs that change nothing (`validateAddress`, `validateUtxoTransfer`,
  `estimateTransactionFeeByAssetId`), are retried.
- **Operations that return vault addresses or keys need a pin store** (below): `listVaults`,
  `generateDepositAddress`, `listAddressesByVaultAccountId`, `addAssetToVaultAccount`. Without one they throw
  `ConfigurationError` before anything is sent.
- **Webhooks:** `$vaultody->webhooks->verify(file_get_contents('php://input'), getallheaders(), $secret)` checks
  `X-Signature` over the raw body (several secrets cover a rotation) and returns a `WebhookEvent`. A bad
  signature throws `WebhookSignatureError` (`reason`: `missing`, `malformed`, `mismatch`), a signed body that is no
  event `WebhookPayloadError`. The scheme has no timestamp, and Vaultody may deliver the same event more than
  once: before acting on an event, check whether you already did, keyed on what the event is about, as the
  developer docs' Webhook Notifications page says (outgoing transaction events: `item['requestId']` and the
  event; incoming ones: `item['transactionId']`, `item['address']`, the event and `item['currentConfirmations']`,
  with `parentTransactionId` and `operationId` in place of `transactionId` for an internal transfer). The SDK
  stores nothing.

The methods are the only way to call the API; the client exposes no lower-level request call.

### vaults

| Method | Request | Returns |
|---|---|---|
| `listVaults` | `GET /vaults/{networkType}` | `Page<Vault>`; pins the vault xpubs (needs a pin store) |
| `listVaultsByAssetId` | `GET /assets/{assetId}/{blockchain}/vaults/{networkType}` | `VaultsByAsset` |
| `listAssetsByVault` | `GET /vaults/{vaultId}/assets` | `VaultAssets` |
| `listTransactionsByVault` | `GET /vaults/{vaultId}/transactions` | `Page<Transaction>` |

### vaultAccounts

| Method | Request | Returns |
|---|---|---|
| `createVaultAccount` | `POST /vaults/{vaultId}/vault-account` | `VaultAccount` (write) |
| `listVaultAccounts` | `GET /vaults/{vaultId}/vault-accounts/details` | `Page<VaultAccount>` |
| `getVaultAccountById` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/details` | `VaultAccount` |
| `updateVaultAccount` | `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit` | `VaultAccount` (write) |
| `addAssetToVaultAccount` | `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset` | `AddedAsset` (write); address checked (needs a pin store) |
| `listAssetsByVaultAccountId` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets` | `Page<VaultAccountAsset>` |
| `listTransactionsByVaultAccount` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions` | `Page<Transaction>` |

### assetsAddresses

| Method | Request | Returns |
|---|---|---|
| `generateDepositAddress` | `POST /vaults/{vaultId}/{blockchain}/{network}/addresses` | `DepositAddress` (write); address checked (needs a pin store) |
| `getAddressBalance` | `GET /vaults/{vaultId}/addresses/{address}/balance` | `Page<AddressBalance>`; next pages by `startingAfter` only |
| `listAddressesByVaultAccountId` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses` | `Page<VaultAddress>`; addresses checked (needs a pin store) |
| `listSupportedAssets` | `GET /supported-assets` | `Page<SupportedAsset>` |
| `validateAddress` | `POST /info/{blockchain}/{network}/addresses/validate` | `AddressValidation` (retried like a read) |
| `encodeXrpAddress` | `GET /utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}` | `XrpXAddress` |
| `decodeXrpAddress` | `GET /utils/xrp/{network}/addresses/decode/{xAddress}` | `XrpClassicAddress` |
| `tronResourceOverview` | `GET /vaults/{vaultId}/{blockchain}/{network}/{address}/overview` | `TronResourceOverview` |
| `tronResourceManagement` | `POST /vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource` | `TronResourceOperation` (write) |

### transactions

| Method | Request | Returns |
|---|---|---|
| `createSingleTransfer` | `POST /vaults/{vaultId}/transaction-requests/single-transfer` | `SingleTransferRequest` (write) |
| `createMultipleTransfer` | `POST /vaults/{vaultId}/transaction-requests/multiple-transfer` | `MultipleTransferRequest` (write) |
| `createUtxoTransfer` | `POST /vaults/{vaultId}/transaction-requests/utxo-transfer` | `UtxoTransferRequest` (write) |
| `validateUtxoTransfer` | `POST /vaults/{vaultId}/transaction-requests/utxo-transfer/validate` | `UtxoTransferValidation` (retried like a read) |
| `createBatchTransactionRequest` | `POST /vaults/{vaultId}/transaction-requests/batch` | `BatchTransactionRequest` (write) |
| `gasSponsorshipTransfer` | `POST /vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer` | `GasSponsorshipTransferRequest` (write) |
| `createTronContractInteractionRequest` | `POST /vaults/{vaultId}/transaction-requests/contract-interaction` | `TronContractInteractionRequest` (write) |
| `estimateTransactionFeeByAssetId` | `POST /vaults/{vaultId}/approximate-fee` | `FeeEstimate` (retried like a read) |
| `getTransactionDetails` | `GET /vaults/{vaultId}/{blockchain}/transactions/{transactionId}` | `TransactionDetails` |
| `getTransactionRequestDetails` | `GET /transaction-requests/{transactionRequestId}` | `TransactionRequestDetails` |
| `listUtxos` | `GET /vaults/{vaultId}/utxos` | `Page<Utxo>` |

### apiKeys

| Method | Request | Returns |
|---|---|---|
| `listApiKeySigningKeys` | `GET /api-keys/current/signing-keys` (no params; pending in the docs) | `Page<ApiKeySigningKey>`, whole on one page |

The operation table behind the methods is `Vaultody\Sdk\Operations::ALL`; `scripts/coverage.mjs` checks it
and the client's methods (found by reflection, `bin/surface.php`) against `contract/openapi.json`, and
`tests/ApiMethodsTest.php` checks every param type and every model field against it too.

## What every call does

- **Signs** every request with HMAC v2, a 16-byte nonce (fresh for every call; a write keeps it on every retry but
  the conflict retry)
  and the pinned `x-api-version` (`Version::API_VERSION`), plus `x-api-keypair-sign` when a signer is set: a key file
  (`privateKeyFile`, `KeyFileSigner`) or any callable (`CallableSigner`, for a KMS or HSM, so the private key
  never has to be in PHP's memory). The key-pair signature covers `vaultody-request-keypair-v1`, the `x-api-key`
  the request is sent with, then the HMAC v2 fields, one per line (`test-vectors/request-keypair-v1.json`), so a
  request signed for one API key can't be sent under another that holds the same key pair. A P-256 signature in
  IEEE P1363 form is converted to DER, and every key-pair signature is checked against the public key before it
  is sent.
- **Verifies** every response, error answers included, before its body is read (`ResponseVerifier`, the
  wire format of `test-vectors/v1.json`; a response certificate is valid for at most an hour).
  `responseSignature` `when-present` (the default while production does not sign) accepts a response with no
  signature headers until the first one from that API origin that carries a signature, verified or not; from
  then on unsigned answers are refused, and that latch is stored with the pins so it outlives the PHP process.
  `required` refuses them from the start. A client with response-signing roots (the `roots` option, or the
  roots a stable release embeds) is always `required`: a `'when-present'` given is ignored, with one warning
  when the client is made, and its first write is preceded by one signed read
  (`GET /api-keys/current/signing-keys`), so a write is never sent to an origin whose answers can't be checked.
  `$vaultody->responseSignature()` says which mode is in force (`test-vectors/response-mode-v1.json`). A
  failure is never retried. The first unsigned answer a client accepts raises the security event
  `['type' => 'unsigned_response_accepted', 'origin' => ..., 'operationId' => ...]` (once per client, as in
  Node and Python), then one warning through the `logger` option: any object with a `warning(string)`
  method, such as a PSR-3 logger (`error_log()` when none is given).
- **Retries** by `test-vectors/retry-v1.json`: reads re-signed with backoff after a 429, a 5xx or a network
  error; a write is never signed again once it may have reached the gateway. A write whose answer was lost
  is resent unchanged at once only when the key pair is confirmed active (through the signed list of the API
  key's signing keys) and within 2.5 s; otherwise the caller gets `RequestOutcomeUnknownError`. Every retry of
  a write keeps its `x-api-nonce` and body, so the gateway's idempotency (per API key and nonce) sees one
  operation: a write signed again (its signature too old to
  resend) gets a fresh timestamp and signatures over the same nonce; a read signed again gets a new nonce. The
  one exception is the one immediate retry of `address_derivation_conflict` / `vault_accounts_creation_failed`:
  nothing was executed, so it is signed again with a new nonce and the same body (the same nonce would only get
  the replayed 409). A second conflict reaches you as `ConflictError` (`retryable`). A 409 `api_nonce_reused` is
  a `RequestSigningError`, never retried.
- **Rate-limits** to 5 requests per second per client (`maxRequestsPerSecond`).
- **Reads** the envelope into `Item` / `Page` or a typed error (`Vaultody\Sdk\Exception\*`).
- **Pins vault xpubs** from `GET /vaults/{main|test}` and **checks every returned address** against them
  (`Verify\Address\AddressVerifier`, 17 chains, `test-vectors/address-v1.json`). Each address gets an entry
  `['vaultId', 'address', 'status']` in `meta->addressChecks`, status `verified`, `unverified` (the pin came from an unsigned answer: trust on first
  use, upgraded by the first signed one) or `not_verifiable` (SMART vaults, rows without a derivation path).
  A mismatch, or an xpub that changed (`VaultKeyChangedError`, with short hashes, never the xpub), refuses
  the whole answer and calls `onSecurityEvent` (`address_verification_failed`, `vault_key_changed`; with no
  `onSecurityEvent`, every event is logged once through the logger as `Vaultody security event: {json}`). An
  item that names another network than the one asked for is refused with `network_mismatch`, another chain with
  `mismatch`. With `requireAddressPaths` on (its default is `Transport::ADDRESS_PATHS_PUBLIC`: off while the API
  hides the derivation paths), an address `generateDepositAddress` answers without its path (`accountIndex`,
  `isChange`, `addressIndex`), for a vault with MPC keys on a chain the SDK derives, is refused with
  `path_missing` instead of `not_verifiable`; lists and `addAssetToVaultAccount` may hold older rows without one,
  so they stay `not_verifiable`. A vault
  listed under the other type (`/vaults/main` vs `/vaults/test`) refuses the answer (`ApiError`), as in Node and
  Python. Security events have exactly the fields of `SecurityEvents::EVENTS`, the same in every language
  ([`../docs/vault-keys-file.md`](../docs/vault-keys-file.md)). A vault that gains an algorithm (`xpub_added`) or
  changes type (`type_changed`) is refused the same way, on purpose. A pin is never replaced automatically: after
  you confirm the change out of band, re-pin the vault with `npx @vaultody-com/sdk vault-keys accept --vault-id <id> --yes`
  (the Node command line, which edits the shared pin file; it shows the old and new fingerprints first) or
  `VaultKeys\Pins::replace()` on your store, which records why in the store's audit list.
- **Takes pins from configuration** too: `pinnedVaultKeys`, a list of
  `['vaultId' => ..., 'type' => 'main'|'test', 'keys' => ['ECDSA' => $xpub, 'EDDSA' => null]]` for the client's
  API origin (exactly these keys, at least one xpub, no vault twice; anything else is a `ConfigurationError`).
  A configured pin counts as `verified`, signed answer or not, and is still compared with every vault list:
  any difference is the alarm (`VaultKeyChangedError`). It is never written to the store and takes the place of
  a stored pin of the same vault. The pin store is still required.
- **Says per vault what a vault list did**: every `listVaults` page has `meta->vaultKeys`, one
  `['vaultId', 'status', 'outcome']` per vault in answer order: `status` `verified`, `unverified` or
  `not_verifiable` (no MPC keys), `outcome` `pinned`, `unchanged`, `upgraded` or `not_verifiable`. Node has
  the same in `meta.vaultKeys`, Python in `meta.vault_keys`.

## The pin store needs an explicit path

Under PHP-FPM every request is a new process, so pins kept in memory protect nothing. Operations that return
addresses or vault keys therefore need `vaultKeysFile` (or `VAULTODY_VAULT_KEYS_FILE`), a path every PHP
worker can write, or a custom `vaultKeyStore` (for example Redis or SQL in containers); without one they fail
with `ConfigurationError` before anything is sent.

The file is the one every SDK reads and writes ([`../docs/vault-keys-file.md`](../docs/vault-keys-file.md)),
so PHP workers and Node or Python processes can share it. It is written in canonical form with mode 0600
under a 0700 directory and an atomic rename; a write holds `<file>.lock`, created exclusively and removed
afterwards (stale after 30 s, given up after 10 s), the lock protocol of every SDK. A file that can't be read,
is writable by others, is a link, or does not match the layout exactly is a `VaultKeyStoreError` (a
`ConfigurationError`) with a code (`not_json`, `unknown_format`, `malformed`, `insecure_permissions`,
`not_regular_file`, `too_large`, ...), never an empty store.

```php
$vaultody = new Vaultody\Sdk\Vaultody([
    'apiKey' => getenv('VAULTODY_API_KEY'),
    'apiSecret' => getenv('VAULTODY_API_SECRET'),
    'passphrase' => getenv('VAULTODY_PASSPHRASE'),
    'privateKeyFile' => '/etc/vaultody/private.pem',
    'vaultKeysFile' => '/var/lib/vaultody/vault-keys.json',
    'onSecurityEvent' => fn (array $event) => error_log('vaultody security event: ' . json_encode($event)),
    'logger' => $psr3Logger,    // optional: any object with warning(string $message)
]);

$event = $vaultody->webhooks->verify(file_get_contents('php://input'), getallheaders(), getenv('VAULTODY_WEBHOOK_SECRET'));
```

## Tests

```sh
php php/tests/run.php
```

A minimal runner (every `tests/*Test.php` returns name => closure), so the tests need nothing but PHP: every
shared vector set, unit tests, and the transport and every client method against a local mock gateway
(`tests/support/`, started with `php -S`) that checks request signatures, applies the gateway's replay rules
and signs its answers with the TEST-ONLY keys of the vectors. Each method's test sends the documented
request example and reads the documented answer and error examples of `contract/openapi.json`. Without
composer, `src/autoload.php` stands in for composer's autoloader.

Packagist reads a read-only mirror of this directory (`vaultody-sdk-php`). Release candidate:
`composer require "vaultody/sdk:^0.9@RC"`.
