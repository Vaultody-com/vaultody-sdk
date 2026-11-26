# vaultody-sdk (Python)

The official Vaultody SDK for Python, imported as `vaultody_sdk`. Python 3.10+. Dependencies:
`vaultody-verify` (same version), `httpx`, `cryptography`.

Release candidate: `pip install --pre vaultody-sdk`.

```python
from vaultody_sdk import Vaultody, FileSigner

with Vaultody(api_key, api_secret, passphrase, signer=FileSigner("private.pem")) as vaultody:
    for vault in vaultody.vaults.list_vaults(networkType="main"):        # every page, fetched as you go
        print(vault["id"], vault["name"])

    address = vaultody.assets_addresses.generate_deposit_address(
        vaultId=vault_id, blockchain="bitcoin", network="mainnet", label="Alice deposit", vaultAccountId=account_id,
    )
    address.item["address"], address.meta.address_checks   # [{"vaultId", "address", "status": "verified"}]

    transfer = vaultody.transactions.create_single_transfer(
        vaultId=vault_id, vaultAccountId=account_id, assetId=asset_id,
        fromAddress=sender, toAddress=recipient, amount="0.001", note="Payout 1842",
        feePriority="standard", context="order-1842",
    )
    transfer.item["transactionRequestId"]
```

`AsyncVaultody` takes the same arguments and has the same methods: a single item is awaited
(`await client.transactions.create_single_transfer(...)`), a list is an async iterator
(`async for vault in client.vaults.list_vaults(networkType="main")`).

## API methods

One method per documented operation of API version 2026-03-20 (the published OpenAPI document,
`contract/openapi.json`, plus `contract/pending/`), on both clients. Methods are grouped as the docs group
them, and named by the docs operationId in snake_case: `createSingleTransfer` is
`client.transactions.create_single_transfer`. CI (`scripts/coverage.mjs`) fails when a documented operation
has no method, or a method or its parameters differ from the document.

- **Arguments** are keyword arguments with the API's own field names, path, query and body fields together
  (`vaultId=`, `feePriority=`, `recipients=[{"address": ..., "amount": ...}]`): the SDK puts each one where
  the operation takes it and builds the `{"context", "data": {"item"}}` body. Before anything is sent they
  are checked against the documented operation: a field it does not document (`unknown_param`), a missing
  required one (`missing_param`), a wrong type (amounts are strings), a `limit` outside 1 to the largest
  page, or a value outside the list the document gives for that field of that operation, matched exactly
  (`networkType="MAIN"` is refused; `prepareStrategy` is `minimize-dust` for `create_multiple_transfer` but
  `minimize_dust` for `estimate_transaction_fee_by_asset_id`, as documented) raise `ParameterError`
  (`invalid_param`). `.param` names the field (`recipients[0].amount`); the value is never echoed. An
  optional field passed as `None` is left out. Nested objects are checked the same way. Answers are read
  leniently: an unknown value or field in a response is passed through.
- **`context=`**, on every method, is your own value that the API echoes back (`meta.context`).
- **A single item** comes back as `Item`: `.item` (`data.item` as sent, unknown fields kept) and `.meta`
  (request id, API version, context, whether the response signature verified, the address checks).
- **A list** comes back as `Pages` (`AsyncPages` on the async client): iterating it fetches page after
  page, each one signed, verified and checked like any call; nothing is sent before the first item is asked
  for. The page size is `limit=` or the operation's largest; `startingAfter=` starts mid-list;
  `max_items=` stops early. `.pages()` yields the pages themselves (`Page`: `.items`, `.has_more`,
  `.meta`), for what each answer says besides its items, such as the address checks of
  `list_addresses_by_vault_account_id`.
- **Types**: `vaultody_sdk.models` has a `TypedDict` for the arguments (`<Operation>Params`) and the answer
  (`<Operation>Result`, or `<Operation>Item` for a list) of every operation, checked field by field against
  the document in the tests; a field with documented values is a `Literal` of exactly those values. The
  package ships `py.typed`: mypy and pyright check the arguments of every call. CI runs `mypy --strict` over
  `tests/typecheck/public_api.py`, an application's calls against the installed package, including calls
  it must refuse.
- **Retries**: "read" operations (every GET, and the POSTs that change nothing) are retried re-signed;
  "write" operations are never signed twice (see "What every call does").

### vaults

| Method | Request | Returns | Retry |
|---|---|---|---|
| `list_vaults` | `GET /vaults/{networkType}` | items, cursor `id`; every page compared with the vault xpub pins | read |
| `list_vaults_by_asset_id` | `GET /assets/{assetId}/{blockchain}/vaults/{networkType}` | Item | read |
| `list_assets_by_vault` | `GET /vaults/{vaultId}/assets` | Item | read |
| `list_transactions_by_vault` | `GET /vaults/{vaultId}/transactions` | items, cursor `id` | read |

### vault_accounts

| Method | Request | Returns | Retry |
|---|---|---|---|
| `create_vault_account` | `POST /vaults/{vaultId}/vault-account` | Item | write |
| `list_vault_accounts` | `GET /vaults/{vaultId}/vault-accounts/details` | items, cursor `vaultAccountId` | read |
| `get_vault_account_by_id` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/details` | Item | read |
| `update_vault_account` | `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit` | Item | write |
| `add_asset_to_vault_account` | `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset` | Item; with `address=` the answer must name that address, with `label=` the new address is checked against the xpub | write |
| `list_assets_by_vault_account_id` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets` | items, cursor `assetId` | read |
| `list_transactions_by_vault_account` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions` | items, cursor `id` | read |

### assets_addresses

| Method | Request | Returns | Retry |
|---|---|---|---|
| `generate_deposit_address` | `POST /vaults/{vaultId}/{blockchain}/{network}/addresses` | Item; the address is checked against the xpub | write |
| `get_address_balance` | `GET /vaults/{vaultId}/addresses/{address}/balance` | items; one page only (cursor field not documented: `PaginationError("cursor_unknown")` if there is more) | read |
| `list_addresses_by_vault_account_id` | `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses` | items, cursor `addressId`; every address checked against the xpub | read |
| `list_supported_assets` | `GET /supported-assets` | items, cursor `assetId` | read |
| `validate_address` | `POST /info/{blockchain}/{network}/addresses/validate` | Item | read |
| `encode_xrp_address` | `GET /utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}` | Item | read |
| `decode_xrp_address` | `GET /utils/xrp/{network}/addresses/decode/{xAddress}` | Item | read |
| `tron_resource_overview` | `GET /vaults/{vaultId}/{blockchain}/{network}/{address}/overview` | Item | read |
| `tron_resource_management` | `POST /vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource` | Item | write |

### transactions

| Method | Request | Returns | Retry |
|---|---|---|---|
| `create_single_transfer` | `POST /vaults/{vaultId}/transaction-requests/single-transfer` | Item | write |
| `create_multiple_transfer` | `POST /vaults/{vaultId}/transaction-requests/multiple-transfer` | Item | write |
| `create_utxo_transfer` | `POST /vaults/{vaultId}/transaction-requests/utxo-transfer` | Item | write |
| `validate_utxo_transfer` | `POST /vaults/{vaultId}/transaction-requests/utxo-transfer/validate` | Item | read |
| `create_batch_transaction_request` | `POST /vaults/{vaultId}/transaction-requests/batch` | Item | write |
| `gas_sponsorship_transfer` | `POST /vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer` | Item | write |
| `create_tron_contract_interaction_request` | `POST /vaults/{vaultId}/transaction-requests/contract-interaction` | Item | write |
| `estimate_transaction_fee_by_asset_id` | `POST /vaults/{vaultId}/approximate-fee` | Item | read |
| `get_transaction_details` | `GET /vaults/{vaultId}/{blockchain}/transactions/{transactionId}` | Item | read |
| `get_transaction_request_details` | `GET /transaction-requests/{transactionRequestId}` | Item | read |
| `list_utxos` | `GET /vaults/{vaultId}/utxos` | items, cursor `utxoId` | read |

### api_keys (documented, not on production yet)

| Method | Request | Returns | Retry |
|---|---|---|---|
| `list_api_key_signing_keys` | `GET /api-keys/current/signing-keys` | items (at most two keys); takes no parameter. `check_signing_key()` compares them with the signer's key | read |

## What every call does

`Vaultody` (httpx.Client) and `AsyncVaultody` (httpx.AsyncClient) are thin: all logic is in `_core.py`, a core
without I/O that yields the I/O it needs (send, sleep, sign, rate-limit, read or write the pin store) and
that both clients drive. So both behave the same, by construction.

1. **Request.** The path and query are percent-encoded by the SDK (RFC 3986 unreserved kept), so what is
   signed is what goes on the request line. POST and PUT send `{"context"?, "data": {"item"}}` as compact
   UTF-8 JSON, at most 1 MiB. `x-api-version` is pinned (`API_VERSION`, 2026-03-20) and signed.
2. **Rate limit.** At most `max_requests_per_second` (5) calls in any one-second window, per client.
3. **Signing.** HMAC v2 with a fresh 16-byte nonce for every call (`x-api-sign-version: 2`). With a
   `signer`, also `x-api-keypair-sign` / `x-api-keypair-id` over the API key and the HMAC v2 fields:
   Ed25519 (64 bytes) or P-256 (DER; a 64-byte IEEE P1363 r || s from Web Crypto, Azure or a KMS is
   converted), checked against the signer's public key before sending.
4. **Response verification** (vaultody-verify), before the body is read (`test-vectors/response-mode-v1.json`).
   A signed response (any of the four `x-api-response-*` headers) is always checked; a failure raises
   `ResponseVerificationError` and is never retried, and a signed response with no root to check it with
   raises `ConfigurationError` `no_roots`. An unsigned response passes (`response_signature="when-present"`,
   the build default of release candidates, while production does not sign) until the origin has sent one
   signed response, verified or not: that answer latches the origin before anything is raised (the security
   event `response_signature_latched`, `rootId` `None` when it did not verify), and from then on the client
   is strict, also after a restart (the latch is kept in the vault key store). `response_signature="required"`
   (or `VAULTODY_RESPONSE_SIGNATURE=required`) is strict from the start. A client with response-signing roots
   (`roots`, or those a stable release embeds) is always `required`: a `when-present` given then is ignored,
   with one warning, and before its first write it makes one signed read (`GET /api-keys/current/signing-keys`,
   the key-pair check when a `signer` is set), so a write is never sent to an origin that does not sign.
   `client.response_signature` is the mode in force. The first unsigned response a client accepts raises
   the security event `{"type": "unsigned_response_accepted", "origin", "operationId"}` (once per client;
   `operationId` is `None` outside the API methods), then one warning on the `vaultody_sdk` logger.
5. **Retries** (`retry.py`, `test-vectors/retry-v1.json`). Reads (GET, and the POSTs that change
   nothing: `validate_address`, `validate_utxo_transfer`, `estimate_transaction_fee_by_asset_id`) are
   retried re-signed with backoff, each time with a new nonce. A write is never signed again once it may
   have reached the gateway: it is resent unchanged (the gateway's replay protection answers a duplicate
   with the first answer for 3 s), and only while the key pair is confirmed active through a signed
   `GET /api-keys/current/signing-keys` (re-checked every 10 minutes). Where the outcome can't be learned,
   `RequestOutcomeUnknownError` (with the nonce, timestamp and request id): check before sending again.
   Every retry of a write keeps its `x-api-nonce` and body, so the gateway's idempotency (per API key and
   nonce) sees one operation: a write signed again (its signature too
   old to resend) gets a fresh timestamp and signatures over the same nonce. The one exception is the one
   immediate retry of `address_derivation_conflict` / `vault_accounts_creation_failed`, which say nothing
   was executed: it is signed again with a new nonce and the same body (with the same nonce the gateway
   would only replay the 409), and later retries of that call keep the new nonce. A second conflict reaches
   you as a `ConflictError` (`retryable` true). A 409 `api_nonce_reused` is a `RequestSigningError`, never
   retried.
6. **Vault xpub pins and address checks.** Every `GET /vaults/{main|test}` answer is compared with the
   pins of the origin. A new vault is pinned `verified` (signed answer) or `unverified` (trust on first
   use); an unverified pin is confirmed by the first signed list. An xpub that differs, or disappears, an
   algorithm added to a pinned vault and a vault type change raise `VaultKeyChangedError` (the alarm; the
   security hook first, no pin changed, nothing returned). The last two are refused on purpose too: after
   you confirm a legitimate change with Vaultody, re-pin the vault with
   `npx @vaultody/sdk vault-keys accept --vault-id <id> --yes` (the Node command line, which edits the pin
   file every SDK shares; it shows the old and new fingerprints first) or `store.replace()`. Nothing else
   changes a pin. Pins you give in `pinned_vault_keys` count as `verified`, are compared with every vault
   list (signed or not) like any pin, so any difference is the alarm, are never written to the store, and
   take the place of the stored pin of their vault. Addresses
   returned by `generate_deposit_address`, `list_addresses_by_vault_account_id` and
   `add_asset_to_vault_account` are derived from the pinned xpub (the address derivation in vaultody-verify);
   a mismatch refuses the whole answer. Each address gets an entry `{"vaultId", "address", "status"}` in `meta.address_checks`, status `verified`, `unverified` or
   `not_verifiable` (no derivation path: SMART vaults, older rows; never reported as verified). With
   `require_address_paths`, an address `generate_deposit_address` answers without its derivation path, for a
   vault with MPC keys on a chain the SDK can derive, is refused instead: `AddressVerificationError` with
   `code` `path_missing` (after the `address_verification_failed` event). Each
   vault-list page reports every vault in `meta.vault_keys`, in answer order, as
   `{"vaultId", "status", "outcome"}`: `status` is its pin after the answer (`verified`, `unverified`) or
   `not_verifiable` (no MPC keys), `outcome` is `pinned`, `unchanged`, `upgraded` or `not_verifiable`.
7. **Typed errors** (`errors.py`, `test-vectors/envelope-errors-v1.json`): branch on the class and `code`.
   Every error class is exported from the package root (`vaultody_sdk.WebhookSignatureError` too), and is a
   `VaultodyError`. `ParameterError.param` names the field (`recipients[0].amount`), never its value.

## Options

| Option | Default | |
|---|---|---|
| `base_url` | `https://rest.vaultody.com` | https only; plain http only to 127.0.0.1, ::1, localhost |
| `signer` | none | `PemSigner`, `FileSigner`, `CallbackSigner` (any KMS; `digest_only=True` for a P-256 digest), `AsyncCallbackSigner` (AsyncVaultody) |
| `response_signature` | `$VAULTODY_RESPONSE_SIGNATURE`, else the build default (`when-present` for release candidates) | or `required`. Always `required` with response-signing roots |
| `pinned_vault_keys` | none | vault xpubs you give yourself, for this client's origin: `[{"vaultId", "type": "main" \| "test", "keys": {"ECDSA": xpub or None, "EDDSA": xpub or None}}]`, exactly those fields, at least one xpub, each vault once (else `ConfigurationError` `invalid_pinned_vault_keys`). They count as verified and are checked against every answer; vaults not listed are pinned in the store as usual |
| `vault_key_store` | file | `$VAULTODY_VAULT_KEYS_FILE`, else `~/.vaultody/vault-keys.json` (0600 in a 0700 directory, atomic writes under a lock; memory with a warning when that location can't be written). Any object with the `VaultKeyStore` methods |
| `on_security_event` | each event logged once as a warning, `Vaultody security event: {json}` | `f(event)`: `unsigned_response_accepted`, `response_signature_latched`, `response_verification_failed`, `vault_key_pinned`, `vault_key_verified`, `vault_key_changed`, `address_verification_failed`, each with exactly the fields of `SECURITY_EVENTS` (the same in every language: [`../../docs/vault-keys-file.md`](../../docs/vault-keys-file.md), `test-vectors/security-events-v1.json`). Never given a secret, an xpub or an address |
| `roots` | embedded | response-signing roots, for test environments only. Given, the client is strict from its first response |
| `require_address_paths` | `ADDRESS_PATHS_PUBLIC` (off while the API hides the paths) | `True`: refuse (`path_missing`) a new deposit address of a vault with MPC keys that comes without its derivation path. `True` or `False` only (else `ConfigurationError` `invalid_require_address_paths`) |
| `max_requests_per_second` | 5 | |
| `timeout` | 30 | seconds per attempt |
| `verify`, `proxy`, `transport` | | a CA bundle or `ssl.SSLContext` (TLS checks can't be switched off), an HTTP proxy, an httpx transport |

The API secret, passphrase and API key are kept in memory (HMAC needs them) and never appear in `repr`,
errors, events or logs.

## The pin file

`FileVaultKeyStore` reads and writes the vault keys file every SDK language shares
([`docs/vault-keys-file.md`](../../docs/vault-keys-file.md)): `{format, origins: {origin: {responseSignature,
vaults, audit}}}`, checked strictly on every read. A file it refuses raises `VaultKeyStoreError` with the
same `code` as in Node and PHP (`not_json`, `unknown_format`, `malformed`, `insecure_permissions`,
`not_regular_file`, `too_large`) and is never taken as empty. It writes the canonical bytes (sorted keys,
two-space indent) atomically, and a change holds `<file>.lock`, created exclusively and removed afterwards
(stale after 30 s, given up after 10 s with `locked`), the lock the Node and PHP stores take too.

## Webhooks

```python
event = vaultody_sdk.webhooks.verify(raw_body, request.headers, [new_secret, old_secret])
event.event, event.item
```

The raw body only; a typed event (`OutgoingTransactionEvent`, `IncomingTransactionEvent`,
`IncomingTransactionRevertedEvent`, or `UnknownWebhookEvent` for an event this version does not know).
Also `client.webhooks.verify`. A bad signature raises `vaultody_sdk.WebhookSignatureError` (`reason`:
`missing`, `malformed`, `mismatch`), a signed body that is no event `WebhookPayloadError`.

The scheme has no timestamp, and Vaultody may deliver the same event more than once. Before you act on an
event, check whether you already acted on it, keyed on what the event is about, as the developer docs'
Webhook Notifications page says:

- outgoing transaction events: `event.item["requestId"]` and `event.event`;
- incoming transaction events: `event.item["transactionId"]`, `event.item["address"]`, `event.event` and
  `event.item["currentConfirmations"]`. An internal transfer has no `transactionId`: use
  `parentTransactionId` and `operationId` in its place.

The SDK stores nothing.

## Modules

| Module | What | Vectors |
|---|---|---|
| `_core.py` | the core without I/O; `Vaultody` (`_client.py`) and `AsyncVaultody` (`_async_client.py`) drive it | all of them, through both clients |
| `signers.py` | signers, P-256 encodings, the local check | `request-full-v1.json`, `request-keypair-v1.json`, `p1363-der-v1.json` |
| `stores.py` | the pin store protocol, the file and memory stores | `vault-keys-file-v1.json` |
| `vault_keys.py` | the pin model and decisions | `vault-key-pins-v1.json` |
| `errors.py` | typed errors, `read_envelope` | `envelope-errors-v1.json` |
| `retry.py` | `decide_retry` | `retry-v1.json` |
| `pagination.py` | `Pages`, `AsyncPages` | `pagination-v1.json` |
| `request_target.py` | the request target | `path-encoding-v1.json` |
| `transport_errors.py` | may an httpx error's request have been sent | `transport-errors-v1.json` |
| `webhooks.py` | `verify` → typed event | `webhook-v1.json` |
| `_operations.py` | the operation table: where each parameter goes, retry class, paging; the argument checks | |
| `_resources.py` | the API methods of both clients, one namespace per docs group | |
| `models.py` | the request and answer `TypedDict`s of every operation | |
| `_surface.py` | what `scripts/coverage.mjs` reads: the methods of both clients and the operation table | |

## Tests

```bash
cd python
python3 -m venv .venv && .venv/bin/pip install -e './vaultody-verify' -e './vaultody-sdk' pytest
cd vaultody-sdk && ../.venv/bin/pytest -q
```

`tests/mock_gateway.py` is a mock API gateway on `httpx.MockTransport`: it checks HMAC v2, the key-pair
signature and the replay rules, signs responses with the TEST-ONLY roots of `test-vectors/v1.json`, and
can play a man in the middle (strip or alter signatures, swap an address, change an xpub, inject a 429 or
a 5xx, drop an answer after the request ran). Every client test runs on both clients (`conftest.py`).

`test_methods.py` calls every method with the docs' own example and answers with the docs' own answer
(`contract/openapi.json`), checking the request line, the body, the result, a documented error, paging, the
retry class and the refused arguments; `test_method_addresses.py` the address and vault key checks of the
methods that return them; `test_models.py` every model and the operation table against the document.
