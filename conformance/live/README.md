# Live conformance

The same cases, through every client (Node, Python sync, Python async, PHP), against a real Vaultody API in a
non-production environment: every read and every safe operation, the paging, the envelope, the typed results, the address
statuses and pins, and the checks an SDK makes before anything is sent. It complements the mock gateway
([`../mock-gateway`](../mock-gateway/README.md)), which covers what a live API can't be made to do on demand
(signed answers, tampering, dropped answers, write retries).

**Not part of CI.** It needs the credentials of a test client, which this public repository's CI never holds.
Run it by hand.

## Running it

```sh
VAULTODY_BASE_URL=https://<the environment's API host> \
  conformance/live/run.sh --env-file /path/to/credentials.env --out /path/to/private/dir
```

- **Credentials:** `VAULTODY_API_KEY`, `VAULTODY_API_SECRET`, `VAULTODY_PASSPHRASE`, from the environment or
  from `--env-file` (`NAME=value` lines, refused unless the file is mode 0600). They are passed to each runner by
  name, never on a command line, and never written or printed.
- **The API key:** a key of a test client in that environment, with no IP whitelist (or one that admits the runner) and no
  request-signing key pair. A test vault with addresses on a few chains gives the most coverage.
- **Refused:** the production API (`https://rest.vaultody.com`).
- **Output** (`--out`, default a new private temporary directory, mode 0700): `fixture.json`, one
  `results-<client>.json` per client, `summary.json`, and `report.md`, the table of every case and client.
- **Clients:** all four by default; name some to run only those (`run.sh ... node php`).

| Variable | Default | |
|---|---|---|
| `VAULTODY_CONFORMANCE_NODE` | `node` | Node.js 22+ |
| `VAULTODY_CONFORMANCE_PYTHON` | `python3` | Python 3.10+ with `python/vaultody-verify` and `python/vaultody-sdk` installed |
| `VAULTODY_CONFORMANCE_PHP` | `php` | PHP 8.2+, or `docker:<image>` (such as `docker:php:8.4-cli`): only the repository is mounted, read only; the fixture goes in on stdin and the results come back on stdout |
| `VAULTODY_CONFORMANCE_FIXTURE` | discovered | a fixture file to use instead of `discover.js` |
| `VAULTODY_CONFORMANCE_TRANSACTION_REQUEST_ID` | none | a transaction request of the API key's client, for `getTransactionRequestDetails` (no list operation returns one) |
| `VAULTODY_CONFORMANCE_CASES` | all | only these case ids, comma-separated (to repeat a few) |
| `VAULTODY_CONFORMANCE_RPS` | SDK default (5) | the clients' own request rate (discovery included) |
| `VAULTODY_CONFORMANCE_BURST` | 0 (off) | the 429 check: that many reads at once, then one write (below) |
| `VAULTODY_CONFORMANCE_RUN_ID` | the time | in the labels of the addresses a run creates |
| `VAULTODY_CONFORMANCE_PAUSE` | 2 | seconds between clients |

## What it does

1. **`discover.js`** finds what the cases need in the API key's own data, through the Node SDK, reads only:
   the first test vault the key can read (a key limited to some vaults still lists them all; a vault that answers
   `api_key_not_allowed_for_wallet` is skipped, on every page of the list), its first vault account, addresses on
   Ethereum, Bitcoin, Tron and XRP, the ETH and BTC assets, a UTXO and a transaction. It writes `fixture.json`
   (ids and addresses, never a secret). A value the data doesn't have is left out, and the cases that need it are
   skipped.
2. **`run-node.js`, `run_python.py --client sync|async`, `run-php.php`** run [`cases.json`](cases.json), in
   order, one call at a time. Each counts its own HTTP requests through the client's supported hook (Node
   `unsupported.fetch`, Python `transport=`, PHP `httpClient`) and records what happened. Params with `$name`
   come from the fixture, `@case.field` from an earlier answer.
3. **`report.js`** judges every client by the same rules:
   - an item or list: answered, with a `requestId`, `apiVersion` 2026-03-20 and a response signature
     `verified` or `absent`, and the case's field present;
   - a list: no item twice; where `everyItem` is set, the SDK's own iterator at a small page size returns
     exactly the items of one page of 50;
   - an address answer: every address has a status (`verified`, `unverified` or `not_verifiable`);
   - a `listVaults` answer: one per-vault pin result `{ vaultId, status, outcome }` per vault on every page;
   - a negative case: the documented error class and code (or reason), with the documented number of requests
     (0: refused before sending; 1: never retried).

## The cases

| Class | Operations |
|---|---|
| read (GET) | every GET: `listVaults` (main and test), `listVaultsByAssetId`, `listAssetsByVault`, `listTransactionsByVault`, `listVaultAccounts`, `getVaultAccountById`, `listAssetsByVaultAccountId`, `listTransactionsByVaultAccount`, `getAddressBalance`, `listAddressesByVaultAccountId`, `listSupportedAssets`, `encodeXrpAddress`, `decodeXrpAddress`, `tronResourceOverview`, `getTransactionDetails`, `getTransactionRequestDetails` (and an unknown id: a typed 404), `listUtxos`, `listApiKeySigningKeys` |
| read-post | `validateAddress`, `estimateTransactionFeeByAssetId`, `validateUtxoTransfer` (a dry run: nothing created, no UTXO reserved) |
| safe-write | `generateDepositAddress` (a test-network address labelled `sdk-conformance-<client>-<run>`), `addAssetToVaultAccount` (the asset an address already holds, on that address: the API's "already added" answer, which writes nothing) |
| negative | a wrong passphrase (a typed `AuthenticationError`, sent once); an invalid enum and an unknown param (`ParameterError`, nothing sent); response-signing roots against an environment that does not sign (`rootsOnUnsignedOrigin`: a client given the vectors' TEST-ONLY root refuses the unsigned answer as `ResponseVerificationError` `missing`, sent once, with its own in-memory pin store); the 429 burst (off by default) |

**Not run live**, because funds move or a phone approval is needed, or a real account would change:
`createVaultAccount`, `updateVaultAccount`, `tronResourceManagement`, and the six transfer operations
(`createSingleTransfer`, `createMultipleTransfer`, `createUtxoTransfer`, `createBatchTransactionRequest`,
`gasSponsorshipTransfer`, `createTronContractInteractionRequest`). Each language runs every one of them against
the mock gateway with the API reference's examples (`node/packages/sdk/test/methods.test.js`,
`python/vaultody-sdk/tests/test_methods.py`, `php/tests/ApiMethodsTest.php`), and the write retries and
"outcome unknown" against its replay rules (`pipeline-retry.test.js`, `test_client_retries.py`,
`TransportTest.php`, `test-vectors/retry-v1.json`).

## The 429 check

`VAULTODY_CONFORMANCE_BURST=N` sends N reads from 4 workers (PHP: one after another) with the client's own
limit lifted, then one deposit address in the same second. It passes when every read is retried to success
after a 429 and the address is created exactly once (one address with its label, one nonce). Without a 429 it
is a SKIP.

Keep it off on a small test environment: there a burst big enough for a 429 can make the API answer 500, 502
or 503 before any 429 comes back. If a case fails with `ServerError`, let the environment recover before the
next client. The plan's per-minute quota is reached at the SDK's default rate anyway,
so a 429 retry often shows up in the ordinary cases ("retried after 429" in the report).

## Response signatures and pins

Until the environment signs responses, every answer is `absent` and accepted in the
SDKs' default `when-present` mode, and each client raises `unsigned_response_accepted` once (each client
instance: the wrong-passphrase case makes a second one) with one warning. A client given response-signing roots
is strict instead, from its first answer (`negative.rootsOnUnsignedOrigin`). Vault xpubs are pinned from
`listVaults` only when the API shows `mpcKeys`; while it hides them (with the address path fields), every vault
is `not_verifiable`, nothing is pinned, and every address is `not_verifiable` too.

Every client starts from the same pin file, `pins-<client>.json`, seeded with the vectors' canonical
`two_origins` document ([`docs/vault-keys-file.md`](../../docs/vault-keys-file.md)): pins and a latch under the
production and a loopback origin, nothing under the origin of the run. Each SDK reads it on its first call and on every
vault list and address answer, so one that can't read the shared layout fails its cases. The report's last
table puts side by side, per client, the file after the run (mode, hash), what the client's own store reads
back for each origin (latch, pins: type, status, algorithms, never an xpub), the per-vault results of each
`listVaults` case, and the unsigned notice (count, operations, fields), with whether all four agree.
