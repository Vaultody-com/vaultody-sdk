# The vault keys file (v1)

Where the SDKs keep the vault xpub pins and the response-signature latch between runs. Node, Python and PHP
read and write exactly this layout, so one file can be shared by clients in different languages.

- **Schema:** [`vault-keys-file-v1.schema.json`](vault-keys-file-v1.schema.json) (JSON Schema 2020-12).
- **Vectors:** [`../test-vectors/vault-keys-file-v1.json`](../test-vectors/vault-keys-file-v1.json): valid and
  invalid files with the result every SDK must give, the canonical bytes a writer produces, and file-system
  cases. Each language runs them; [`../conformance/interop/run.mjs`](../conformance/interop/run.mjs) (CI job
  `vault-keys-interop`) checks that a file written by each SDK reads the same in the other two, that all three
  write the same bytes, and that writers in all three languages can share one file at the same time.
- **Where:** `VAULTODY_VAULT_KEYS_FILE` in every language. Node and Python default to
  `~/.vaultody/vault-keys.json`; PHP needs the path set (`vaultKeysFile`), because every PHP-FPM request is a
  new process.

## Layout

```json
{
  "format": "vaultody vault keys v1",
  "origins": {
    "https://rest.vaultody.com": {
      "audit": [],
      "responseSignature": { "latchedAt": 1794201002, "rootId": "vaultody-response-root-2026" },
      "vaults": {
        "6630f1c2a9e4b5d7c8e9f0a1": {
          "firstSeenAt": 1794201002,
          "keys": { "ECDSA": "xpub661My…", "EDDSA": null },
          "status": "verified",
          "type": "main",
          "vaultId": "6630f1c2a9e4b5d7c8e9f0a1",
          "verification": { "rootId": "vaultody-response-root-2026", "timestamp": 1794201000 },
          "verifiedAt": 1794201002
        }
      }
    }
  }
}
```

| Field | Value |
|---|---|
| `format` | exactly `vaultody vault keys v1`; any other tag is refused (no other version exists) |
| `origins` | API origin → entry. The origin is `scheme://host[:port]`, host lowercase, no default port |
| `responseSignature` | **the latch**: `null`, or `{ latchedAt, rootId }` once a response carrying a response signature (any of the four `x-api-response-*` headers) came from the origin, whether it verified or not. `rootId` is the root that verified it, or `null` when it did not (refused, or no root to check it with). Set once; a client never clears it. From then on an unsigned response from the origin is refused (`../test-vectors/response-mode-v1.json`) |
| `vaults` | vault id → pin; a pin's `vaultId` equals its key |
| pin `type` | `main` or `test` |
| pin `keys` | `{ ECDSA, EDDSA }`: the xpub as first seen in `GET /vaults/{main\|test}`, or `null`; at least one xpub |
| pin `status` | `verified` (a signed answer showed these xpubs: `verifiedAt` and `verification: { rootId, timestamp }` set) or `unverified` (trust on first use from an unsigned answer: both `null`) |
| `audit` | `{ vaultId, at, reason, removed }` for every explicit replacement or removal of a pin (administrative only, such as `npx @vaultody-com/sdk@next vault-keys accept`; the transport never writes one) |

Times are Unix seconds, JSON integers (no fraction, no exponent, at most 2^53 − 1). Every field is required
and no other field is allowed, at any level.

Pins given in a client's configuration (Node and PHP `pinnedVaultKeys`, Python `pinned_vault_keys`) are never
written here. They count as verified and take the place of this file's pin of the same vault for that client.

A pin changes only by an explicit replacement after the client confirmed the change with Vaultody: an xpub that
changed or is gone, a key the vault did not have, or a vault type change all stay refused until then.
`npx @vaultody-com/sdk@next vault-keys accept --vault-id <vaultId>` shows the pinned and the new fingerprints, and with
`--yes --expect <the type and fingerprints it showed>` replaces the pin, when the API still shows exactly those, and
appends an `audit` entry.

## Reading: what is refused

A file that is refused is never treated as empty (an empty store would pin whatever xpub comes next). The
store raises `VaultKeyStoreError` with one of these codes, the same in every language:

| Code | When |
|---|---|
| `not_json` | not strict UTF-8 JSON (a byte-order mark, invalid UTF-8, a syntax error, an empty file) |
| `unknown_format` | the top level is not an object, or `format` is not exactly the tag |
| `malformed` | anything else the schema does not allow: an unknown field, a missing one, a wrong type, a bad status, a time that is not an integer, a pin under another vault id, the old per-language layouts |
| `insecure_permissions` | POSIX: the file is writable by the group or by others (`mode & 022`); `chmod 600` fixes it |
| `not_regular_file` | the path is a symbolic link, a directory or another special file |
| `too_large` | over 16 MiB |

The store's other codes, the same in every language: `unreadable` (an I/O error reading), `unwritable`,
`locked` (the lock was held for 10 seconds), `invalid_pin` (a pin or latch the file can't hold, handed to the
store) and `store_conflict` (a pin changed in the store between the client's read and its write, by another
writer: the answer is refused, and calling again reads afresh).

A missing file is an empty store. Reading takes no lock.

## Writing

- **Only on a change**: a client that only reads never creates the file.
- **Canonical bytes**: UTF-8, object keys sorted at every level, two-space indent, `": "` between key and
  value, `/` and non-ASCII characters not escaped, one newline at the end. Every SDK writes the same bytes for
  the same content (the vectors' `canonical` cases).
- **Atomic and private**: the directory is created with mode 0700 if missing; the content goes to a temporary
  file in the same directory with mode 0600, is synced to disk, and is renamed over the file.
- **One writer at a time, across languages**: a read-change-write holds `<file>.lock`, created exclusively
  (`O_CREAT|O_EXCL`, mode 0600, holding the process id) and removed afterwards. A lock file older than 30
  seconds was left by a process that died, and is removed. A writer waits up to 10 seconds, then fails with
  `locked`. No `flock()`: Node.js has none, and a shared file needs one protocol.
- **Fallback**: when the default location (Node, Python) can't be written, pins stay in memory for the life
  of the process, with a warning. An explicit path never falls back.

## The client behaviour that goes with it (every language)

- **Per-vault results of `listVaults`**: each answer page carries one entry per vault, in answer order: Node
  `meta.vaultKeys`, Python `meta.vault_keys`, PHP `$page->meta->vaultKeys`, each entry
  `{ vaultId, status, outcome }`. `status` is the vault's pin after the answer (`verified`, `unverified`) or
  `not_verifiable` (no MPC keys: SMART, AUTOMATION); `outcome` is what the answer did to the pin: `pinned`,
  `unchanged`, `upgraded` or `not_verifiable`. An alarm (an xpub changed or gone, an algorithm added, a type
  changed) returns no result: `VaultKeyChangedError`, with one `{ vaultId, algorithm, reason, pinned, seen }`
  per alarm (hashes, never an xpub), after the `vault_key_changed` security event.
- **Address checks**: every answer that returns vault addresses carries one entry per address, in answer
  order: Node `meta.addressChecks`, Python `meta.address_checks`, PHP `$result->meta->addressChecks`, each
  `{ vaultId, address, status }` with status `verified`, `unverified` or `not_verifiable`. A vault list that
  lists a vault under the other type (`/vaults/main` vs `/vaults/test`), or can't be read, is refused with
  `ApiError` (no code).
- **Security events**: the hook (Node `onSecurityEvent`, Python `on_security_event`, PHP `onSecurityEvent`) gets
  only these types, each with exactly these fields, in every language
  ([`../test-vectors/security-events-v1.json`](../test-vectors/security-events-v1.json); Node
  `SECURITY_EVENTS`, Python `SECURITY_EVENTS`, PHP `SecurityEvents::EVENTS`). A field that is unknown is
  `null` (Python `None`). No event carries a secret, an xpub or an address. The hook is called before the
  error is thrown, and an exception from it never hides the error: it is logged once as a warning, `the
  security event hook raised on <type>; ...`. **With no hook**, every event is logged once at warning level
  as `Vaultody security event: ` and its JSON (compact, the fields in this order); with a hook nothing is
  logged for it (`unsigned_response_accepted` also has its own warning, hook or not). Node logs through
  `logger.warn`, Python through the `vaultody_sdk` logger, PHP through `logger->warning()` (`error_log()` by
  default).

  | Type | Fields | When |
  |---|---|---|
  | `unsigned_response_accepted` | `type`, `origin`, `operationId` | `when-present` mode, before the latch: the first unsigned response a client accepts, once per client; then one warning is logged (Node `logger.warn`; Python the `vaultody_sdk` logger; PHP `logger->warning()`, default `error_log()`). `operationId` is `None` in Python for a call outside the API methods |
  | `response_signature_latched` | `type`, `origin`, `rootId`, `latchedAt` | the first response from an origin that carries a response signature, verified or not (raised before its error); the values are the latch as stored, `rootId` `null` when it did not verify |
  | `response_verification_failed` | `type`, `origin`, `operationId`, `status`, `reason` | a response fails its signature check; `ResponseVerificationError` follows (no event for a setup error such as no root keys) |
  | `vault_key_pinned` | `type`, `origin`, `vaultId`, `status` | a vault pinned for the first time (`verified` or `unverified`) |
  | `vault_key_verified` | `type`, `origin`, `vaultId`, `status` | an unverified pin confirmed by a signed vault list (`verified`) |
  | `vault_key_changed` | `type`, `origin`, `alarms` | a vault list differs from a pin; `VaultKeyChangedError` follows |
  | `address_verification_failed` | `type`, `origin`, `operationId`, `vaultId`, `code` | any address check that refuses an answer; `AddressVerificationError` follows. The codes, the same in every language (the vector's `addressCodes`): `mismatch` (not derived from the pinned xpub; not the address sent; an item on another chain than asked), `network_mismatch` (an item on another network than asked, or a network that does not go with the vault type), `invalid`, `unsupported`, `unknown_vault`, `path_missing` (with `requireAddressPaths` on, `generateDepositAddress` answered an address without its derivation path for a vault with MPC keys) |
