# Changelog

One version for every package ([`VERSION`](VERSION); Python writes a release candidate the PEP 440 way,
`0.9.0rc1` for `0.9.0-rc.1`). A release needs a `## <version>` section here: it becomes the notes of the
GitHub release ([docs/RELEASING.md](docs/RELEASING.md)).

## Unreleased

## 0.9.0-rc.1

The first release candidate. The production root key is not embedded yet: responses without a signature are
accepted (`when-present`) and vault pins are marked unverified (trust on first use) until a release candidate
embeds it.

- The SDKs for Node.js (`@vaultody/sdk`, `@vaultody/verify`), Python (`vaultody-sdk`, `vaultody-verify`) and
  PHP (`vaultody/sdk`), for API version `2026-03-20`, under the Apache License 2.0.
- The `vaultody keys` command line ships with `@vaultody/sdk` (`npx @vaultody/sdk keys ...`); `keys verify` asks
  through the SDK's client.
- Pins given in configuration (`pinnedVaultKeys`, Python `pinned_vault_keys`) count as verified and are checked
  against every vault list like any pin; PHP has the option too now.
- A key added to a pinned vault, or a vault type change, stays refused until the client re-pins the vault:
  `npx @vaultody/sdk vault-keys accept --vault-id <vaultId>` shows the old and new fingerprints, and
  `--yes --expect type=…,ECDSA=…,EDDSA=…` re-pins only when the API still shows exactly those.
- A client with response-signing roots (the `roots` option, or a stable release that embeds the root) refuses an
  unsigned response from its first call; `when-present` is then ignored with a warning. Any response that carries a
  signature header, verified or not, latches its origin (the latch's `rootId` is `null` when it did not verify).
  Such a client makes one signed read before its first write to an origin that is not latched yet
  (`test-vectors/response-mode-v1.json`).
- `requireAddressPaths` (Python `require_address_paths`): on, `generateDepositAddress` refuses an address of a
  vault with MPC keys that comes without its derivation path (`path_missing`). Off until the API returns the paths.
- A response certificate valid for more than 3600 seconds is refused (`invalid`). The key-pair signed string
  carries the `x-api-key` on its second line, so a request signed for one API key is refused under another.
- PHP: a 64-byte P-256 signature from a signer is always read as IEEE P1363, also when it starts like DER.
- The one immediate retry after `address_derivation_conflict` or `vault_accounts_creation_failed` uses a new
  `x-api-nonce`; every other retry of a write keeps its nonce.
