# Releasing

Every package is released together, at the one version in [`VERSION`](../VERSION):

| Registry | Package | How |
|---|---|---|
| npm | `@vaultody-com/verify`, then `@vaultody-com/sdk` | trusted publishing (OIDC) with provenance; dist-tag `next` for a release candidate |
| PyPI | `vaultody-verify`, then `vaultody-sdk` | trusted publishing (OIDC) with PEP 740 attestations |
| Packagist | `vaultody/sdk` | `php/` and the tag pushed to the read-only mirror `Vaultody-com/vaultody-sdk-php`; Packagist reads the tag |
| GitHub | release `v<version>` | every package, `SHA256SUMS`, the build provenance attestation; notes from [`CHANGELOG.md`](../CHANGELOG.md) |

The manual [`release`](../.github/workflows/release.yml) workflow does all of it, on a signed tag. Nothing is
published from a laptop, except each npm package's very first version ([below](#the-first-publish)).

**Release candidates only (`X.Y.Z-rc.N`, starting at `0.9.0-rc.1`) until the [order](#order-with-the-server-side-work)
below is done.** The production root is embedded since `0.9.0-rc.1`; the workflow refuses a stable version while no
production root is embedded.

## Steps

1. **Version pull request.**
   - `node scripts/version.mjs set 0.9.0-rc.1` writes `VERSION` and every package: Node and PHP as written,
     Python in its PEP 440 form `0.9.0rc1`. `node scripts/version.mjs check` compares them.
   - Add a `## 0.9.0-rc.1` section to `CHANGELOG.md`: its text becomes the release notes.
   - A code owner reviews; merge to `main`. The `release-dry-run` job on the pull request lists what a release of it
     would still refuse.
2. **Signed tag**, by a release manager whose SSH key is in [`.github/release-signers`](../.github/release-signers),
   on the merged commit:

   ```sh
   git fetch origin
   git -c gpg.format=ssh -c user.signingkey="$HOME/.ssh/<key>.pub" tag -s v0.9.0-rc.1 -m v0.9.0-rc.1 origin/main
   git push origin v0.9.0-rc.1
   ```

   A pushed `v*` tag is never moved or deleted. A version whose release fails for a reason in the code is
   not reused: the fix goes out as the next `rc`.
3. **Run** Actions → release → *Use workflow from* **Tags: v0.9.0-rc.1**, version `0.9.0-rc.1`, what `all`
   (`root_fingerprint` only for a stable version), or:

   ```sh
   gh workflow run release.yml --ref v0.9.0-rc.1 -f version=0.9.0-rc.1 -f what=all
   ```

4. **Approve** each environment when the run waits on it: `npm-release`, `pypi-release`, `packagist-release`.
5. **Check:** `npm view @vaultody-com/sdk dist-tags`, `pip download --no-deps vaultody-sdk==0.9.0rc1`,
   `composer show --all vaultody/sdk`, the GitHub release, and
   `gh attestation verify <a downloaded file> --repo Vaultody-com/vaultody-sdk`.

If the run stops after something was published, use **Re-run failed jobs**: it keeps the run's packages, a
version already on npm or PyPI is skipped, and the mirror's tag is left as it is when it holds the same tree.

## Who does what

| Who | What |
|---|---|
| The developer releasing | the version pull request; starts the run |
| A code owner ([`.github/CODEOWNERS`](../.github/CODEOWNERS)) | reviews the version pull request and every change to `.github/`, the roots, the vectors and the contract |
| Release managers (their keys in `.github/release-signers`) | sign and push the tag |
| Required reviewers of each environment | approve `npm-release`, `pypi-release`, `packagist-release`; never the person who started the run |
| A registry owner (2FA) | the first npm publish of each package |
| An organisation admin | the trusted publishers, the environments, the mirror and its deploy key |

## What stops a release

The `preflight` job ([`scripts/release/guard.mjs`](../scripts/release/guard.mjs)) refuses, before anything else runs:

- a run that is not on the tag `v<version>`, an unsigned or lightweight tag, a tag not signed by a key in
  `.github/release-signers` on `main`, or a tag not on `main`;
- a private repository: npm provenance and GitHub attestations need a public one;
- a `version` input other than `VERSION`, or any package that says another version;
- an embedded root that is invalid, differs between the languages, or is a test root, in any release;
- no `LICENSE` (in the repository and in each package) or no licence in a manifest; `"private": true` or
  `Private :: Do Not Upload` still set; an npm `repository` other than this repository; no `CHANGELOG.md` section;
- build defaults that differ between the languages (`DEFAULT_RESPONSE_SIGNATURE`, `ADDRESS_PATHS_PUBLIC`: Node
  `node/packages/sdk/src/defaults.js`, Python `vaultody_sdk/_defaults.py`, PHP `Transport`), in any release;
- for a stable version also: no current root embedded, a `root_fingerprint` input that is not that root,
  an operation still in `contract/pending/`, a `DEFAULT_RESPONSE_SIGNATURE` other than `required`, or
  `ADDRESS_PATHS_PUBLIC` not `true`.

Then `test.yml` (tests, vectors, coverage, interop) and `secret-scan.yml` (gitleaks over the history) must
pass, and the build refuses a package with tests, vectors, a secret or a test root key in it
([`check-packages.mjs`](../scripts/release/check-packages.mjs), gitleaks over the unpacked packages).
`node scripts/release/guard.mjs --report` shows what a release of the current commit would refuse.

## The first publish

npm has no pending publisher: a package must exist before its trusted publisher can be added. Once per
npm package:

1. Run the workflow with what `build-only`. Download the run's `release` artifact, then
   `sha256sum --check SHA256SUMS` and `gh attestation verify npm/vaultody-com-verify-0.9.0-rc.1.tgz --repo Vaultody-com/vaultody-sdk`.
2. A registry owner publishes both tarballs by hand, with 2FA:
   `npm publish vaultody-com-verify-0.9.0-rc.1.tgz --access public --tag next`, then the same for `vaultody-com-sdk-0.9.0-rc.1.tgz`.
   These two versions have no provenance.
3. An organisation admin adds the trusted publisher to each package and sets "Require 2FA and disallow tokens".
4. Run the workflow again on the same tag with what `all`, the same day: npm skips the two versions when it
   holds the very tarballs this run builds (and stops otherwise); PyPI (pending publishers) and Packagist
   publish, and the GitHub release follows.

what `testpypi` sends only the Python packages to TestPyPI, to try the PyPI side first.

## Order with the server-side work

| Step | Needs | What can be released |
|---|---|---|
| Registries | the registries, the trusted publishers and the release environments | a release candidate |
| Production root key (response signing): **done**, `root-prod` embedded since `0.9.0-rc.1` | the root's PEM and fingerprint in all three languages, in one pull request | a release candidate that embeds it, published **before** production starts signing responses, with time for clients to upgrade: a version with empty slots fails closed on every signed response. A release candidate with the root stays `when-present` (it bridges: unsigned answers until the first signed one, which latches the origin); a stable version with it is strict at once |
| Key-pair request signing live on production | `listApiKeySigningKeys` published: `contract/` refreshed, `contract/pending/` empty | a stable version (the guard refuses one while anything is pending) |
| Vault xpub fields shown on production | the xpub and derivation fields, with `blockchain`/`network` on the address answers, no longer hidden; then `ADDRESS_PATHS_PUBLIC` set to `true` in all three languages (`generateDepositAddress` then requires the path) | `1.0.0` (the release manager checks that the fields are live; the guard checks the constant) |
| `1.0.0` | all of the above, production signing responses; the stable release commit sets `DEFAULT_RESPONSE_SIGNATURE` to `required` and `ADDRESS_PATHS_PUBLIC` to `true` in all three languages, together with the root | stable, with `root_fingerprint` = the fingerprint published to clients |

**The release-candidate window.** A release candidate with the root is only as strong as its latch. Whatever strips
the signature from every response keeps the client from ever latching, and a client whose latch lives in memory
(`MemoryVaultKeyStore`) starts unlatched in every new process. That is accepted for release candidates only, so the
window stays short, in this order:

1. production signs every response;
2. a short window in which release-candidate clients latch;
3. stable `0.9.0`: `required` by default, strict from the first call (with the other stable conditions above).
