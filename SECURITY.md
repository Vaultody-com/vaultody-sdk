# Security policy

The Vaultody SDKs verify signed API responses, sign API requests, pin vault xpubs to check deposit
addresses, and verify webhook signatures. A weakness in any of these can make a client trust data it
should not, so please report it privately.

## Reporting a vulnerability

Do not open a public issue, discussion or pull request. Report privately, by either:

- GitHub's **Report a vulnerability** button on this repository's **Security** tab (private vulnerability
  reporting);
- e-mail to [security@vaultody.com](mailto:security@vaultody.com).
  <!-- PLACEHOLDER: confirm that security@vaultody.com exists and is monitored before the repository goes public. -->

Include the package and version, the language and runtime version, what you observed, and the steps or a
proof of concept. Please do not test against accounts or data that are not yours.

We confirm that we received your report and keep you informed until a fix is released.
<!-- TODO before going public: the response times we commit to (acknowledgement, first assessment, fix). -->

## Supported versions

Until 1.0, only the latest release candidate receives fixes.
<!-- TODO before 1.0: the support window for stable versions. -->

## Scope

In scope: response signature verification, request signing (HMAC and key pair), the vault xpub pins and
address checks, webhook signature verification, retries of writes, the `vaultody` command line, and the
release pipeline of this repository.

Not a vulnerability: the keys, secrets and signatures in `test-vectors/` and in the test suites. They are
marked TEST-ONLY and public on purpose, so that every language can check the same bytes.
