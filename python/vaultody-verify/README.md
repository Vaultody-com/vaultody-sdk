# vaultody-verify (Python)

Checks that a Vaultody API response came from the Vaultody API gateway unchanged, and that it answers
the request you actually sent.

Cloudflare terminates TLS in front of the Vaultody API, so TLS alone doesn't prove where a response came
from. The gateway signs every response instead. A root key held in a hardware security module certifies
each gateway pod's short-lived signing key, and the pod signs every response together with the request
it answers. This package checks both signatures against roots it has pinned.

Python 3.10+. The only dependency is `cryptography`; `requests` support is an optional extra.

```bash
pip install './python/vaultody-verify[requests]'      # from a checkout; the package is not on PyPI
```

## Usage with `requests`

```python
import requests
from vaultody_verify import ResponseSignatureError, verify_requests_response

resp = session.post(url, data=body_bytes, headers=signed_headers)   # your usual signed API call

try:
    verify_requests_response(resp)          # raises unless the response is genuine
except ResponseSignatureError as error:
    log.error("rejected Vaultody response: %s", error)   # error.reason, e.g. "invalid"
    raise

data = resp.json()                          # parse only after it verified
```

`verify_requests_response` uses what `requests` really sent: `resp.request.method`,
`resp.request.path_url`, `resp.request.body` and the `x-api-sign` and `x-api-keypair-sign` headers, with `resp.status_code`,
`resp.headers` and `resp.content`. Send the body as `bytes` or `str` (including `json=`). A file or
generator body is gone by the time the response arrives, so it can't be verified and raises `TypeError`.

## Any other HTTP client

```python
from vaultody_verify import verify_response

result = verify_response(
    request={
        "method": "POST",
        "url": "/vaults/6630f1c2a9e4b5d7c8e9f0a1/bitcoin/mainnet/addresses?context=yes",  # path + query as sent
        "body": request_body_bytes,     # exactly the bytes sent; None if there was no body
        "api_sign": x_api_sign,         # the x-api-sign header you sent; None if none
        "keypair_sign": x_api_keypair_sign,  # the x-api-keypair-sign header you sent; None if none
    },
    response={
        "status": 201,
        "headers": response_headers,    # dict or any Mapping; names are matched case-insensitively
        "body": raw_response_bytes,
    },
)
result.verified, result.key_id, result.root_id, result.timestamp
```

- `url` is the path and query exactly as they went on the wire, percent-encoding untouched. It is not a
  full URL. The query is everything after the first `?`.
- Bodies are raw bytes. A `str` is taken as UTF-8.
- If you compress request bodies yourself, pass the uncompressed bytes. The gateway hashes the body after
  removing Content-Encoding.

## Verify the raw bytes before parsing

The signature covers the exact response body bytes. Verify those bytes, then parse them. Don't parse
JSON and serialise it again, and don't read fields from a response that failed: until it verifies, an
address in it may be an attacker's. Use `resp.content`, not `resp.text` or `resp.json()`.

## Strict by default

`require_response_signature=True` is the default: a response without a signature raises
`ResponseSignatureError("missing")`.

`require_response_signature=False` exists for rollout only. It tolerates exactly one thing: a response
with **none** of the four signature headers, which returns `VerificationResult(verified=False, reason="missing")`.
A response with some headers stripped, or with any other problem, still raises. An attacker who can
alter responses can also strip all four headers, so non-strict mode protects nothing; switch to strict
as soon as signing is on.

## Roots and rotation

The package embeds the production roots in `vaultody_verify/roots.py` as SubjectPublicKeyInfo PEM, each
next to its fingerprint: the lowercase hex SHA-256 of the key's DER, which is also the `rootId` that
certificates name. At import, the package checks every embedded PEM against its fingerprint and refuses
to load on a mismatch.

There are two slots, **current** and **next**, so a root can be rotated without breaking clients:

1. Vaultody creates a new root and publishes it as **next**, in a helper release and by email, ahead of
   time. Clients upgrade, and from then on they trust both roots.
2. The gateway switches to signing pod certificates with the new root.
3. A later release drops the old root and pins a new **next**.

To compare the embedded fingerprints with the ones Vaultody sent you:

```bash
python -c "from vaultody_verify.roots import embedded_fingerprints; print(embedded_fingerprints())"
openssl pkey -pubin -in root.pem -outform DER | shasum -a 256     # fingerprint of a PEM you were given
```

`roots=` replaces the embedded roots, for example to trust a test environment's root or a key you
received out of band. It takes a list of PEM (`str` or `bytes`), DER `bytes`, `cryptography` EC
public keys, or a mapping such as `{"current": pem, "next": pem}`. A PEM or DER root must be an
uncompressed, named-curve P-256 SPKI, and its id is the SHA-256 of those exact DER bytes; a compressed
point or explicit curve parameters raise `ConfigurationError`:

```python
verify_requests_response(resp, roots=[QA_ROOT_PEM])
```

**This build embeds no production roots yet.** They are filled in at release. Until then a signed
response checked without `roots=` raises `ConfigurationError`, so a missing root can never let a signed
response through unchecked. The roots are looked up only once a response carries a signature: in
non-strict mode a response with no signature headers at all still returns `verified=False`,
`reason="missing"` without any root, and in strict mode it raises `ResponseSignatureError("missing")`.
A malformed `roots=` value raises `ConfigurationError` at once, signed response or not.

## Errors

`ResponseSignatureError` means: don't trust this response. `.reason` is one of:

| reason | meaning |
|---|---|
| `missing` | a signature header is absent or empty (strict mode, or only some headers missing) |
| `invalid` | malformed headers or certificate, a certificate valid for more than an hour (`notAfter - notBefore` over 3600 seconds), or a signature that does not verify for this request and response |
| `expired` | the signature time is outside the certificate window, or the local clock is more than `max_clock_skew_seconds` (300) past it |
| `unknown_root` | the certificate names a root that is not pinned (for example one already rotated out) |
| `request_unbound` | genuine, but the gateway did not read the request body (over 1 MB, or the upload was cut short), so the response is not bound to the body you sent |
| `unsupported_version` | a signature version this package does not know; upgrade it |

`ConfigurationError` means the verifier is set up wrong (no roots for a signed response, or an unusable
root key). It says
nothing about the response and is deliberately not a `ResponseSignatureError`. Wrong argument types raise
`TypeError`. An `url` that isn't a path raises `ValueError`. All errors this package raises on purpose
derive from `VaultodyVerifyError`.

Other options: `now=` (Unix seconds, for tests) and `max_clock_skew_seconds=` (default 300).

## Signing requests

`vaultody_verify.keys` builds the authentication headers of an API request: `x-api-sign` (HMAC v2, with
a fresh `x-api-nonce` every time) and, for an API key with a request-signing key pair, `x-api-keypair-sign`
and `x-api-keypair-id`. The strings and signatures are the gateway's, pinned by
`test-vectors/request-hmac-v2.json`, `request-full-v1.json` and `request-keypair-v1.json`. The key-pair string
is `vaultody-request-keypair-v1`, the `x-api-key` the request is sent with, then the HMAC v2 fields
(timestamp, method, path, `x-api-version`, passphrase, nonce, query, body), joined with `\n`: two API keys
may hold the same public key, and a request signed for one is refused under the other.

```python
from vaultody_verify import read_signing_key, sign_api_request, sign_hmac_v2_request

credentials = {"apiKey": api_key, "apiSecret": api_secret, "passphrase": passphrase}
request = {"method": "POST", "path": "/vaults/.../addresses", "query": "", "body": body_text, "apiVersion": "2026-03-20"}

headers = sign_hmac_v2_request(credentials, request)               # an API key without a key pair
key = read_signing_key(open("private.pem").read())                 # Ed25519 or P-256, PKCS#8 or SEC1 PEM
headers = sign_api_request(key, credentials, request)              # with the key pair
```

- The API secret must be the base64 text the dashboard shows (padding optional). Anything else raises
  `UsageError` with `code == "invalid_api_secret"` before anything is signed; the secret is never in a
  message. An API key that is not one line of text raises `UsageError` before the key pair signs.
- `p1363_to_der(signature)` turns a P-256 signature from Web Crypto, Azure Key Vault or a KMS that returns
  IEEE P1363 (r || s, 64 bytes) into the DER the gateway requires (`SignatureFormatError` with
  `invalid_length` or `zero_integer` otherwise; `test-vectors/p1363-der-v1.json`).
- `read_signing_keys_response(status, body, fingerprint)` reads a verified answer of
  `GET /api-keys/current/signing-keys` and says whether your key is `active`, `inactive`, `not_listed`, or
  the request was `refused` (`test-vectors/signing-keys-v1.json`). Verify the response first.

## Webhook deliveries

```python
from vaultody_verify import WebhookSignatureError, verify_webhook_signature

try:
    verify_webhook_signature(request_body_bytes, request_headers, signing_secret)
except WebhookSignatureError as error:      # error.reason: missing, malformed or mismatch
    abort(401)                              # Flask, for example
event = json.loads(request_body_bytes)      # parse only after it verified
```

`X-Signature` must be exactly 64 lowercase hex characters: the HMAC-SHA256 of the raw body, keyed with the
signing secret. Pass a list of secrets during a rotation; the result's `secret_index` says which one
matched (`test-vectors/webhook-v1.json`).

The scheme has no timestamp, and Vaultody may deliver the same event more than once. Before you act on an event,
check whether you already acted on it, keyed on what the event is about, as the developer docs' Webhook
Notifications page says: for outgoing transaction events `data.item.requestId` and `data.event`; for incoming
ones `data.item.transactionId`, `data.item.address`, `data.event` and `data.item.currentConfirmations` (an
internal transfer has no `transactionId`: use `data.item.parentTransactionId` and `data.item.operationId` in its
place).

## Vault addresses

```python
from vaultody_verify import AddressVerificationError, check_address, network_of_vault

vault = {"type": "main", "keys": {"ECDSA": ecdsa_xpub, "EDDSA": eddsa_xpub}}   # pinned from GET /vaults/main
check_address(vault, blockchain="bitcoin", network=network_of_vault("bitcoin", "main"), address=address,
              account_index=0, is_change=False, address_index=7, address_format="p2wpkh")
```

`check_address` derives the address from the vault's xpub at `m/account/change/index` and raises
`AddressVerificationError` (`reason`: `unsupported`, `network_mismatch`, `not_verifiable`, `missing_key` or
`mismatch`) unless it is exactly the one given. Where the xpub comes from is your trust decision.
`network_of_vault` gives the network of an address whose response omits it (`test-vectors/address-v1.json`).

## Tests

```bash
cd python/vaultody-verify
python3 -m venv .venv && .venv/bin/pip install -e '.[requests]' pytest
.venv/bin/pytest -q
```

The tests run every case in `../../test-vectors/v1.json`, the canonical vectors generated by the gateway
with test-only keys, and require exactly the verdict and reason each one expects; likewise the key-pair,
HMAC v2, full header set, P1363, signing-keys and webhook vectors in the same directory.
