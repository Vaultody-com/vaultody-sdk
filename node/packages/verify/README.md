# @vaultody/verify

Checks that a Vaultody API response came, unchanged, from the Vaultody API gateway.

TLS for the API ends at a CDN in front of the gateway, so a valid TLS connection proves only that the CDN
answered. The gateway signs every response itself. This package checks that signature against Vaultody
root keys embedded in the package, and refuses a response that was altered, stripped of its signature, or
moved onto a different request.

Node.js 22 or later. No dependencies.

## Install

Release candidate:

```sh
npm install @vaultody/verify@next
```

## Usage with fetch

```js
const { verifyFetchResponse, ResponseSignatureError } = require('@vaultody/verify');

const url = 'https://rest.vaultody.com/vaults/<vaultId>/bitcoin/mainnet/addresses?context=yes';
const init = {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-sign': apiSign /* and your other API headers */ },
    body: JSON.stringify({ context: 'yes', data: { item: { label: 'deposit-7' } } }),
};

const response = await fetch(url, init);
try {
    // Pass the same URL and init you gave fetch. This reads the response body for you.
    const { body } = await verifyFetchResponse({ url, ...init }, response);
    const data = JSON.parse(body.toString('utf8')); // parse only after verifying
} catch (error) {
    if (error instanceof ResponseSignatureError) {
        // Do not use this response. error.reason says why (see below).
    }
    throw error;
}
```

You can also pass a `Request`. Send a clone so its body can still be read:
`verifyFetchResponse(request, await fetch(request.clone()))`.

The result is `{ verified: true, keyId, rootId, timestamp, body }`. `body` is a `Buffer` with the raw
response bytes. The `Response` body has already been read at this point, so use this `body`.

## Usage with any other HTTP client

```js
const { verifyResponse } = require('@vaultody/verify');

const result = verifyResponse({
    request: { method: 'POST', url: '/vaults/<vaultId>/bitcoin/mainnet/addresses?context=yes', body: requestBytes, apiSign, keypairSign },
    response: { status: res.statusCode, headers: res.headers, body: responseBytes },
});
// → { verified: true, keyId, rootId, timestamp }
```

- `request.url` is the path and query **exactly as sent on the request line**, starting with `/`. It
  never includes the host. It is split at the first `?`, and nothing is decoded or normalised. With Node's
  `http`/`https` this is `req.path`. With axios on Node it is `response.request.path`.
- `request.method` is the method as sent. It is not upper-cased for you.
- `request.body` is the bytes you sent, before any Content-Encoding (compression). Omit it, or pass
  `null`, if there was no body.
- `request.apiSign` is the `x-api-sign` header you sent, if any.
- `request.keypairSign` is the `x-api-keypair-sign` header you sent, if any. The response is bound to it
  too, so a key-pair signature dropped, added or changed on the way makes the response fail.
- `response.headers` may be a plain object with names in any case, a fetch `Headers` or a `Map`.
- Bodies may be a `Buffer`, a `Uint8Array`, an `ArrayBuffer`, or a string (read as UTF-8).

## Verify the raw bytes before parsing

The signature covers the exact bytes the gateway sent. Verify those bytes first, and only then parse
them as JSON. Re-serialising parsed JSON rarely gives the same bytes back, so a parsed object is refused
with a `TypeError`. Response bytes are taken after Content-Encoding is removed, which fetch does for you.

## Strict by default

`requireResponseSignature` defaults to `true`, so a response without a signature is an error.

With `requireResponseSignature: false`, a response that carries **none** of the four signature headers
returns `{ verified: false, reason: 'missing' }` instead of throwing. This is meant only for a transition
period. Everything else still throws, including a response with only some of the headers: a partly
stripped signature means someone removed it.

## Options

| Option | Default | |
|---|---|---|
| `requireResponseSignature` | `true` | See above. |
| `roots` | the embedded roots | Root public keys to trust instead of the embedded ones. See below. |
| `now` | the system clock | The current time, as Unix seconds or a `Date`. |
| `maxClockSkewSeconds` | `300` | How far past a certificate's end this machine's clock may be. |

## Errors

A failed check throws a `ResponseSignatureError` with `error.reason` set to one of these values (also
exported as `REASONS`):

| `reason` | Meaning |
|---|---|
| `missing` | A signature header is absent or empty. The response was not signed, or the signature was stripped. |
| `invalid` | Malformed headers or certificate, a certificate valid for more than an hour (`notAfter - notBefore` over 3600 seconds, also exported as `MAX_CERT_LIFETIME_SECONDS`), or the signature does not match. Either the response was changed, the request you passed is not the one that was sent, or the certificate was not issued as the gateway issues them. |
| `expired` | The response was signed outside its certificate's validity window, or this machine's clock is more than `maxClockSkewSeconds` past the end of that window. |
| `unknown_root` | The certificate was issued by a root this package does not trust. Upgrade the package, or check `roots`. |
| `request_unbound` | The response is genuine, but the gateway did not read the request body (over 1 MB, or the upload was cut off). It is therefore not tied to the body you sent. |
| `unsupported_version` | The response uses a signature format this version of the package does not know. Upgrade it. |

Setup problems throw a `ConfigurationError` instead, and never look like a verdict on the
response. This happens when a signed response arrives and no root keys are configured, a configured root
is not a P-256 public key, or a fingerprint does not match its key. The roots are looked up only once a
response carries a signature: with `requireResponseSignature: false`, a response with no signature
headers at all still returns `{ verified: false, reason: 'missing' }` without any root. A malformed `roots`
option throws at once, signed response or not. Wrong arguments, such as a full URL in `request.url` or a parsed
body, throw a `TypeError`.

## Root keys and rotation

The gateway's root key is a P-256 key held in an HSM. It certifies each gateway instance's short-lived
signing key. This package embeds the production root public keys in `src/roots.js`, in two slots:

- `current`: the root the gateway signs with today;
- `next`: the root it will move to.

Each slot holds the key as SPKI PEM next to its fingerprint: the lowercase hex SHA-256 of the key's DER.
The same fingerprint is sent to clients by email, outside the CDN. You can check it yourself:
`openssl pkey -pubin -in root.pem -outform DER | openssl dgst -sha256`. When the package loads, it
recomputes every fingerprint and refuses to load if one differs.

**The production roots are not filled in yet.** Until a release embeds them, verifying a signed
response throws a `ConfigurationError`, never a pass. Pass `roots` explicitly in the meantime.

A rotation works like this:

1. A new root is created in the HSM. It is published as `next` in a package release, and its
   fingerprint is emailed to clients ahead of time.
2. Once clients have upgraded, the gateway starts certifying its keys with the new root. Upgraded clients
   accept responses under both roots during the change-over.
3. A later release makes the new root `current`, drops the old one, and pins the following `next` when it
   exists. Responses certified by a dropped root fail with `unknown_root`.

The `roots` option **replaces** the embedded roots; it does not add to them. Use it for test environments,
which have their own roots, or to trust a new root before the release that embeds it. It accepts a PEM
string, `{ pem }`, `{ pem, fingerprint }` (the fingerprint is then checked), an array of those, or an
object such as `{ current, next }` in which an empty slot is skipped. A root must be an EC P-256 public key
in standard SPKI form (named curve, uncompressed point); a compressed point or explicit curve parameters
throw `ConfigurationError`. `result.rootId` tells you which root certified a response.

## How fetch's URL can differ from what you typed

The gateway signs the path and query it received, and `verifyFetchResponse` rebuilds them the way fetch
sends them: the WHATWG URL's `pathname + search`. That can differ from the text you typed:

- Spaces, non-ASCII characters and some punctuation are percent-encoded: `/a b/ü` is sent as
  `/a%20b/%C3%BC`. In the query, `'` becomes `%27` as well.
- Existing percent-escapes are kept as typed. `%2f` and `%2F` stay different, and neither is decoded.
- `.` and `..` path segments are resolved: `/a/./b/../c` is sent as `/a/c`.
- Backslashes become slashes in `http`/`https` URLs.
- The fragment (`#...`) is never sent, and an empty query (`/a?`) is sent without the `?`.
- fetch upper-cases `delete`, `get`, `head`, `options`, `post` and `put` in any case. Every other method
  is sent exactly as written: `patch` stays `patch`, and the gateway signs it that way.

`verifyFetchResponse` handles all of this for you. If you call `verifyResponse` yourself, pass the path
your HTTP client actually put on the wire, not the string you built.

## Request-signing keys

An API key can hold up to two public keys of your own. Once it holds one, every request made with it must
also be signed with the matching private key (`x-api-keypair-sign`). `require('@vaultody/verify/keys')` makes
and reads those keys (`generateSigningKeyPair`, `readSigningKeyFile`, `inspectPublicKey`, `fingerprintOf`),
signs the challenge the dashboard shows when you register a key (`signChallengeProof`), and signs requests
(below). It does no network I/O.

The `vaultody keys` command line (`generate`, `fingerprint`, `prove`, `verify`) is built on it and ships with
[`@vaultody/sdk`](../sdk/README.md#command-line-request-signing-keys): `npx @vaultody/sdk keys ...`. Its
`keys verify` asks the API through the SDK's client.

## Signing requests

`signHmacV2Request(credentials, request)` returns the authentication headers of an API key without a key
pair (`x-api-sign` version 2 with a fresh `x-api-nonce`); `signApiRequest(key, credentials, request)` adds
`x-api-keypair-sign` and `x-api-keypair-id`. The API secret must be the base64 text the dashboard shows
(padding optional); anything else throws a `UsageError` with code `invalid_api_secret` before anything is
signed. `p1363ToDer(signature)` turns a P-256 signature from Web Crypto, Azure Key Vault or a KMS that
returns IEEE P1363 (r‖s, 64 bytes) into the DER the gateway requires.

`x-api-keypair-sign` signs `vaultody-request-keypair-v1`, the `x-api-key`, then the HMAC v2 fields, one per line
(`keypairRequestMessage`): the API key is in the string, so a request signed for one API key is refused under
another that holds the same key pair. A pasted public key is read only up to 1024 characters, as a registration
does, in time linear in its length.

`readSigningKeysResponse(response, fingerprint)` reads an already verified answer of
`GET /api-keys/current/signing-keys`: `active`, `inactive`, `not_listed` or `refused`.

## Webhook deliveries

```js
const { verifyWebhookSignature, WebhookSignatureError } = require('@vaultody/verify/webhook');

app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    try {
        verifyWebhookSignature(req.body, req.headers, [CURRENT_SECRET, PREVIOUS_SECRET]);
    } catch (error) {
        if (error instanceof WebhookSignatureError) {
            return res.status(401).end();      // error.reason: missing, malformed or mismatch
        }
        throw error;
    }
    const event = JSON.parse(req.body);         // parse only after it verified
    // ...
});
```

`X-Signature` must be exactly 64 lowercase hex characters of HMAC-SHA256 over the raw body, keyed with the
signing secret. Several secrets cover a rotation; the result names the index of the one that matched.

The scheme has no timestamp, and Vaultody may deliver the same event more than once. Before you act on an event,
check whether you already acted on it, keyed on what the event is about, as the developer docs' Webhook
Notifications page says: for outgoing transaction events `data.item.requestId` and `data.event`; for incoming
ones `data.item.transactionId`, `data.item.address`, `data.event` and `data.item.currentConfirmations` (an
internal transfer has no `transactionId`: use `data.item.parentTransactionId` and `data.item.operationId` in its
place).

## Vault addresses

```js
const { checkAddress, networkOfVault, AddressVerificationError } = require('@vaultody/verify/address');

const vault = { type: 'main', keys: { ECDSA: ecdsaXpub, EDDSA: eddsaXpub } };   // pinned from GET /vaults/main
checkAddress(vault, { blockchain: 'bitcoin', network: networkOfVault('bitcoin', 'main'), address,
    accountIndex: 0, isChange: false, addressIndex: 7, addressFormat: 'p2wpkh' });
```

`checkAddress` derives the address from the vault's xpub at `m/accountIndex/isChange/addressIndex` (BIP32 public
derivation for secp256k1, Vaultody's own scheme for ed25519; 17 chains) and throws `AddressVerificationError`
(`reason`: `unsupported`, `network_mismatch`, `not_verifiable`, `missing_key` or `mismatch`) unless it is exactly
the address given. Where the xpub comes from is the caller's trust decision: `@vaultody/sdk` takes it only from
`GET /vaults/{main|test}` and pins it on first sight. `networkOfVault` gives the network of an address whose
response omits it (`test-vectors/address-v1.json`).

## Tests

```sh
node --test
```

The tests run every case in `../../../test-vectors/v1.json`, `request-keypair-v1.json`,
`keypair-challenge-v1.json`, `request-hmac-v2.json`, `request-full-v1.json`, `signing-keys-v1.json`,
`p1363-der-v1.json` and `webhook-v1.json`, the vectors shared with the gateway and the other languages,
and each case must produce exactly its expected result. `test/package-exports.test.js` imports every export
with `require()` and with ESM `import`. The `vaultody` command line is tested in `@vaultody/sdk`.
