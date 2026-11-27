# Mock gateway

An HTTP server on 127.0.0.1 that answers SDK requests the way the Vaultody API gateway does. Every language runs its pipeline tests against it in CI. It uses only `node:http` and `node:crypto`, and it is written apart from the SDKs and from `@vaultody-com/verify`, so it can't share their bugs.

| What it does | How |
|---|---|
| Checks request signatures | `x-api-sign` version 2 and a timestamp within 30 s + 10 s. For an API key with key pairs, also the nonce, `x-api-keypair-id` and `x-api-keypair-sign` (Ed25519 raw, P-256 DER only). |
| Replay protection | For a duplicate nonce, within 3 s it returns the first answer with `x-api-replayed: true`. While the first is still running, it waits up to 5 s, then answers 409 `duplicate_api_request_in_progress`. Later it answers 401 `duplicate_api_request`. A 429 forgets the record. Key-pair requests are always enforced; legacy keys are only reported, as on production, so a duplicate runs again and the tests count it. |
| Signs every answer | Errors included, with the TEST-ONLY roots and pod keys of `test-vectors/v1.json`: the current, next or an unpinned root; an expired certificate; an unread body; another signature version. Or no signature at all. |
| Routes | The routes a test registers, then `GET /api-keys/current/signing-keys` and `GET /vaults/{main\|test}` from its own state, else 404. |
| Faults | One per request, in order: a status before the route or after it ran, a dropped connection, a delay, or a moved fake clock. A MITM hook can rewrite an answer after it was signed. |

`node/packages/sdk/test/mock-gateway.test.js` holds it to the vectors the real gateway's code produced: `request-hmac-v2.json`, every verdict of `request-keypair-v1.json`, and the signatures of `v1.json`.

```js
const { startMockGateway, fakeClock, rootPem } = require('./conformance/mock-gateway');
const gw = await startMockGateway({ clock: fakeClock(Date.now()), keys: { [apiKey]: { secret, passphrase, keypairs: [publicKeyPem] } } });
gw.route('POST', /\/single-transfer$/, request => ({ status: 201, body: { data: { item: {} } } }));
gw.fault({ when: 'after', drop: true });   // the next request runs, its answer is lost
// ... a client with baseUrl: gw.url and roots: [rootPem('current')]
await gw.close();
```
