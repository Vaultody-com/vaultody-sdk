'use strict';

// Request signing through the whole pipeline: the client signs, the mock gateway checks every signature with
// its own code (conformance/mock-gateway), and the headers it received are compared with the vectors.
//  - test-vectors/request-full-v1.json: every case, every authentication header;
//  - test-vectors/request-hmac-v2.json: every case the SDK can produce (the others describe requests the SDK
//    never sends, listed below with the reason; the mock gateway is checked against them in
//    mock-gateway.test.js), and every refused API secret;
//  - test-vectors/request-keypair-v1.json: each signed string through the SDK's signer stage;
//  - test-vectors/p1363-der-v1.json: P-256 signer output normalised to DER, and a P1363 signer end to end.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { Vaultody, MemoryVaultKeyStore, ConfigurationError, pemSigner } = require('../src');
const { prepareSigner, normalizeSignature } = require('../src/signer');
const { setup, latchedStore, CREDENTIALS, KEYS, VAULT, json } = require('./helpers');
const { load } = require('./vectors');
const internal = require('../src/internal');

const FULL = load('request-full-v1.json');
const HMAC = load('request-hmac-v2.json');
const KEYPAIR = load('request-keypair-v1.json');
const P1363 = load('p1363-der-v1.json');

const addressRoute = gw => gw.route('POST', /\/addresses$/, request => {
    const { data } = JSON.parse(request.body.toString('utf8'));

    return { status: 201, body: { apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b1', data: { item: { address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', label: data.item.label } } } };
});
const okRoute = (gw, method, pattern) => gw.route(method, pattern, () => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b2', data: { item: { ok: true } } } }));

/** The call that produces a vector's request, or null when the SDK can't produce it. */
function callOf(request) {
    if (request.nonce === '') {
        return null;
    }
    if (request.method === 'GET' && request.path === '/vaults/main' && request.query === 'limit=50' && request.body === '') {
        return ['listVaults', { networkType: 'main', limit: 50 }, {}];
    }
    if (request.method === 'GET' && request.path === '/api-keys/current/signing-keys' && request.query === '' && request.body === '') {
        return ['listApiKeySigningKeys', {}, {}];
    }
    const address = /^(\/v2)?\/vaults\/([0-9a-f]{24})\/bitcoin\/mainnet\/addresses$/.exec(request.path);
    if (request.method === 'POST' && address && request.query === '') {
        const body = JSON.parse(request.body);
        const params = { vaultId: address[2], blockchain: 'bitcoin', network: 'mainnet', ...body.data.item };
        // The SDK writes { context?, data: { item } } compactly, item fields in the order given.
        const rebuilt = JSON.stringify(body.context === undefined ? { data: { item: body.data.item } } : { context: body.context, data: { item: body.data.item } });
        if (rebuilt !== request.body) {
            return null;
        }

        return ['generateDepositAddress', params, body.context === undefined ? {} : { context: body.context }];
    }
    if (request.method === 'PUT' && /^\/vaults\/[0-9a-f]{24}\/vault-accounts\/[0-9a-f]{24}\/edit$/.test(request.path)) {
        const [, , vaultId, , vaultAccountId] = request.path.split('/');
        const body = JSON.parse(request.body);
        if (JSON.stringify(body) !== request.body) {
            return null;
        }

        return ['updateVaultAccount', { vaultId, vaultAccountId, ...body.data.item }, {}];
    }
    const balance = /^\/vaults\/([0-9a-f]{24})\/addresses\/([^/]+)\/balance$/.exec(request.path);
    if (request.method === 'GET' && balance && request.query === 'limit=1') {
        return ['getAddressBalance', { vaultId: balance[1], address: decodeURIComponent(balance[2]), limit: 1 }, {}];
    }

    return null;
}

/** Runs one vector request through a client on the vector's clock and nonce; resolves to the headers received. */
async function sendVector({ request, key = null, apiSecret = CREDENTIALS.apiSecret }) {
    const [operationId, params, options] = callOf(request);
    const nonces = [];
    // The origin signed for this client before, so no signed read precedes a write: the vector request is the only one.
    const env = await setup({
        key,
        latched: true,
        client: {
            apiSecret,
            unsupported: {
                apiVersion: request.apiVersion,
                nonce: () => (nonces.length > 0 ? nonces.shift() : crypto.randomBytes(16).toString('hex')),
            },
        },
    });
    try {
        env.gw.keys.get(CREDENTIALS.apiKey).secret = apiSecret;
        addressRoute(env.gw);
        okRoute(env.gw, 'PUT', /\/edit$/);
        okRoute(env.gw, 'GET', /\/balance$/);
        let client = env.client;
        if (request.path.startsWith('/v2/')) {
            client = new Vaultody({
                apiKey: CREDENTIALS.apiKey, apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: `${env.gw.url}/v2`, vaultKeyStore: await latchedStore(env.gw),
                maxRequestsPerSecond: 1000, signer: key ? pemSigner(KEYS[key].privateKeyPkcs8Pem) : undefined, logger: { warn() {} },
                roots: [require('./helpers').rootPem('current')],
                unsupported: { clock: env.clock, apiVersion: request.apiVersion, nonce: () => (nonces.length > 0 ? nonces.shift() : crypto.randomBytes(16).toString('hex')) },
            });
        }
        if (key) {
            // The key pair is confirmed before the first write, with nonces of its own.
            await client.confirmSigningKey();
        }
        env.clock.set(Number(request.timestamp) * 1000);
        nonces.push(request.nonce);
        await internal.request(client, operationId, params, options);

        return env.gw.requests[env.gw.requests.length - 1];
    } finally {
        await env.close();
    }
}

describe('test-vectors/request-full-v1.json through the pipeline', () => {
    for (const vector of FULL.cases) {
        it(vector.name, async () => {
            assert.ok(callOf(vector.request), 'the SDK produces this request');
            const received = await sendVector({ request: vector.request, key: vector.key });
            for (const [name, value] of Object.entries(vector.expected.headers)) {
                if (value === null) {
                    // P-256 signatures are randomised: the gateway accepted it, which is the check.
                    assert.ok(received.headers[name], name);
                } else {
                    assert.equal(received.headers[name], value, name);
                }
            }
            const sent = Object.keys(received.headers).filter(name => name.startsWith('x-api-'));
            assert.deepEqual(sent.sort(), Object.keys(vector.expected.headers).sort());
        });
    }
});

// What the SDK never sends, by design.
const NOT_PRODUCIBLE = {
    post_all_fields: 'context goes in the body of a POST, never also in its query',
    get_empty_fields: 'the SDK always sends a nonce and x-api-version',
    no_nonce: 'the SDK always sends a nonce',
    raw_query_as_sent: 'listVaults has no offset or label parameter',
    query_with_question_mark: 'the SDK percent-encodes "?" in a query value',
    unicode_body: 'the SDK writes compact JSON, context first',
    body_trailing_newline: 'the SDK writes compact JSON without a trailing newline',
};

describe('test-vectors/request-hmac-v2.json through the pipeline', () => {
    it('lists every case the SDK does not produce, with the reason', () => {
        const unproducible = HMAC.cases.filter(vector => !vector.expected.error && !callOf(vector.request)).map(vector => vector.name).sort();
        assert.deepEqual(unproducible, Object.keys(NOT_PRODUCIBLE).sort());
    });

    for (const vector of HMAC.cases) {
        if (vector.expected.error) {
            it(`${vector.name}: refused before anything is signed`, () => {
                assert.throws(() => new Vaultody({ apiKey: CREDENTIALS.apiKey, apiSecret: vector.secret, passphrase: CREDENTIALS.passphrase, vaultKeyStore: new MemoryVaultKeyStore() }),
                    error => error instanceof ConfigurationError && error.code === vector.expected.error && !error.message.includes(vector.secret || '\u0000'));
            });
        } else if (!NOT_PRODUCIBLE[vector.name]) {
            it(vector.name, async () => {
                const received = await sendVector({ request: vector.request, apiSecret: vector.secret });
                assert.equal(received.headers['x-api-sign'], vector.expected.signature);
                assert.equal(received.headers['x-api-sign-version'], '2');
            });
        }
    }
});

describe('test-vectors/request-keypair-v1.json through the signer stage', () => {
    const keys = { ed25519: KEYS.ed25519, p256: KEYS.p256 };
    for (const vector of KEYPAIR.cases.filter(item => item.category === 'valid' && keys[item.signed.key])) {
        it(vector.name, async () => {
            const key = keys[vector.signed.key];
            const signer = prepareSigner(pemSigner(key.privateKeyPkcs8Pem));
            assert.equal(signer.fingerprint, key.fingerprint);
            const signature = await signer.sign(Buffer.from(vector.signed.signedString, 'utf8'));
            if (vector.signed.algorithm === 'ed25519') {
                assert.equal(signature, vector.signed.signature);
            } else {
                assert.ok(crypto.verify('sha256', Buffer.from(vector.signed.signedString, 'utf8'), { key: crypto.createPublicKey(key.publicKeySpkiPem), dsaEncoding: 'der' }, Buffer.from(signature, 'base64')));
            }
        });
    }
});

describe('test-vectors/p1363-der-v1.json through the signer stage', () => {
    const publicKeyPem = crypto.createPublicKey({ key: Buffer.from(P1363.publicKeySpkiDerBase64, 'base64'), format: 'der', type: 'spki' }).export({ format: 'pem', type: 'spki' });

    for (const vector of P1363.cases) {
        it(vector.name, async () => {
            const input = Buffer.from(vector.p1363Hex, 'hex');
            if (input.length === 64) {
                if (vector.expected.error) {
                    assert.throws(() => normalizeSignature('p-256', input), error => error instanceof ConfigurationError && error.code === 'invalid_signature' && error.message.includes(vector.expected.error));
                } else {
                    assert.equal(normalizeSignature('p-256', input).toString('hex'), vector.expected.derHex);
                }
            } else {
                // Not r||s: taken as DER (what most KMS APIs return); the local check refuses it unless it verifies.
                assert.equal(normalizeSignature('p-256', input).toString('hex'), vector.p1363Hex);
            }
            if (vector.messageBase64) {
                // A signer that answers in P1363 (Web Crypto, Azure Key Vault): the SDK sends the DER and its own
                // check against the public key passes.
                const signer = prepareSigner({ algorithm: 'p-256', publicKeyPem, sign: () => input });
                assert.equal(Buffer.from(await signer.sign(Buffer.from(vector.messageBase64, 'base64')), 'base64').toString('hex'), vector.expected.derHex);
            } else if (input.length !== 64 || vector.expected.error) {
                const signer = prepareSigner({ algorithm: 'p-256', publicKeyPem, sign: () => input });
                await assert.rejects(signer.sign(Buffer.from('any message')), error => error instanceof ConfigurationError
                    && ['invalid_signature', 'signer_key_mismatch'].includes(error.code));
            }
        });
    }

    it('a Web Crypto style P1363 signer works end to end, the gateway receiving DER', async () => {
        const env = await setup({ key: 'p256', client: {} });
        try {
            const privateKey = crypto.createPrivateKey(KEYS.p256.privateKeyPkcs8Pem);
            const p1363Signer = {
                algorithm: 'p-256',
                publicKeyPem: KEYS.p256.publicKeySpkiPem,
                sign: async message => crypto.sign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' }),
            };
            const client = new Vaultody({
                apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: env.gw.url,
                vaultKeyStore: new MemoryVaultKeyStore(), signer: p1363Signer, roots: [require('./helpers').rootPem('current')], logger: { warn() {} },
                unsupported: { clock: env.clock },
            });
            addressRoute(env.gw);
            const result = await internal.request(client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'p1363' });
            assert.equal(result.item.label, 'p1363');
            const der = Buffer.from(env.gw.requests[env.gw.requests.length - 1].headers['x-api-keypair-sign'], 'base64');
            assert.equal(der[0], 0x30);
        } finally {
            await env.close();
        }
    });
});

module.exports = { addressRoute, json };
