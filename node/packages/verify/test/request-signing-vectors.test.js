'use strict';

// test-vectors/request-hmac-v2.json and request-full-v1.json, generated with the gateway's own apiSign and
// RequestKeypair: the HMAC v2 string and signature, the secrets the SDK refuses, and every authentication
// header of a request, with and without a key pair.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const keys = require('../src/keys');

const HMAC_VECTORS = require('../../../../test-vectors/request-hmac-v2.json');
const FULL_VECTORS = require('../../../../test-vectors/request-full-v1.json');

describe('test-vectors/request-hmac-v2.json', () => {
    for (const vector of HMAC_VECTORS.cases) {
        it(vector.name, () => {
            const { secret, request, expected } = vector;
            if (expected.error) {
                assert.throws(() => keys.hmacV2Signature(secret, request), error => error instanceof keys.UsageError && error.code === expected.error);
                assert.throws(() => keys.signHmacV2Request({ apiKey: 'k', apiSecret: secret, passphrase: request.passphrase }, request), { code: expected.error });

                return;
            }
            const message = keys.hmacV2RequestMessage(request);
            assert.equal(message.toString('utf8'), expected.signedString);
            assert.equal(message.toString('base64'), expected.signedStringBase64);
            assert.equal(keys.hmacV2Signature(secret, request), expected.signature);
        });
    }

    it('never puts the secret in an error', () => {
        const secret = `${HMAC_VECTORS.cases[0].secret}\n`;
        assert.throws(() => keys.hmacV2Signature(secret, HMAC_VECTORS.cases[0].request), error => !error.message.includes(secret.trim()));
    });
});

describe('test-vectors/request-full-v1.json', () => {
    const { credentials } = FULL_VECTORS;
    const keyOf = name => keys.readSigningKey(FULL_VECTORS.keys[name].privateKeyPkcs8Pem, { accept: 'private' });

    for (const vector of FULL_VECTORS.cases) {
        it(vector.name, () => {
            const { request, expected } = vector;
            const headers = vector.key
                ? keys.signApiRequest(keyOf(vector.key), credentials, request)
                : keys.signHmacV2Request(credentials, request);

            assert.deepEqual(Object.keys(headers).sort(), Object.keys(expected.headers).sort());
            for (const [name, value] of Object.entries(expected.headers)) {
                if (value !== null) {
                    assert.equal(headers[name], value, name);
                }
            }
            if (expected.keypairSignature === 'none') {
                assert.equal(expected.keypairSignedStringBase64, null);

                return;
            }

            // The key-pair string carries the API key the request is sent with.
            const signedString = keys.keypairRequestMessage({ ...request, apiKey: credentials.apiKey });
            assert.equal(signedString.toString('base64'), expected.keypairSignedStringBase64);
            if (expected.keypairSignature === 'exact') {
                assert.equal(headers['x-api-keypair-sign'], expected.headers['x-api-keypair-sign']);
            }
            // Whatever the algorithm, the signature must verify the way the gateway checks it.
            const registered = keys.readSigningKey(FULL_VECTORS.keys[vector.key].publicKeySpkiPem, { accept: 'public' });
            assert.deepEqual(keys.verifyKeypairRequest([registered], { ...request, apiKey: credentials.apiKey }, {
                keypairId: headers['x-api-keypair-id'],
                keypairSign: headers['x-api-keypair-sign'],
            }), { valid: true });
            if (FULL_VECTORS.keys[vector.key].algorithm === 'p-256') {
                assert.ok(crypto.verify('sha256', signedString, { key: registered.publicKey, dsaEncoding: 'der' }, Buffer.from(headers['x-api-keypair-sign'], 'base64')));
            }
        });
    }

    it('signs every request with a fresh nonce when none is given', () => {
        const { request } = FULL_VECTORS.cases[0];
        const fresh = { ...request, nonce: undefined, timestamp: undefined };
        const first = keys.signHmacV2Request(credentials, fresh);
        const second = keys.signHmacV2Request(credentials, fresh);
        assert.match(first['x-api-nonce'], /^[0-9a-f]{32}$/);
        assert.notEqual(first['x-api-nonce'], second['x-api-nonce']);
    });

    it('puts no secret in the headers', () => {
        const headers = keys.signHmacV2Request(credentials, FULL_VECTORS.cases[0].request);
        assert.ok(!Object.values(headers).includes(credentials.apiSecret));
    });
});
