'use strict';

// test-vectors/webhook-v1.json: X-Signature on webhook deliveries.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { verifyWebhookSignature, WebhookSignatureError } = require('../src/webhook');
const { ConfigurationError } = require('../src/errors');

const VECTORS = require('../../../../test-vectors/webhook-v1.json');

describe('test-vectors/webhook-v1.json', () => {
    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            const body = Buffer.from(vector.bodyBase64, 'base64');
            const secrets = vector.secrets.length === 1 ? vector.secrets[0] : vector.secrets;
            if (vector.expected.valid) {
                assert.deepEqual(verifyWebhookSignature(body, vector.headers, secrets), vector.expected);
                // The same through a fetch Headers object and a Map
                assert.deepEqual(verifyWebhookSignature(body, new Headers(vector.headers), vector.secrets), vector.expected);
                assert.deepEqual(verifyWebhookSignature(body.toString('utf8'), new Map(Object.entries(vector.headers)), vector.secrets), vector.expected);
            } else {
                assert.throws(() => verifyWebhookSignature(body, vector.headers, secrets), error => error instanceof WebhookSignatureError && error.reason === vector.expected.reason);
            }
        });
    }

    it('refuses a parsed body, so nothing is verified over re-serialised JSON', () => {
        const vector = VECTORS.cases[0];
        const parsed = JSON.parse(Buffer.from(vector.bodyBase64, 'base64').toString('utf8'));
        assert.throws(() => verifyWebhookSignature(parsed, vector.headers, vector.secrets), TypeError);
    });

    it('refuses to run without a secret', () => {
        const vector = VECTORS.cases[0];
        const body = Buffer.from(vector.bodyBase64, 'base64');
        for (const secrets of [undefined, '', [], [''], [vector.secrets[0], 42]]) {
            assert.throws(() => verifyWebhookSignature(body, vector.headers, secrets), ConfigurationError);
        }
    });

    it('refuses the header given twice', () => {
        const vector = VECTORS.cases[0];
        const value = vector.headers['X-Signature'];
        assert.throws(() => verifyWebhookSignature(Buffer.from(vector.bodyBase64, 'base64'), { 'x-signature': [value, value] }, vector.secrets), { reason: 'malformed' });
    });
});
