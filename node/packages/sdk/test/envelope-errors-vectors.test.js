'use strict';

// test-vectors/envelope-errors-v1.json: status, headers and raw body → result kind or typed error.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const errors = require('../src/errors');
const { load } = require('./vectors');

const VECTORS = load('envelope-errors-v1.json');

describe('test-vectors/envelope-errors-v1.json', () => {
    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            const response = { status: vector.status, headers: vector.headers, body: Buffer.from(vector.body, 'utf8') };
            const { expected } = vector;
            if (expected.kind !== 'error') {
                const result = errors.readEnvelope(response);
                const { items, item, ...meta } = result;
                const actual = { ...meta };
                if (result.kind === 'page') {
                    actual.count = items.length;
                }
                assert.deepEqual(actual, expected);

                return;
            }

            let thrown;
            assert.throws(() => errors.readEnvelope(response), error => {
                thrown = error;

                return true;
            });
            assert.equal(thrown.constructor.name, expected.class);
            assert.equal(thrown.name, expected.class);
            assert.ok(thrown instanceof errors.ApiError);
            assert.ok(thrown instanceof errors.VaultodyError);
            assert.ok(thrown instanceof errors[expected.class]);
            assert.equal(thrown.status, vector.status);
            assert.equal(thrown.code, expected.code);
            if (expected.message !== null) {
                assert.equal(thrown.message, expected.message);
            } else {
                assert.ok(thrown.message.length > 0);
            }
            assert.equal(thrown.requestId, expected.requestId);
            assert.equal(thrown.apiVersion, expected.apiVersion);
            assert.equal(thrown.replayed, expected.replayed);
            assert.equal(thrown.retryable, expected.retryable);
            if ('details' in expected) {
                assert.deepEqual(thrown.details, expected.details);
            } else {
                assert.equal('details' in thrown, false);
            }
        });
    }

    it('reads a fetch Headers object too', () => {
        const vector = VECTORS.cases.find(candidate => candidate.name === 'item_replayed');
        const result = errors.readEnvelope({ status: vector.status, headers: new Headers(vector.headers), body: vector.body });
        assert.equal(result.replayed, true);
    });
});

// The errors the SDK raises with no answer of the API: exported from the package root, each a VaultodyError, and
// raised for real with the same class and fields as in Python and PHP.
describe('test-vectors/envelope-errors-v1.json: sdkErrors', () => {
    const sdk = require('..');
    const { MemoryVaultKeyStore } = sdk;
    const { sdkErrors } = VECTORS;

    for (const name of sdkErrors.classes) {
        it(`${name} is exported from the package root and is a VaultodyError`, () => {
            assert.equal(typeof sdk[name], 'function', name);
            assert.equal(sdk[name], errors[name]);
            assert.ok(sdk[name].prototype instanceof sdk.VaultodyError, name);
        });
    }

    for (const vector of sdkErrors.cases) {
        it(vector.name, async () => {
            let thrown;
            if (vector.call) {
                const sent = [];
                const client = new sdk.Vaultody({
                    apiKey: 'TEST-ONLY-key', apiSecret: 'VEVTVC1PTkxZ', passphrase: 'TEST-ONLY-passphrase', vaultKeyStore: new MemoryVaultKeyStore(),
                    unsupported: { fetch: async url => { sent.push(url); throw new Error('nothing may be sent'); } },
                });
                await assert.rejects(client[vector.call.group][vector.call.operationId](vector.call.params), error => {
                    thrown = error;

                    return true;
                });
                assert.deepEqual(sent, []);
            } else {
                const { bodyBase64, headers, secrets } = vector.webhook;
                assert.throws(() => sdk.verifyWebhook(Buffer.from(bodyBase64, 'base64'), headers, secrets), error => {
                    thrown = error;

                    return true;
                });
            }
            assert.equal(thrown.constructor.name, vector.expected.class);
            assert.ok(thrown instanceof sdk[vector.expected.class]);
            assert.ok(thrown instanceof sdk.VaultodyError);
            for (const [field, value] of Object.entries(vector.expected.fields)) {
                assert.equal(thrown[field], value, field);
            }
        });
    }
});
