'use strict';

// test-vectors/signing-keys-v1.json through the pipeline: the client signs GET /api-keys/current/signing-keys
// with the vectors' clock, nonce and Ed25519 key, so its x-api-sign and x-api-keypair-sign are exactly the
// ones the vector answers were signed over; the mock gateway checks them and the vector's answer comes back as
// received. confirmSigningKey must reach each case's verdict, and only an active key in a signed answer turns
// on the key-pair retry mode. The vectors accept an unsigned answer as unsigned, so each case runs on a new client
// of a release candidate that embeds the roots (when-present until its first signed answer).

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { ResponseVerificationError } = require('../src');
const { setup, T0 } = require('./helpers');
const { load } = require('./vectors');

const VECTORS = load('signing-keys-v1.json');
const NONCE = '0c9b8a7f6e5d4c3b2a1908f7e6d5c4b3';

describe('test-vectors/signing-keys-v1.json through the pipeline', () => {
    for (const vector of VECTORS.cases) {
        it(vector.name, async () => {
            const env = await setup({ key: 'ed25519', roots: 'embedded', client: { unsupported: { nonce: () => NONCE } } });
            try {
                assert.equal(env.client.signerFingerprint, vector.fingerprint);
                env.gw.mitm = ({ response }) => {
                    env.clock.set(vector.now * 1000);

                    return { status: vector.response.status, headers: vector.response.headers, body: Buffer.from(vector.response.bodyBase64, 'base64') };
                };
                env.clock.set(T0);
                const run = env.client.confirmSigningKey();
                if (vector.expected.signature.error) {
                    await assert.rejects(run, error => error instanceof ResponseVerificationError && error.reason === vector.expected.signature.error);
                } else {
                    const result = await run;
                    assert.equal(result.outcome, vector.expected.outcome);
                    assert.equal(result.signature, vector.expected.signature);
                    if (vector.expected.code) {
                        assert.equal(result.code, vector.expected.code);
                    }
                    assert.equal(result.keyMode, result.outcome === 'active' && result.signature === 'verified' ? 'keypair' : 'legacy');
                }

                const [sent] = env.gw.requests;
                assert.equal(sent.headers['x-api-sign'], vector.request.apiSign);
                if (vector.request.keypairSign !== '') {
                    assert.equal(sent.headers['x-api-keypair-sign'], vector.request.keypairSign);
                }
                // Never retried after a failed check.
                assert.equal(env.gw.requests.length, 1);
            } finally {
                await env.close();
            }
        });
    }
});
