'use strict';

// test-vectors/signing-keys-v1.json: signed answers of GET /api-keys/current/signing-keys, checked the way
// `vaultody keys verify` checks them: the response signature first, over the request as sent, then the list.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { verifyResponse } = require('../src/response');
const { ResponseSignatureError } = require('../src/errors');
const { readSigningKeysResponse } = require('../src/keys');

const VECTORS = require('../../../../test-vectors/signing-keys-v1.json');
const RESPONSE_VECTORS = require('../../../../test-vectors/v1.json');

const rootDer = name => Buffer.from(RESPONSE_VECTORS.keys.roots[name].publicKeySpkiDerBase64, 'base64');
const rootPem = name => require('node:crypto').createPublicKey({ key: rootDer(name), format: 'der', type: 'spki' }).export({ format: 'pem', type: 'spki' });

describe('test-vectors/signing-keys-v1.json', () => {
    const roots = VECTORS.pinnedRoots.map(rootPem);

    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            const { request, response, now, expected } = vector;
            const body = Buffer.from(response.bodyBase64, 'base64');
            let signature;
            try {
                const result = verifyResponse({
                    request: {
                        method: request.method,
                        url: request.query === '' ? request.path : `${request.path}?${request.query}`,
                        body: Buffer.from(request.bodyBase64, 'base64'),
                        apiSign: request.apiSign,
                        keypairSign: request.keypairSign,
                    },
                    response: { status: response.status, headers: response.headers, body },
                }, { roots, now, requireResponseSignature: false });
                signature = result.verified ? 'verified' : 'absent';
            } catch (error) {
                if (!(error instanceof ResponseSignatureError)) {
                    throw error;
                }
                signature = { error: error.reason };
            }
            assert.deepEqual(signature, expected.signature);
            if (typeof signature !== 'string') {
                return;
            }

            const read = readSigningKeysResponse({ status: response.status, body }, vector.fingerprint);
            assert.equal(read.outcome, expected.outcome);
            if (expected.code) {
                assert.equal(read.error.code, expected.code);
            }
        });
    }
});
