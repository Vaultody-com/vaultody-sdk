'use strict';

// Every case of the key-pair vectors (test-vectors/request-keypair-v1.json, keypair-challenge-v1.json) run
// through src/keys.js, the module behind the `vaultody keys` command line: the keys and fingerprints, the
// public keys as pasted, the signed strings it builds, the signatures it makes, and the verdicts its
// verifiers give. keypair-vectors.test.js checks the same vectors with a separate reference implementation.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const keys = require('../src/keys');

const REQUEST_VECTORS = require('../../../../test-vectors/request-keypair-v1.json');
const CHALLENGE_VECTORS = require('../../../../test-vectors/keypair-challenge-v1.json');

// The registration's error codes and the module's own for the same refusal
const KEY_ERROR_OF = Object.freeze({
    api_key_public_key_invalid: keys.KEY_ERRORS.INVALID,
    api_key_public_key_is_private: keys.KEY_ERRORS.PRIVATE,
    api_key_public_key_unsupported_algorithm: keys.KEY_ERRORS.UNSUPPORTED_ALGORITHM,
});

const publicKeyNamed = (vectors, name) => keys.readSigningKey(vectors.keys[name].publicKeySpkiPem, { accept: 'public' });
const privateKeyNamed = (vectors, name) => keys.readSigningKey(vectors.keys[name].privateKeyPkcs8Pem, { accept: 'private' });

function inspected(pem) {
    try {
        const { algorithm, spkiDer, fingerprint } = keys.inspectPublicKey(pem);

        return { algorithm, canonicalSpkiDerBase64: spkiDer.toString('base64'), fingerprint };
    } catch (e) {
        if (e instanceof keys.SigningKeyError) {
            return { error: e.code };
        }
        throw e;
    }
}

const expectedOf = expected => (expected.error ? { error: KEY_ERROR_OF[expected.error] } : expected);

describe('src/keys.js on test-vectors/request-keypair-v1.json', () => {
    describe('the keys: both halves read, algorithm and fingerprint as in the vector', () => {
        for (const [name, vectorKey] of Object.entries(REQUEST_VECTORS.keys)) {
            it(name, () => {
                const fromPrivate = privateKeyNamed(REQUEST_VECTORS, name);
                const fromPublic = publicKeyNamed(REQUEST_VECTORS, name);
                for (const key of [fromPrivate, fromPublic]) {
                    assert.equal(key.algorithm, vectorKey.algorithm);
                    assert.equal(key.fingerprint, vectorKey.fingerprint);
                    assert.equal(key.fingerprint.length, 50);
                    assert.equal(key.spkiDer.toString('base64'), vectorKey.publicKeySpkiDerBase64);
                }
                assert.equal(fromPrivate.kind, 'private');
                assert.equal(fromPublic.kind, 'public');
                assert.equal(fromPublic.privateKey, null);
            });
        }
    });

    describe('public keys as pasted: what a registration makes of them', () => {
        for (const keyCase of REQUEST_VECTORS.publicKeys) {
            it(`${keyCase.name} → ${keyCase.expected.error || keyCase.expected.fingerprint}`, () => {
                assert.deepEqual(inspected(keyCase.publicKeyPem), expectedOf(keyCase.expected));
            });
        }

        it('the fingerprint command takes the pasted private key and gives its public key\'s fingerprint', () => {
            const privateCase = REQUEST_VECTORS.publicKeys.find(keyCase => keyCase.name === 'ed25519_private_key');
            assert.equal(keys.readSigningKey(privateCase.publicKeyPem, { accept: 'any' }).fingerprint, REQUEST_VECTORS.keys.ed25519.fingerprint);
        });
    });

    describe('every case: the signed string built, then the gateway\'s verdict', () => {
        for (const vector of REQUEST_VECTORS.cases) {
            it(`${vector.name} → ${vector.expected.valid ? 'valid' : vector.expected.reason}`, () => {
                const { signed, verify } = vector;

                const built = keys.keypairRequestMessage(signed.request);
                if (vector.category === 'signed_string') {
                    // the signer signed some other string: that is the point of the case
                    assert.notEqual(built.toString('base64'), signed.signedStringBase64);
                } else {
                    assert.equal(built.toString('base64'), signed.signedStringBase64);
                    assert.equal(built.toString('utf8'), signed.signedString);
                }

                const registered = verify.registeredKeys.map(name => publicKeyNamed(REQUEST_VECTORS, name));
                const verdict = keys.verifyKeypairRequest(registered, verify.request, {
                    keypairId: verify.headers['x-api-keypair-id'],
                    keypairSign: verify.headers['x-api-keypair-sign'],
                });
                assert.deepEqual(verdict, vector.expected);
            });
        }

        it('the HMAC v2 string is the same fields under the "v2" tag', () => {
            const vector = REQUEST_VECTORS.cases.find(candidate => candidate.name === 'hmac_v2_string_signed');
            assert.equal(keys.hmacV2RequestMessage(vector.signed.request).toString('base64'), vector.signed.signedStringBase64);
        });
    });

    describe('signing: the module signs what the vectors hold', () => {
        const validCases = REQUEST_VECTORS.cases.filter(vector => vector.category === 'valid');

        for (const vector of validCases) {
            it(`${vector.name}: x-api-keypair-sign and x-api-keypair-id`, () => {
                const { signed } = vector;
                const key = privateKeyNamed(REQUEST_VECTORS, signed.key);
                const headers = keys.signApiRequest(key, { apiKey: signed.request.apiKey, apiSecret: Buffer.from('TEST-ONLY secret').toString('base64'), passphrase: signed.request.passphrase }, {
                    method: signed.request.method,
                    path: signed.request.path,
                    query: signed.request.query,
                    body: signed.request.body,
                    apiVersion: signed.request.apiVersion,
                    timestamp: signed.request.timestamp,
                    nonce: signed.request.nonce,
                });
                assert.equal(headers['x-api-keypair-id'], REQUEST_VECTORS.keys[signed.key].fingerprint);
                if (signed.algorithm === 'ed25519') {
                    // Ed25519 is deterministic: the same signature, byte for byte
                    assert.equal(headers['x-api-keypair-sign'], signed.signature);
                } else {
                    // ECDSA is randomised: a fresh signature that verifies
                    assert.deepEqual(keys.verifyKeypairRequest([publicKeyNamed(REQUEST_VECTORS, signed.key)], signed.request, {
                        keypairId: headers['x-api-keypair-id'],
                        keypairSign: headers['x-api-keypair-sign'],
                    }), { valid: true });
                }
                assert.equal(headers['x-api-key'], signed.request.apiKey);
                assert.equal(headers['x-api-sign-version'], '2');
                assert.equal(headers['x-api-nonce'], signed.request.nonce);
                assert.equal(headers['x-api-version'], signed.request.apiVersion || undefined);
            });
        }
    });
});

describe('src/keys.js on test-vectors/keypair-challenge-v1.json', () => {
    describe('every case: the proof string built, then the registration\'s verdict', () => {
        for (const vector of CHALLENGE_VECTORS.cases) {
            it(`${vector.name} → ${vector.expected.valid ? 'valid' : vector.expected.reason}`, () => {
                const { signed, verify } = vector;

                const built = keys.challengeProofMessage(signed);
                if (vector.category === 'signed_string') {
                    assert.notEqual(built.toString('base64'), signed.proofStringBase64);
                } else {
                    assert.equal(built.toString('base64'), signed.proofStringBase64);
                    assert.equal(built.toString('utf8'), signed.proofString);
                }

                // The registration rebuilds the proof string from the pasted key's own fingerprint.
                const ok = keys.verifyChallengeProof(publicKeyNamed(CHALLENGE_VECTORS, verify.publicKey), verify);
                assert.deepEqual(ok ? { valid: true } : { valid: false, reason: 'api_key_public_key_proof_invalid' }, vector.expected);
            });
        }
    });

    describe('signing: prove makes the vector\'s proof', () => {
        for (const vector of CHALLENGE_VECTORS.cases.filter(candidate => candidate.category === 'valid')) {
            it(vector.name, () => {
                const { signed } = vector;
                const key = privateKeyNamed(CHALLENGE_VECTORS, signed.key);
                const signature = keys.signChallengeProof(key, { apiKeyId: signed.apiKeyId, challenge: signed.challenge });
                if (signed.algorithm === 'ed25519') {
                    assert.equal(signature, signed.signature);
                } else {
                    const der = Buffer.from(signature, 'base64');
                    assert.equal(der.toString('base64'), signature);
                    assert.deepEqual([der[0], der[1]], [0x30, der.length - 2], 'one DER SEQUENCE');
                }
                assert.equal(keys.verifyChallengeProof(publicKeyNamed(CHALLENGE_VECTORS, signed.key), {
                    apiKeyId: signed.apiKeyId, challenge: signed.challenge, signature,
                }), true);
            });
        }
    });

    describe('the challenge format: only the exact form is a challenge', () => {
        const key = privateKeyNamed(CHALLENGE_VECTORS, 'ed25519');
        for (const formatCase of CHALLENGE_VECTORS.challengeFormat) {
            it(`${JSON.stringify(formatCase.challenge)} → ${formatCase.valid ? 'valid' : 'refused'}`, () => {
                assert.equal(keys.isChallenge(formatCase.challenge), formatCase.valid);
                const prove = () => keys.signChallengeProof(key, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d4', challenge: formatCase.challenge });
                if (formatCase.valid) {
                    assert.match(prove(), /^[A-Za-z0-9+/]{86}==$/);
                } else {
                    assert.throws(prove, keys.UsageError);
                }
            });
        }
    });
});
