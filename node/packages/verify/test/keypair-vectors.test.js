'use strict';

// The shared vectors for the customer key-pair signature (test-vectors/request-keypair-v1.json) and the
// proof of possession at registration (test-vectors/keypair-challenge-v1.json). For every case this builds
// the signed string from the request fields the way a client must, checks it against the bytes in the
// vector, then verifies the signature the way the API does and expects the
// vector's verdict. They are the contract for the SDKs' request signing.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { strictBase64 } = require('../src/encoding');

const REQUEST_VECTORS = require('../../../../test-vectors/request-keypair-v1.json');
const CHALLENGE_VECTORS = require('../../../../test-vectors/keypair-challenge-v1.json');

const REQUEST_TAG = 'vaultody-request-keypair-v1';
const CHALLENGE_TAG = 'vaultody-keypair-challenge-v1';
const CHALLENGE_FORMAT = /^vk-chal-[0-9a-f]{64}$/;

/** The string a client signs for x-api-keypair-sign, as UTF-8: the tag, the x-api-key, then the HMAC v2 fields */
const requestSignedString = request => Buffer.from([
    REQUEST_TAG, request.apiKey, request.timestamp, request.method, request.path, request.apiVersion, request.passphrase, request.nonce, request.query, request.body,
].join('\n'), 'utf8');

const challengeProofString = ({ apiKeyId, fingerprint, challenge }) => Buffer.from([CHALLENGE_TAG, apiKeyId, fingerprint, challenge].join('\n'), 'utf8');

/**
 * What a registration makes of a pasted public key: Ed25519 or P-256 only, a private key refused before
 * parsing, the fingerprint over the canonical SPKI DER (a P-256 point uncompressed, through its coordinates).
 */
function publicKeyOf(pem) {
    if (pem.includes('PRIVATE KEY')) {
        return { error: 'api_key_public_key_is_private' };
    }

    let key;
    try {
        key = crypto.createPublicKey(pem);
    } catch (e) {
        return { error: 'api_key_public_key_invalid' };
    }

    let algorithm;
    if (key.asymmetricKeyType === 'ed25519') {
        algorithm = 'ed25519';
    } else if (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails.namedCurve === 'prime256v1') {
        algorithm = 'p-256';
        key = crypto.createPublicKey({ key: key.export({ format: 'jwk' }), format: 'jwk' });
    } else {
        return { error: 'api_key_public_key_unsupported_algorithm' };
    }

    const spkiDer = key.export({ format: 'der', type: 'spki' });
    const fingerprint = `SHA256:${crypto.createHash('sha256').update(spkiDer).digest('base64').replace(/=+$/, '')}`;

    return { algorithm, canonicalSpkiDerBase64: spkiDer.toString('base64'), fingerprint, key };
}

/** Ed25519: the raw 64 bytes; P-256: ECDSA SHA-256 in DER, which OpenSSL accepts only in its one encoding */
function signatureVerifies(publicKey, message, signatureText) {
    const signature = strictBase64(signatureText);
    if (!signature) {
        return false;
    }

    try {
        return publicKey.algorithm === 'ed25519'
            ? signature.length === 64 && crypto.verify(null, message, publicKey.key, signature)
            : crypto.verify('sha256', message, { key: publicKey.key, dsaEncoding: 'der' }, signature);
    } catch (e) {
        return false;
    }
}

const publicKeyNamed = (vectors, name) => publicKeyOf(vectors.keys[name].publicKeySpkiPem);
const withoutKey = ({ key, ...rest }) => rest;
const verdictOf = ok => (ok ? { valid: true } : null);

describe('test-vectors/request-keypair-v1.json', () => {
    it('is the v1 format, with cases in every category and both algorithms', () => {
        assert.equal(REQUEST_VECTORS.format, 'vaultody request key-pair signatures, v1');
        assert.match(REQUEST_VECTORS.warning, /TEST-ONLY/);
        const categories = new Set(REQUEST_VECTORS.cases.map(vector => vector.category));
        for (const category of ['valid', 'tampered', 'key', 'encoding', 'signed_string']) {
            assert.ok(categories.has(category), `no ${category} cases`);
        }
        const validAlgorithms = new Set(REQUEST_VECTORS.cases.filter(vector => vector.expected.valid).map(vector => vector.signed.algorithm));
        assert.deepEqual([...validAlgorithms].sort(), ['ed25519', 'p-256']);
    });

    it('signs the x-api-key: a request signed for one API key is refused under another with the same key pair', () => {
        const swapped = REQUEST_VECTORS.cases.find(vector => vector.name === 'signed_for_other_api_key');
        assert.ok(swapped, 'no signed_for_other_api_key case');
        assert.notEqual(swapped.verify.request.apiKey, swapped.signed.request.apiKey);
        assert.deepEqual({ ...swapped.verify.request, apiKey: swapped.signed.request.apiKey }, swapped.signed.request);
        assert.deepEqual(swapped.expected, { valid: false, reason: 'invalid_api_keypair_sign' });
        for (const vector of REQUEST_VECTORS.cases) {
            assert.equal(typeof vector.verify.request.apiKey, 'string', vector.name);
        }
    });

    describe('the keys', () => {
        for (const [name, key] of Object.entries(REQUEST_VECTORS.keys)) {
            it(`${name}: fingerprint and public half match`, () => {
                const parsed = publicKeyOf(key.publicKeySpkiPem);
                assert.equal(parsed.fingerprint, key.fingerprint);
                assert.equal(parsed.algorithm, key.algorithm);
                assert.equal(crypto.createPublicKey(key.privateKeyPkcs8Pem).export({ format: 'der', type: 'spki' }).toString('base64'), key.publicKeySpkiDerBase64);
            });
        }
    });

    describe('public keys as pasted', () => {
        for (const keyCase of REQUEST_VECTORS.publicKeys) {
            it(`${keyCase.name} → ${keyCase.expected.error || keyCase.expected.fingerprint}`, () => {
                assert.deepEqual(withoutKey(publicKeyOf(keyCase.publicKeyPem)), keyCase.expected);
            });
        }
    });

    describe('every case: signing-string build, then verify', () => {
        for (const vector of REQUEST_VECTORS.cases) {
            it(`${vector.name} → ${vector.expected.valid ? 'valid' : vector.expected.reason}`, () => {
                const { signed, verify } = vector;

                // 1. The client's signed string, from the request fields
                const built = requestSignedString(signed.request);
                if (vector.category === 'signed_string') {
                    // what was signed here is not that string: that is the point of the case
                    assert.notEqual(built.toString('base64'), signed.signedStringBase64);
                } else {
                    assert.equal(built.toString('base64'), signed.signedStringBase64);
                    assert.equal(built.toString('utf8'), signed.signedString);
                    assert.ok(signatureVerifies(publicKeyNamed(REQUEST_VECTORS, signed.key), built, signed.signature), 'the signer signed it');
                }

                // 2. The gateway's check, on the request and headers as received
                const registered = verify.registeredKeys.map(name => publicKeyNamed(REQUEST_VECTORS, name));
                const publicKey = registered.find(candidate => candidate.fingerprint === verify.headers['x-api-keypair-id']);
                let verdict;
                if (!publicKey) {
                    verdict = { valid: false, reason: 'unknown_api_keypair_id' };
                } else {
                    verdict = verdictOf(signatureVerifies(publicKey, requestSignedString(verify.request), verify.headers['x-api-keypair-sign']))
                        || { valid: false, reason: 'invalid_api_keypair_sign' };
                }
                assert.deepEqual(verdict, vector.expected);
            });
        }
    });
});

describe('test-vectors/keypair-challenge-v1.json', () => {
    it('is the v1 format and shares the request vectors\' keys', () => {
        assert.equal(CHALLENGE_VECTORS.format, 'vaultody key-pair proof of possession, challenge v1');
        assert.deepEqual(CHALLENGE_VECTORS.keys, REQUEST_VECTORS.keys);
    });

    describe('every case: proof-string build, then verify', () => {
        for (const vector of CHALLENGE_VECTORS.cases) {
            it(`${vector.name} → ${vector.expected.valid ? 'valid' : vector.expected.reason}`, () => {
                const { signed, verify } = vector;

                const built = challengeProofString(signed);
                if (vector.category === 'signed_string') {
                    assert.notEqual(built.toString('base64'), signed.proofStringBase64);
                } else {
                    assert.equal(built.toString('base64'), signed.proofStringBase64);
                    assert.ok(signatureVerifies(publicKeyNamed(CHALLENGE_VECTORS, signed.key), built, signed.signature), 'the signer signed it');
                }

                // The registration rebuilds the proof from the pasted key's own fingerprint
                const publicKey = publicKeyNamed(CHALLENGE_VECTORS, verify.publicKey);
                const proof = challengeProofString({ apiKeyId: verify.apiKeyId, fingerprint: publicKey.fingerprint, challenge: verify.challenge });
                const verdict = verdictOf(CHALLENGE_FORMAT.test(verify.challenge) && signatureVerifies(publicKey, proof, verify.signature))
                    || { valid: false, reason: 'api_key_public_key_proof_invalid' };
                assert.deepEqual(verdict, vector.expected);
            });
        }
    });

    describe('the challenge format a client checks before signing', () => {
        for (const formatCase of CHALLENGE_VECTORS.challengeFormat) {
            it(`${JSON.stringify(formatCase.challenge)} → ${formatCase.valid ? 'valid' : 'refused'}`, () => {
                assert.equal(CHALLENGE_FORMAT.test(formatCase.challenge), formatCase.valid);
            });
        }
    });
});
