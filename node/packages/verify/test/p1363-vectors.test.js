'use strict';

// test-vectors/p1363-der-v1.json: a P-256 signature as IEEE P1363 r||s (Web Crypto, Azure, some KMS APIs)
// turned into the DER form the gateway requires.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { p1363ToDer, SignatureFormatError } = require('../src/keys');

const VECTORS = require('../../../../test-vectors/p1363-der-v1.json');

describe('test-vectors/p1363-der-v1.json', () => {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(VECTORS.publicKeySpkiDerBase64, 'base64'), format: 'der', type: 'spki' });

    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            const input = Buffer.from(vector.p1363Hex, 'hex');
            if (vector.expected.error) {
                assert.throws(() => p1363ToDer(input), error => error instanceof SignatureFormatError && error.code === vector.expected.error);

                return;
            }
            const der = p1363ToDer(input);
            assert.equal(der.toString('hex'), vector.expected.derHex);
            if (vector.messageBase64 !== null) {
                const message = Buffer.from(vector.messageBase64, 'base64');
                assert.ok(crypto.verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, der));
            }
        });
    }

    it('takes a Uint8Array view at an offset', () => {
        const vector = VECTORS.cases.find(candidate => candidate.name === 'both_high_bits');
        const padded = new Uint8Array(70);
        padded.set(Buffer.from(vector.p1363Hex, 'hex'), 3);
        assert.equal(p1363ToDer(padded.subarray(3, 67)).toString('hex'), vector.expected.derHex);
    });

    it('refuses anything but bytes', () => {
        assert.throws(() => p1363ToDer('00'.repeat(64)), { code: 'invalid_length' });
    });
});
