'use strict';

// Every case in the shared vectors must come out exactly as the gateway's reference verifier says: same
// verdict, same reason. The vectors are the contract between the gateway and every client helper.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const crypto = require('node:crypto');

const { verifyResponse, MAX_CERT_LIFETIME_SECONDS } = require('../src/response');
const { VECTORS, exchangeOf, optionsOf, verdictOf, rootPem } = require('./helpers');

const asHeaders = plain => {
    const headers = new Headers();
    for (const [name, value] of Object.entries(plain)) {
        headers.append(name, value);
    }

    return headers;
};

const asMap = plain => new Map(Object.entries(plain));

const SHAPES = {
    'plain object': plain => plain,
    'fetch Headers': asHeaders,
    Map: asMap,
};

describe('test-vectors/v1.json', () => {
    it('is the v1 format and has cases in every category', () => {
        assert.equal(VECTORS.format, 'vaultody signed API responses, wire format v1');
        assert.equal(VECTORS.verifier.skewSeconds, 300);
        const categories = new Set(VECTORS.cases.map(vector => vector.category));
        for (const category of ['valid', 'tampered', 'binding', 'time', 'root', 'certificate_form', 'header']) {
            assert.ok(categories.has(category), `no ${category} cases`);
        }
        for (const vector of VECTORS.cases) {
            // The helper takes path and query as one target split at the first "?", so a path holding
            // one would not round-trip.
            assert.ok(!vector.verify.request.path.includes('?'), `${vector.name} path holds a "?"`);
        }
    });

    for (const [shape, toShape] of Object.entries(SHAPES)) {
        describe(`headers as a ${shape}`, () => {
            for (const vector of VECTORS.cases) {
                it(`${vector.name} → ${vector.expected.valid ? 'valid' : vector.expected.reason}`, () => {
                    const exchange = exchangeOf(vector, toShape(vector.verify.response.headers));
                    const verdict = verdictOf(() => verifyResponse(exchange, optionsOf(vector)));
                    assert.deepEqual(verdict, vector.expected);
                });
            }
        });
    }

    describe('a valid case reports which key and root signed it', () => {
        for (const vector of VECTORS.cases.filter(candidate => candidate.expected.valid)) {
            it(vector.name, () => {
                const result = verifyResponse(exchangeOf(vector), optionsOf(vector));
                assert.deepEqual(result, {
                    verified: true,
                    keyId: vector.signed.certificate.keyId,
                    rootId: vector.signed.certificate.rootId,
                    timestamp: vector.signed.ts,
                });
            });
        }
    });
});

describe('the certificate lifetime', () => {
    const ROOT = VECTORS.keys.roots.current;
    const POD = VECTORS.keys.podKeys.pod1;
    const NOT_BEFORE = 1794200000;

    /** A response signed by pod 1 under a certificate the current root signed for [notBefore, notAfter] */
    function signedUnder(notAfter) {
        const cert = Buffer.from(['vaultody-response-key-v1', ROOT.rootId, POD.publicKeyBase64, POD.keyId, String(NOT_BEFORE), String(notAfter)].join('\n'), 'ascii');
        const rootSignature = crypto.sign('sha256', cert, crypto.createPrivateKey(ROOT.privateKeyPkcs8Pem));
        const ts = NOT_BEFORE + 1000;
        const body = Buffer.from('{"ok":true}');
        const head = ['vaultody-response-v1', String(ts), '200', 'GET', '/vaults', '', crypto.createHash('sha256').update('').digest('hex'), '', ''].join('\n');
        const signature = crypto.sign(null, Buffer.concat([Buffer.from(`${head}\n`, 'ascii'), body]), crypto.createPrivateKey(POD.privateKeyPkcs8Pem));

        return verdictOf(() => verifyResponse({
            request: { method: 'GET', url: '/vaults', body: '', apiSign: '', keypairSign: '' },
            response: {
                status: 200,
                headers: {
                    'x-api-response-sign': signature.toString('base64'),
                    'x-api-response-timestamp': String(ts),
                    'x-api-response-sign-version': '1',
                    'x-api-response-cert': `${cert.toString('base64')}.${rootSignature.toString('base64')}`,
                },
                body,
            },
        }, { roots: [rootPem('current')], now: ts + 2 }));
    }

    it('is at most 3600 seconds, as the vectors say', () => {
        assert.equal(MAX_CERT_LIFETIME_SECONDS, 3600);
        assert.equal(VECTORS.verifier.maxCertificateLifetimeSeconds, MAX_CERT_LIFETIME_SECONDS);
    });

    it('accepts a certificate valid for exactly 3600 seconds', () => {
        assert.deepEqual(signedUnder(NOT_BEFORE + 3600), { valid: true });
    });

    it('refuses one valid for 3601 seconds as invalid, though the response is inside its window', () => {
        assert.deepEqual(signedUnder(NOT_BEFORE + 3601), { valid: false, reason: 'invalid' });
    });
});
