'use strict';

// Root keys are the trust anchor. A missing or wrongly entered root must stop verification loudly with a
// configuration error, never quietly pass responses or blame them.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { describe, it } = require('node:test');

const { verifyResponse } = require('../src/response');
const { ConfigurationError, ResponseSignatureError } = require('../src/errors');
const { loadEmbeddedRoots } = require('../src/rootKeys');
const EMBEDDED_ROOTS = require('../src/roots');
const {
    VECTORS, caseNamed, exchangeOf, rootPem, withoutSignHeaders,
} = require('./helpers');

const current = caseNamed('valid_current_root');
const next = caseNamed('valid_next_root');
const fingerprintOf = name => VECTORS.keys.roots[name].rootId;
const embeddedIsEmpty = !EMBEDDED_ROOTS.current.pem && !EMBEDDED_ROOTS.next.pem;

const check = (vector, roots, extra = {}) => verifyResponse(exchangeOf(vector), { roots, now: vector.verify.now, ...extra });
const isConfigError = error => error instanceof ConfigurationError && !(error instanceof ResponseSignatureError);

describe('embedded roots', () => {
    it('has a current and a next slot, each a PEM with its fingerprint', () => {
        assert.deepEqual(Object.keys(EMBEDDED_ROOTS).sort(), ['current', 'next']);
        for (const slot of ['current', 'next']) {
            assert.deepEqual(Object.keys(EMBEDDED_ROOTS[slot]).sort(), ['fingerprint', 'pem']);
        }
        assert.ok(Object.isFrozen(EMBEDDED_ROOTS));
    });

    it('fails verification with a configuration error while no roots are embedded', { skip: !embeddedIsEmpty && 'production roots are embedded' }, () => {
        assert.throws(() => verifyResponse(exchangeOf(current), { now: current.verify.now }), isConfigError);
        assert.throws(() => verifyResponse(exchangeOf(current), { now: current.verify.now, roots: null }), isConfigError);
        assert.throws(() => verifyResponse(exchangeOf(current)), /no root keys are configured/);
    });

    it('needs no root for an unsigned response when not strict', { skip: !embeddedIsEmpty && 'production roots are embedded' }, () => {
        const unsigned = exchangeOf(current, withoutSignHeaders(current.verify.response.headers));
        assert.deepEqual(verifyResponse(unsigned, { now: current.verify.now, requireResponseSignature: false }), { verified: false, reason: 'missing' });
        assert.deepEqual(
            verifyResponse(unsigned, { now: current.verify.now, requireResponseSignature: false, roots: { current: '', next: { pem: '' } } }),
            { verified: false, reason: 'missing' },
        );
    });

    it('calls an unsigned response missing, not a setup mistake, when strict', { skip: !embeddedIsEmpty && 'production roots are embedded' }, () => {
        const unsigned = exchangeOf(current, withoutSignHeaders(current.verify.response.headers));
        assert.throws(() => verifyResponse(unsigned, { now: current.verify.now }), error => error instanceof ResponseSignatureError && error.reason === 'missing');
    });

    it('still fails closed on a signed response when the roots option holds no key', () => {
        assert.throws(() => check(current, { current: '', next: { pem: '' } }), isConfigError);
        assert.throws(() => check(current, []), isConfigError);
    });

    it('reports a malformed root at once, even for an unsigned response', () => {
        const unsigned = exchangeOf(current, withoutSignHeaders(current.verify.response.headers));
        assert.throws(() => verifyResponse(unsigned, { now: current.verify.now, requireResponseSignature: false, roots: 'not a key' }), isConfigError);
        assert.throws(() => verifyResponse(unsigned, { now: current.verify.now, requireResponseSignature: false, roots: 42 }), isConfigError);
    });

    it('accepts a slot only with a matching fingerprint', () => {
        const pinned = loadEmbeddedRoots({
            current: { pem: rootPem('current'), fingerprint: fingerprintOf('current') },
            next: { pem: rootPem('next'), fingerprint: fingerprintOf('next') },
        });
        assert.deepEqual(pinned.map(root => root.rootId), [fingerprintOf('current'), fingerprintOf('next')]);
        assert.deepEqual(loadEmbeddedRoots({ current: { pem: '', fingerprint: '' }, next: { pem: '', fingerprint: '' } }), []);
    });

    it('refuses a fingerprint that does not match its key', () => {
        assert.throws(() => loadEmbeddedRoots({
            current: { pem: rootPem('current'), fingerprint: fingerprintOf('next') },
            next: { pem: '', fingerprint: '' },
        }), /does not match its key/);
    });

    it('refuses a half-filled slot', () => {
        assert.throws(() => loadEmbeddedRoots({ current: { pem: rootPem('current'), fingerprint: '' } }), /a key but no fingerprint/);
        assert.throws(() => loadEmbeddedRoots({ next: { pem: '', fingerprint: fingerprintOf('next') } }), /a fingerprint but no key/);
    });

    it('stops the package from loading when an embedded fingerprint is wrong', () => {
        const badRoots = {
            current: { pem: rootPem('current'), fingerprint: fingerprintOf('next') },
            next: { pem: '', fingerprint: '' },
        };
        // A separate process gets a fresh module cache, with roots.js replaced before the package loads.
        const script = `
            const Module = require('node:module');
            const rootsPath = ${JSON.stringify(path.join(__dirname, '..', 'src', 'roots.js'))};
            const fake = new Module(rootsPath);
            fake.filename = rootsPath;
            fake.loaded = true;
            fake.exports = ${JSON.stringify(badRoots)};
            require.cache[rootsPath] = fake;
            require(${JSON.stringify(path.join(__dirname, '..', 'src', 'index.js'))});
        `;
        const child = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });

        assert.notEqual(child.status, 0);
        assert.match(child.stderr, /ConfigurationError/);
        assert.match(child.stderr, /embedded root "current" fingerprint/);
    });
});

describe('the roots option', () => {
    it('takes a PEM string, { pem }, { pem, fingerprint }, an array or { current, next }', () => {
        const forms = [
            rootPem('current'),
            { pem: rootPem('current') },
            { pem: rootPem('current'), fingerprint: fingerprintOf('current') },
            [rootPem('current')],
            [{ pem: rootPem('current') }, rootPem('next')],
            { current: rootPem('current'), next: null },
            { current: { pem: rootPem('current'), fingerprint: fingerprintOf('current') }, next: { pem: '', fingerprint: '' } },
        ];
        for (const roots of forms) {
            assert.equal(check(current, roots).rootId, fingerprintOf('current'));
        }
    });

    it('accepts certificates from both current and next during a rotation', () => {
        const roots = { current: rootPem('current'), next: rootPem('next') };
        assert.equal(check(current, roots).rootId, fingerprintOf('current'));
        assert.equal(check(next, roots).rootId, fingerprintOf('next'));
    });

    it('rejects certificates from a root that was dropped', () => {
        assert.throws(() => check(current, { current: rootPem('next') }), error => error.reason === 'unknown_root');
    });

    it('replaces the embedded roots rather than adding to them', () => {
        assert.throws(() => check(next, [rootPem('current')]), error => error.reason === 'unknown_root');
    });

    it('refuses an empty set of roots', () => {
        for (const roots of [[], {}, { current: '', next: null }, { current: { pem: '', fingerprint: '' } }, [null]]) {
            assert.throws(() => check(current, roots), isConfigError, JSON.stringify(roots));
        }
    });

    it('refuses a fingerprint that does not match, or is not lowercase hex', () => {
        assert.throws(() => check(current, { pem: rootPem('current'), fingerprint: fingerprintOf('next') }), isConfigError);
        assert.throws(() => check(current, { pem: rootPem('current'), fingerprint: fingerprintOf('current').toUpperCase() }), isConfigError);
    });

    it('refuses a compressed-point root, in the roots option and as an embedded root', () => {
        const point = crypto.createPublicKey(rootPem('current')).export({ format: 'jwk' });
        const compressedDer = Buffer.concat([
            Buffer.from('3039301306072a8648ce3d020106082a8648ce3d030107032200', 'hex'),
            Buffer.from([Buffer.from(point.y, 'base64url').at(-1) & 1 ? 0x03 : 0x02]),
            Buffer.from(point.x, 'base64url'),
        ]);
        const compressedPem = `-----BEGIN PUBLIC KEY-----\n${compressedDer.toString('base64')}\n-----END PUBLIC KEY-----\n`;
        const fingerprint = crypto.createHash('sha256').update(compressedDer).digest('hex');
        assert.deepEqual(crypto.createPublicKey(compressedPem).export({ format: 'jwk' }), point);
        assert.throws(() => check(current, compressedPem), isConfigError);
        assert.throws(() => check(current, { current: compressedPem }), isConfigError);
        assert.throws(() => loadEmbeddedRoots({ current: { pem: compressedPem, fingerprint }, next: { pem: '', fingerprint: '' } }), isConfigError);
    });

    it('refuses anything but one P-256 public key', () => {
        const ed25519 = crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' });
        const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey.export({ format: 'pem', type: 'spki' });
        const compressed = crypto.createPublicKey(rootPem('current')).export({ format: 'jwk' });
        const compressedDer = Buffer.concat([
            Buffer.from('3039301306072a8648ce3d020106082a8648ce3d030107032200', 'hex'),
            Buffer.from([Buffer.from(compressed.y, 'base64url').at(-1) & 1 ? 0x03 : 0x02]),
            Buffer.from(compressed.x, 'base64url'),
        ]);
        const compressedPem = `-----BEGIN PUBLIC KEY-----\n${compressedDer.toString('base64')}\n-----END PUBLIC KEY-----\n`;
        const invalid = [
            VECTORS.keys.roots.current.privateKeyPkcs8Pem,
            ed25519,
            p384,
            compressedPem,
            rootPem('current') + rootPem('next'),
            '-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n',
            VECTORS.keys.roots.current.publicKeySpkiDerBase64,
            Buffer.from('not a pem'),
            42,
        ];
        for (const roots of invalid) {
            assert.throws(() => check(current, [roots]), isConfigError, String(roots).slice(0, 40));
        }
    });
});
