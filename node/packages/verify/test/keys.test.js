'use strict';

// src/keys.js beyond the shared vectors: which key files it takes and refuses, the canonical P-256
// fingerprint, how a new key pair is written to disk, the request it signs and the API root it accepts.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, describe, it } = require('node:test');

const keys = require('../src/keys');

const REQUEST_VECTORS = require('../../../../test-vectors/request-keypair-v1.json');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-keys-'));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
let counter = 0;
const tmpDir = () => {
    const dir = path.join(tmp, String(counter += 1));
    fs.mkdirSync(dir);

    return dir;
};

const modeOf = file => fs.statSync(file).mode & 0o777;
const refusedWith = code => error => error instanceof keys.SigningKeyError && error.code === code;

describe('readSigningKey', () => {
    const ed25519 = crypto.generateKeyPairSync('ed25519');
    const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    it('reads PKCS#8 and SEC1 P-256 private keys and the public key to one fingerprint', () => {
        const pkcs8 = keys.readSigningKey(p256.privateKey.export({ format: 'pem', type: 'pkcs8' }));
        const sec1 = keys.readSigningKey(p256.privateKey.export({ format: 'pem', type: 'sec1' }));
        const spki = keys.readSigningKey(p256.publicKey.export({ format: 'pem', type: 'spki' }));
        assert.equal(pkcs8.algorithm, 'p-256');
        assert.equal(sec1.fingerprint, pkcs8.fingerprint);
        assert.equal(spki.fingerprint, pkcs8.fingerprint);
        assert.match(pkcs8.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/);
    });

    it('fingerprints a compressed P-256 point as the uncompressed one', () => {
        const compressed = REQUEST_VECTORS.publicKeys.find(keyCase => keyCase.name === 'p256_compressed');
        const key = keys.readSigningKey(compressed.publicKeyPem);
        assert.equal(key.fingerprint, REQUEST_VECTORS.keys.p256.fingerprint);
        assert.equal(key.spkiDer.length, 91);
        assert.equal(key.publicKeyPem, REQUEST_VECTORS.keys.p256.publicKeySpkiPem);
    });

    it('takes CRLF line endings and surrounding whitespace', () => {
        const pem = ed25519.publicKey.export({ format: 'pem', type: 'spki' });
        assert.equal(keys.readSigningKey(`\n  ${pem.replace(/\n/g, '\r\n')}  \n`).fingerprint, keys.readSigningKey(pem).fingerprint);
    });

    it('refuses a public key where the private key is needed, and a private key where only a public key belongs', () => {
        assert.throws(() => keys.readSigningKey(ed25519.publicKey.export({ format: 'pem', type: 'spki' }), { accept: 'private' }), refusedWith('public_key'));
        for (const pem of [
            ed25519.privateKey.export({ format: 'pem', type: 'pkcs8' }),
            p256.privateKey.export({ format: 'pem', type: 'sec1' }),
            ed25519.privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: 'TEST-ONLY' }),
            JSON.stringify(ed25519.privateKey.export({ format: 'jwk' })),
            '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n',
            'PuTTY-User-Key-File-3: ssh-ed25519\n',
        ]) {
            assert.throws(() => keys.readSigningKey(pem, { accept: 'public' }), refusedWith('private_key'));
        }
    });

    it('refuses other key types and curves, naming the type', () => {
        const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
        const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
        const x25519 = crypto.generateKeyPairSync('x25519');
        const cases = [
            [rsa.publicKey.export({ format: 'pem', type: 'spki' }), /RSA/],
            [rsa.publicKey.export({ format: 'pem', type: 'pkcs1' }), /RSA/],
            [rsa.privateKey.export({ format: 'pem', type: 'pkcs1' }), /RSA/],
            [rsa.privateKey.export({ format: 'pem', type: 'pkcs8' }), /RSA/],
            [p384.publicKey.export({ format: 'pem', type: 'spki' }), /P-384/],
            [p384.privateKey.export({ format: 'pem', type: 'pkcs8' }), /P-384/],
            [x25519.publicKey.export({ format: 'pem', type: 'spki' }), /X25519/],
        ];
        for (const [pem, named] of cases) {
            assert.throws(() => keys.readSigningKey(pem), error => refusedWith('unsupported_algorithm')(error) && named.test(error.message)
                && /Ed25519 and ECDSA P-256/.test(error.message));
        }
    });

    it('refuses an encrypted private key', () => {
        for (const pem of [
            ed25519.privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: 'TEST-ONLY' }),
            p256.privateKey.export({ format: 'pem', type: 'sec1', cipher: 'aes-256-cbc', passphrase: 'TEST-ONLY' }),
        ]) {
            assert.throws(() => keys.readSigningKey(pem), refusedWith('encrypted_key'));
        }
    });

    it('refuses anything that is not one PEM key', () => {
        const publicPem = ed25519.publicKey.export({ format: 'pem', type: 'spki' });
        for (const text of [
            '',
            '   \n',
            'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8iBQ7a3hX4jxPS0Ue5SCjL5Lr8dHk5Ow9fKj4ApZx2 user@host',
            '-----BEGIN CERTIFICATE-----\nMIIBszCCAWWgAwIBAgIU\n-----END CERTIFICATE-----\n',
            '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n',
            publicPem + publicPem,
            '-----BEGIN PUBLIC KEY-----\nnot base64!\n-----END PUBLIC KEY-----\n',
            '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n',
            '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',
            '-----BEGIN DH PARAMETERS-----\nAAAA\n-----END DH PARAMETERS-----\n',
            'x'.repeat(20000),
            publicPem.replace('-----BEGIN PUBLIC KEY-----\n', '-----BEGIN PUBLIC KEY-----\n'.padEnd(5000, ' ')),
        ]) {
            assert.throws(() => keys.readSigningKey(text, { accept: 'public' }), keys.SigningKeyError, JSON.stringify(text.slice(0, 40)));
        }
    });

    it('takes a pasted public key of at most 1024 characters, as a registration does', () => {
        const pem = ed25519.publicKey.export({ format: 'pem', type: 'spki' });
        const padded = pem.padEnd(1024, '\n');
        assert.equal(padded.length, 1024);
        assert.equal(keys.readSigningKey(padded, { accept: 'public' }).fingerprint, keys.readSigningKey(pem).fingerprint);
        assert.throws(() => keys.readSigningKey(`${padded}\n`, { accept: 'public' }), error => refusedWith('invalid_key')(error)
            && /longer than 1024 characters/.test(error.message));
    });

    it('takes a PEM public key with CRLF, tabs and blank lines inside', () => {
        const pem = ed25519.publicKey.export({ format: 'pem', type: 'spki' });
        const [begin, body, end] = pem.trim().split('\n');
        const spaced = `${begin}\r\n\r\n\t${body.slice(0, 20)}\t\r\n  ${body.slice(20)}\r\n\r\n${end}\r\n`;
        assert.equal(keys.readSigningKey(spaced, { accept: 'public' }).fingerprint, keys.readSigningKey(pem).fingerprint);
    });

    // A lazy body between two runs of whitespace backtracked quadratically: seconds for a few thousand spaces
    it('reads a PEM in time linear in its length', () => {
        const begin = '-----BEGIN PUBLIC KEY-----';
        let started = Date.now();
        for (const text of [`${begin}${' '.repeat(1000)}A`, `${begin}${' \n'.repeat(495)}A`, `${begin}${' '.repeat(16 * 1024 - begin.length - 1)}A`]) {
            assert.throws(() => keys.readSigningKey(text), keys.SigningKeyError);
            assert.throws(() => keys.readSigningKey(text, { accept: 'public' }), keys.SigningKeyError);
        }
        assert.ok(Date.now() - started < 100, `took ${Date.now() - started} ms`);

        started = Date.now();
        assert.equal(keys.pemBody(`${begin}${' \n'.repeat(512 * 1024)}A`), null);
        assert.equal(keys.pemBody(`${begin}${' '.repeat(1024 * 1024)}-----END PUBLIC KEY-----`), ' '.repeat(1024 * 1024));
        assert.ok(Date.now() - started < 100, `took ${Date.now() - started} ms`);
    });

    it('never repeats key material in a refusal', () => {
        const privatePem = REQUEST_VECTORS.keys.ed25519.privateKeyPkcs8Pem;
        const body = privatePem.split('\n')[1];
        for (const [text, accept] of [[privatePem, 'public'], [privatePem.replace('PRIVATE KEY', 'PRIVATE  KEY'), 'any'], [privatePem.replace(body, `${body}x`), 'any']]) {
            assert.throws(() => keys.readSigningKey(text, { accept }), error => error instanceof keys.SigningKeyError && !error.message.includes(body.slice(0, 16)));
        }
    });
});

describe('generateSigningKeyPair', () => {
    for (const algorithm of ['ed25519', 'p-256']) {
        it(`${algorithm}: PKCS#8 private key, canonical SPKI public key, matching fingerprint`, () => {
            const pair = keys.generateSigningKeyPair(algorithm);
            assert.match(pair.privateKeyPem, /^-----BEGIN PRIVATE KEY-----\n/);
            assert.match(pair.publicKeyPem, /^-----BEGIN PUBLIC KEY-----\n/);
            const fromPrivate = keys.readSigningKey(pair.privateKeyPem, { accept: 'private' });
            const fromPublic = keys.inspectPublicKey(pair.publicKeyPem);
            assert.equal(fromPrivate.algorithm, algorithm);
            assert.equal(fromPrivate.fingerprint, pair.fingerprint);
            assert.equal(fromPublic.fingerprint, pair.fingerprint);
            assert.equal(fromPublic.publicKeyPem, pair.publicKeyPem, 'written in canonical form');
        });
    }

    it('refuses any other algorithm', () => {
        for (const algorithm of ['P-256', 'Ed25519', 'rsa', 'p256', '', undefined]) {
            assert.throws(() => keys.generateSigningKeyPair(algorithm), keys.UsageError);
        }
    });
});

describe('writeKeyPairFiles', () => {
    const pair = () => keys.generateSigningKeyPair('ed25519');
    const write = (dir, extra = {}) => {
        const generated = pair();
        keys.writeKeyPairFiles({
            privatePath: path.join(dir, 'private.pem'),
            publicPath: path.join(dir, 'public.pem'),
            privateKeyPem: generated.privateKeyPem,
            publicKeyPem: generated.publicKeyPem,
            ...extra,
        });

        return generated;
    };

    it('writes the private key with mode 0600 and the public key with 0644, whatever the umask', () => {
        const previous = process.umask(0o077);
        try {
            const dir = tmpDir();
            const generated = write(dir);
            assert.equal(modeOf(path.join(dir, 'private.pem')), 0o600);
            assert.equal(modeOf(path.join(dir, 'public.pem')), 0o644);
            assert.equal(fs.readFileSync(path.join(dir, 'private.pem'), 'utf8'), generated.privateKeyPem);
            assert.equal(fs.readFileSync(path.join(dir, 'public.pem'), 'utf8'), generated.publicKeyPem);
        } finally {
            process.umask(previous);
        }
    });

    it('never overwrites without force, and leaves nothing behind when it refuses', () => {
        const dir = tmpDir();
        const first = write(dir);
        assert.throws(() => write(dir), { code: 'EEXIST' });
        assert.equal(fs.readFileSync(path.join(dir, 'private.pem'), 'utf8'), first.privateKeyPem);

        // Only the public file exists: the private key it would have written first is removed again.
        const other = tmpDir();
        fs.writeFileSync(path.join(other, 'public.pem'), 'existing');
        assert.throws(() => write(other), { code: 'EEXIST' });
        assert.deepEqual(fs.readdirSync(other), ['public.pem']);
        assert.equal(fs.readFileSync(path.join(other, 'public.pem'), 'utf8'), 'existing');
    });

    it('never writes through a symlink, even a dangling one', () => {
        const dir = tmpDir();
        const target = path.join(dir, 'target');
        fs.symlinkSync(target, path.join(dir, 'private.pem'));
        assert.throws(() => write(dir), { code: 'EEXIST' });
        assert.equal(fs.existsSync(target), false);
    });

    it('with force replaces both files, with the private key again 0600 even if the old file was wider', () => {
        const dir = tmpDir();
        write(dir);
        fs.chmodSync(path.join(dir, 'private.pem'), 0o644);
        const second = write(dir, { force: true });
        assert.equal(fs.readFileSync(path.join(dir, 'private.pem'), 'utf8'), second.privateKeyPem);
        assert.equal(modeOf(path.join(dir, 'private.pem')), 0o600);
        assert.equal(modeOf(path.join(dir, 'public.pem')), 0o644);
    });

    it('with force replaces a symlink itself, not its target', () => {
        const dir = tmpDir();
        const target = path.join(dir, 'target');
        fs.writeFileSync(target, 'untouched');
        fs.symlinkSync(target, path.join(dir, 'private.pem'));
        write(dir, { force: true });
        assert.equal(fs.readFileSync(target, 'utf8'), 'untouched');
        assert.equal(fs.lstatSync(path.join(dir, 'private.pem')).isSymbolicLink(), false);
    });

    it('refuses one path for both keys', () => {
        const dir = tmpDir();
        const generated = pair();
        assert.throws(() => keys.writeKeyPairFiles({
            privatePath: path.join(dir, 'key.pem'),
            publicPath: path.join(dir, '.', 'key.pem'),
            privateKeyPem: generated.privateKeyPem,
            publicKeyPem: generated.publicKeyPem,
        }), keys.UsageError);
        assert.deepEqual(fs.readdirSync(dir), []);
    });
});

describe('readSigningKeyFile', () => {
    it('reads a key file, and refuses a missing file, a directory or a huge file without reading it', () => {
        const dir = tmpDir();
        const generated = keys.generateSigningKeyPair('p-256');
        fs.writeFileSync(path.join(dir, 'private.pem'), generated.privateKeyPem);
        assert.equal(keys.readSigningKeyFile(path.join(dir, 'private.pem'), { accept: 'private' }).fingerprint, generated.fingerprint);

        assert.throws(() => keys.readSigningKeyFile(path.join(dir, 'missing.pem')), keys.UsageError);
        assert.throws(() => keys.readSigningKeyFile(dir), keys.UsageError);
        fs.writeFileSync(path.join(dir, 'huge.pem'), Buffer.alloc(100000, 0x41));
        assert.throws(() => keys.readSigningKeyFile(path.join(dir, 'huge.pem')), refusedWith('invalid_key'));
    });
});

describe('challenge proofs', () => {
    const key = keys.readSigningKey(REQUEST_VECTORS.keys.ed25519.privateKeyPkcs8Pem);
    const challenge = `vk-chal-${'ab'.repeat(32)}`;

    it('refuses an API key id with whitespace and a challenge in any other form', () => {
        for (const apiKeyId of ['', ' 6630f1c2a9e4b5d7c8e9f0d4', '6630f1c2a9e4b5d7c8e9f0d4\n', 'a b']) {
            assert.throws(() => keys.signChallengeProof(key, { apiKeyId, challenge }), keys.UsageError);
        }
        assert.throws(() => keys.signChallengeProof(key, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d4', challenge: challenge.toUpperCase() }), keys.UsageError);
    });

    it('a proof binds the API key id, the key and the challenge', () => {
        const signature = keys.signChallengeProof(key, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d4', challenge });
        assert.equal(keys.verifyChallengeProof(key, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d4', challenge, signature }), true);
        assert.equal(keys.verifyChallengeProof(key, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d5', challenge, signature }), false);
        assert.equal(keys.verifyChallengeProof(key, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d4', challenge: `vk-chal-${'cd'.repeat(32)}`, signature }), false);
        const other = keys.readSigningKey(REQUEST_VECTORS.keys.ed25519_other.publicKeySpkiPem);
        assert.equal(keys.verifyChallengeProof(other, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d4', challenge, signature }), false);
        assert.equal(keys.verifyChallengeProof(key, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d4', challenge, signature: `${signature}\n` }), false);
    });

    it('isApiKeyId takes the 24 hex character id the dashboard shows', () => {
        assert.equal(keys.isApiKeyId('6630f1c2a9e4b5d7c8e9f0d4'), true);
        for (const text of ['6630f1c2a9e4b5d7c8e9f0d', '6630f1c2a9e4b5d7c8e9f0d4a', '6630f1c2a9e4b5d7c8e9f0dg', '', undefined]) {
            assert.equal(keys.isApiKeyId(text), false);
        }
    });
});

describe('signApiRequest', () => {
    const key = keys.readSigningKey(REQUEST_VECTORS.keys.p256.privateKeyPkcs8Pem);
    const apiSecret = crypto.randomBytes(32).toString('base64');
    const credentials = { apiKey: 'TEST-ONLY-api-key', apiSecret, passphrase: 'TEST-ONLY passphrase' };

    it('signs the HMAC v2 string with the decoded secret and the key-pair string with the private key, never sending the secret', () => {
        const fields = { method: 'GET', path: '/api-keys/current/signing-keys', timestamp: '1794201000', nonce: 'n-1' };
        const headers = keys.signApiRequest(key, credentials, fields);
        const v2 = ['v2', '1794201000', 'GET', '/api-keys/current/signing-keys', '', 'TEST-ONLY passphrase', 'n-1', '', ''].join('\n');
        assert.equal(headers['x-api-sign'], crypto.createHmac('sha256', Buffer.from(apiSecret, 'base64')).update(v2).digest('base64'));
        assert.deepEqual(keys.verifyKeypairRequest([key], { ...fields, apiKey: credentials.apiKey, passphrase: credentials.passphrase }, {
            keypairId: headers['x-api-keypair-id'], keypairSign: headers['x-api-keypair-sign'],
        }), { valid: true });
        assert.deepEqual(Object.keys(headers).sort(), [
            'x-api-key', 'x-api-keypair-id', 'x-api-keypair-sign', 'x-api-nonce', 'x-api-passphrase', 'x-api-sign', 'x-api-sign-version', 'x-api-timestamp',
        ]);
        assert.equal(headers['x-api-key'], credentials.apiKey);
        assert.ok(!Object.values(headers).includes(apiSecret));
    });

    it('signs the x-api-key it sends: under another API key with the same key pair, the key-pair signature is refused', () => {
        const fields = { method: 'POST', path: '/vaults/v/transaction-requests', body: '{}', timestamp: '1794201000', nonce: 'n-2' };
        const headers = keys.signApiRequest(key, credentials, fields);
        const received = { ...fields, passphrase: credentials.passphrase };
        const sentWith = { keypairId: headers['x-api-keypair-id'], keypairSign: headers['x-api-keypair-sign'] };

        assert.equal(keys.keypairRequestMessage({ ...received, apiKey: credentials.apiKey }).toString('utf8').split('\n')[1], credentials.apiKey);
        assert.deepEqual(keys.verifyKeypairRequest([key], { ...received, apiKey: credentials.apiKey }, sentWith), { valid: true });
        assert.deepEqual(keys.verifyKeypairRequest([key], { ...received, apiKey: 'TEST-ONLY-other-api-key' }, sentWith), {
            valid: false, reason: 'invalid_api_keypair_sign',
        });
    });

    it('keypairRequestMessage refuses an API key that is missing or not one line', () => {
        const fields = { method: 'GET', path: '/a', timestamp: '1794201000', passphrase: 'p', nonce: 'n-1' };
        for (const apiKey of [undefined, '', 'k\nx', 'k\r']) {
            assert.throws(() => keys.keypairRequestMessage({ ...fields, apiKey }), keys.UsageError);
        }
    });

    it('makes a fresh nonce and the current timestamp when none is given', () => {
        const before = Math.floor(Date.now() / 1000);
        const first = keys.signApiRequest(key, credentials, { method: 'GET', path: '/a' });
        const second = keys.signApiRequest(key, credentials, { method: 'GET', path: '/a' });
        assert.match(first['x-api-nonce'], /^[0-9a-f]{32}$/);
        assert.notEqual(first['x-api-nonce'], second['x-api-nonce']);
        assert.ok(Number(first['x-api-timestamp']) >= before && Number(first['x-api-timestamp']) <= before + 5);
    });

    it('refuses missing credentials, a secret that is not base64, a bad nonce and a public key', () => {
        for (const bad of [{ apiKey: '' }, { apiSecret: undefined }, { passphrase: '' }, { apiSecret: '!!!!' }]) {
            assert.throws(() => keys.signApiRequest(key, { ...credentials, ...bad }, { method: 'GET', path: '/a' }), keys.UsageError);
        }
        for (const nonce of ['has space', 'x'.repeat(129), 'ü']) {
            assert.throws(() => keys.signApiRequest(key, credentials, { method: 'GET', path: '/a', nonce }), keys.UsageError);
        }
        const publicOnly = keys.readSigningKey(REQUEST_VECTORS.keys.p256.publicKeySpkiPem);
        assert.throws(() => keys.signApiRequest(publicOnly, credentials, { method: 'GET', path: '/a' }), TypeError);
    });
});

describe('API versions', () => {
    it('isApiVersion takes YYYY-MM-DD only', () => {
        for (const version of ['2026-03-20', '2024-12-12', '2027-01-31']) {
            assert.equal(keys.isApiVersion(version), true, version);
        }
        for (const version of ['2026-3-20', '2026-13-01', '2026-03-32', '2026-03-00', '26-03-20', '2026-03-20 ', 'v2', '', undefined, 20260320]) {
            assert.equal(keys.isApiVersion(version), false, String(version));
        }
    });

    it('signApiRequest puts x-api-version on its own line of both signed strings and in the header', () => {
        const key = keys.readSigningKey(REQUEST_VECTORS.keys.ed25519.privateKeyPkcs8Pem);
        const apiSecret = Buffer.from('TEST-ONLY secret').toString('base64');
        const fields = { method: 'GET', path: '/api-keys/current/signing-keys', apiVersion: keys.SIGNING_KEYS_API_VERSION, timestamp: '1794201000', nonce: 'n-1' };
        const headers = keys.signApiRequest(key, { apiKey: 'k', apiSecret, passphrase: 'p' }, fields);
        assert.equal(keys.SIGNING_KEYS_API_VERSION, '2026-03-20');
        assert.equal(headers['x-api-version'], '2026-03-20');
        const lines = ['1794201000', 'GET', '/api-keys/current/signing-keys', '2026-03-20', 'p', 'n-1', '', ''];
        assert.equal(headers['x-api-sign'], crypto.createHmac('sha256', Buffer.from(apiSecret, 'base64')).update(['v2', ...lines].join('\n')).digest('base64'));
        assert.equal(keys.keypairRequestMessage({ ...fields, apiKey: 'k', passphrase: 'p' }).toString('utf8'), ['vaultody-request-keypair-v1', 'k', ...lines].join('\n'));
        assert.equal(headers['x-api-keypair-sign'], crypto.sign(null, keys.keypairRequestMessage({ ...fields, apiKey: 'k', passphrase: 'p' }), key.privateKey).toString('base64'));
    });
});

describe('signingKeysUrl', () => {
    it('puts the endpoint under the root, keeping a path prefix', () => {
        assert.equal(keys.signingKeysUrl().href, 'https://rest.vaultody.com/api-keys/current/signing-keys');
        assert.equal(keys.signingKeysUrl('https://rest.example.test/').href, 'https://rest.example.test/api-keys/current/signing-keys');
        assert.equal(keys.signingKeysUrl('http://127.0.0.1:8080/v2/').pathname, '/v2/api-keys/current/signing-keys');
    });

    it('takes plain http only to this machine, for a port-forward', () => {
        for (const root of ['http://localhost:8080', 'http://127.0.0.1:1', 'http://127.10.0.3', 'http://[::1]:8080', 'http://LOCALHOST:8080/v2']) {
            assert.equal(keys.signingKeysUrl(root).protocol, 'http:', root);
        }
        for (const root of ['http://rest.vaultody.com', 'http://rest.example.test/', 'http://10.0.0.1:8080', 'http://192.168.1.10',
            'http://localhost.example.com', 'http://127.0.0.1.example.com', 'http://[::2]', 'http://0.0.0.0:8080']) {
            assert.throws(() => keys.signingKeysUrl(root), error => error instanceof keys.UsageError
                && /must be an https URL.*plain http is allowed only to this machine \(localhost, for a port-forward\)/.test(error.message), root);
        }
    });

    it('refuses other schemes, credentials, a query or a fragment, without repeating the root', () => {
        for (const root of ['rest.vaultody.com', 'ftp://rest.vaultody.com', 'https://user:TEST-ONLY-pw@rest.vaultody.com', 'https://rest.vaultody.com/?a=1', 'https://rest.vaultody.com/?', 'https://rest.vaultody.com/#x']) {
            assert.throws(() => keys.signingKeysUrl(root), error => error instanceof keys.UsageError && !error.message.includes('TEST-ONLY-pw'), root);
        }
    });
});

describe('package entry points', () => {
    it('exports the key API from ./keys and the package root', () => {
        const fromSubpath = require('@vaultody-com/verify/keys');
        const root = require('@vaultody-com/verify');
        assert.equal(fromSubpath.readSigningKeysResponse, keys.readSigningKeysResponse);
        for (const name of ['readSigningKey', 'readSigningKeyFile', 'inspectPublicKey', 'generateSigningKeyPair', 'signChallengeProof',
            'verifyChallengeProof', 'signApiRequest', 'readSigningKeysResponse', 'SigningKeyError']) {
            assert.equal(root[name], keys[name], name);
        }
    });

    it('does no network I/O and declares no command: the vaultody command line ships with @vaultody-com/sdk', () => {
        const manifest = require('@vaultody-com/verify/package.json');
        assert.equal(manifest.bin, undefined);
        assert.ok(!manifest.files.includes('bin/'));
        assert.equal(keys.checkRegisteredKey, undefined);
        for (const file of fs.readdirSync(path.join(__dirname, '..', 'src'), { recursive: true }).filter(name => name.endsWith('.js'))) {
            assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '..', 'src', file), 'utf8'), /require\('(?:node:)?(?:https?|http2|net|tls|dgram)'\)/, file);
        }
    });
});
