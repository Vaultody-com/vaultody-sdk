'use strict';

// Request signers: key files and PEM, a callback, and the AWS KMS, Cloud KMS and Vault transit adapters (with
// fakes that answer the way those services do, signing with node:crypto), each through the whole pipeline to
// the mock gateway, which checks the key-pair signature itself. And the refusals: a signer holding another
// key, a wrong length, a key file that is not a private key.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it } = require('node:test');

const { Vaultody, MemoryVaultKeyStore, ConfigurationError, pemSigner, fileSigner, awsKmsSigner, gcpKmsSigner, vaultTransitSigner } = require('../src');
const { prepareSigner } = require('../src/signer');
const { setup, CREDENTIALS, KEYS, VAULT, rootPem } = require('./helpers');
const internal = require('../src/internal');

const privateKeyOf = name => crypto.createPrivateKey(KEYS[name].privateKeyPkcs8Pem);

/** A write through a client with this signer, against a gateway holding the key; resolves to the item. */
async function roundTrip(keyName, signer) {
    const env = await setup({ key: keyName });
    try {
        env.gw.route('POST', /\/addresses$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item: { address: 'a', label: 'l' } } } }));
        const client = new Vaultody({
            apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: env.gw.url,
            vaultKeyStore: new MemoryVaultKeyStore(), signer, roots: [rootPem('current')], logger: { warn() {} }, unsupported: { clock: env.clock },
        });
        const result = await internal.request(client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'l' });
        assert.equal((await client.confirmSigningKey()).keyMode, 'keypair');

        return result.item;
    } finally {
        await env.close();
    }
}

describe('signers through the pipeline', () => {
    it('pemSigner and fileSigner, Ed25519 and P-256', async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-signer-'));
        try {
            for (const name of ['ed25519', 'p256']) {
                const file = path.join(dir, `${name}.pem`);
                fs.writeFileSync(file, KEYS[name].privateKeyPkcs8Pem, { mode: 0o600 });
                assert.equal((await roundTrip(name, pemSigner(KEYS[name].privateKeyPkcs8Pem))).address, 'a');
                assert.equal((await roundTrip(name, fileSigner(file))).address, 'a');
            }
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('a callback signer, P-256 digest only', async () => {
        const key = privateKeyOf('p256');
        const signer = {
            algorithm: 'p-256',
            publicKeyPem: KEYS.p256.publicKeySpkiPem,
            digestOnly: true,
            // An HSM that signs a SHA-256 digest: ECDSA over the digest as given.
            sign: async digest => {
                assert.equal(digest.length, 32);

                return signDigest(key, digest);
            },
        };
        assert.equal((await roundTrip('p256', signer)).address, 'a');
    });

    it('awsKmsSigner: P-256 as DIGEST/ECDSA_SHA_256 (DER back), Ed25519 as RAW/ED25519_SHA_512', async () => {
        const seen = [];
        const kms = name => async params => {
            seen.push({ ...params, Message: Buffer.from(params.Message).length });
            const signature = name === 'p256' ? signDigest(privateKeyOf(name), Buffer.from(params.Message)) : crypto.sign(null, Buffer.from(params.Message), privateKeyOf(name));

            return { KeyId: params.KeyId, Signature: new Uint8Array(signature), SigningAlgorithm: params.SigningAlgorithm };
        };
        await roundTrip('p256', awsKmsSigner({ keyId: 'alias/sdk', algorithm: 'p-256', publicKeyPem: KEYS.p256.publicKeySpkiPem, sign: kms('p256') }));
        await roundTrip('ed25519', awsKmsSigner({ keyId: 'alias/sdk', algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, sign: kms('ed25519') }));
        assert.deepEqual(seen[0], { KeyId: 'alias/sdk', Message: 32, MessageType: 'DIGEST', SigningAlgorithm: 'ECDSA_SHA_256' });
        assert.equal(seen.find(item => item.SigningAlgorithm === 'ED25519_SHA_512').MessageType, 'RAW');

        const signer = prepareSigner(awsKmsSigner({ keyId: 'k', algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, sign: kms('ed25519') }));
        await assert.rejects(signer.sign(Buffer.alloc(5000)), error => error instanceof ConfigurationError && error.code === 'signer_message_too_large');
    });

    it('gcpKmsSigner: digest for P-256, data for Ed25519; the Node client\'s [response] form', async () => {
        const gcp = name => async request => [{ signature: name === 'p256' ? signDigest(privateKeyOf(name), Buffer.from(request.digest.sha256)) : crypto.sign(null, Buffer.from(request.data), privateKeyOf(name)) }];
        await roundTrip('p256', gcpKmsSigner({ name: 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1', algorithm: 'p-256', publicKeyPem: KEYS.p256.publicKeySpkiPem, asymmetricSign: gcp('p256') }));
        await roundTrip('ed25519', gcpKmsSigner({ name: 'n', algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, asymmetricSign: gcp('ed25519') }));
    });

    it('vaultTransitSigner: prehashed asn1 for P-256, the vault:v1: prefix removed', async () => {
        const writes = [];
        const vault = name => async (where, body) => {
            writes.push({ where, body });
            const input = Buffer.from(body.input, 'base64');
            const signature = name === 'p256' ? signDigest(privateKeyOf(name), input) : crypto.sign(null, input, privateKeyOf(name));

            return { data: { signature: `vault:v1:${signature.toString('base64')}` } };
        };
        await roundTrip('p256', vaultTransitSigner({ keyName: 'sdk', algorithm: 'p-256', publicKeyPem: KEYS.p256.publicKeySpkiPem, write: vault('p256') }));
        await roundTrip('ed25519', vaultTransitSigner({ keyName: 'sdk', mount: 'kms', algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, write: vault('ed25519') }));
        assert.equal(writes[0].where, 'transit/sign/sdk');
        assert.deepEqual({ ...writes[0].body, input: undefined }, { input: undefined, prehashed: true, hash_algorithm: 'sha2-256', marshaling_algorithm: 'asn1' });
        assert.ok(writes.some(item => item.where === 'kms/sign/sdk'));
    });
});

/**
 * ECDSA P-256 over a SHA-256 digest given as is, DER encoded: what a digest-signing KMS does. node:crypto always
 * hashes its input, so the signature is built from the private scalar: k random (an ephemeral key pair, whose
 * public point is kG), r = (kG).x mod n, s = k^-1 (z + r d) mod n.
 */
function signDigest(privateKey, digest) {
    const jwk = privateKey.export({ format: 'jwk' });
    const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    const d = BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`);
    const z = BigInt(`0x${digest.toString('hex')}`);
    for (;;) {
        const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const ek = ephemeral.privateKey.export({ format: 'jwk' });
        const k = BigInt(`0x${Buffer.from(ek.d, 'base64url').toString('hex')}`);
        const r = BigInt(`0x${Buffer.from(ek.x, 'base64url').toString('hex')}`) % n;
        if (r === 0n) {
            continue;
        }
        const s = (modInverse(k, n) * ((z + r * d) % n)) % n;
        if (s === 0n) {
            continue;
        }
        const p1363 = Buffer.from(r.toString(16).padStart(64, '0') + s.toString(16).padStart(64, '0'), 'hex');

        return require('@vaultody-com/verify/keys').p1363ToDer(p1363);
    }
}

function modInverse(a, m) {
    let [oldR, r] = [a % m, m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
        const q = oldR / r;
        [oldR, r] = [r, oldR - q * r];
        [oldS, s] = [s, oldS - q * s];
    }

    return ((oldS % m) + m) % m;
}

describe('signer refusals', () => {
    it('a signer holding another key fails locally, before anything is sent', async () => {
        const other = crypto.generateKeyPairSync('ed25519').privateKey;
        const signer = prepareSigner({ algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, sign: message => crypto.sign(null, message, other) });
        await assert.rejects(signer.sign(Buffer.from('m')), error => error instanceof ConfigurationError && error.code === 'signer_key_mismatch');
        // Switched off, the gateway would refuse it instead.
        const unchecked = prepareSigner({ algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, sign: message => crypto.sign(null, message, other) }, { verifyLocally: false });
        assert.equal(Buffer.from(await unchecked.sign(Buffer.from('m')), 'base64').length, 64);
    });

    it('an Ed25519 signature of another length, an algorithm that does not match the key, a bad shape', async () => {
        const short = prepareSigner({ algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, sign: () => Buffer.alloc(63) });
        await assert.rejects(short.sign(Buffer.from('m')), error => error.code === 'invalid_signature');
        assert.throws(() => prepareSigner({ algorithm: 'p-256', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, sign() {} }), error => error.code === 'invalid_signer');
        assert.throws(() => prepareSigner({ algorithm: 'ed25519', publicKeyPem: KEYS.ed25519.publicKeySpkiPem, digestOnly: true, sign() {} }), error => error.code === 'invalid_signer');
        assert.throws(() => prepareSigner({ algorithm: 'rsa', publicKeyPem: 'x', sign() {} }), error => error.code === 'invalid_signer');
        assert.throws(() => new Vaultody({ apiKey: 'k', apiSecret: CREDENTIALS.apiSecret, passphrase: 'p', vaultKeyStore: new MemoryVaultKeyStore(), signer: { sign: 1 } }), error => error.code === 'invalid_signer');
    });

    it('a key file must hold a private key, and its contents never reach an error', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-signer-'));
        try {
            const file = path.join(dir, 'public.pem');
            fs.writeFileSync(file, KEYS.ed25519.publicKeySpkiPem);
            assert.throws(() => fileSigner(file), error => error instanceof ConfigurationError && error.code === 'invalid_signer' && !error.message.includes('BEGIN'));
            assert.throws(() => fileSigner(path.join(dir, 'missing.pem')), error => error instanceof ConfigurationError);
            assert.throws(() => pemSigner(KEYS.ed25519.publicKeySpkiPem), error => error instanceof ConfigurationError);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('the fingerprint sent as x-api-keypair-id is the registered one', () => {
        assert.equal(prepareSigner({ algorithm: 'p-256', publicKeyPem: KEYS.p256.publicKeySpkiPem, sign() {} }).fingerprint, KEYS.p256.fingerprint);
        assert.equal(prepareSigner(pemSigner(KEYS.ed25519.privateKeyPkcs8Pem)).fingerprint, KEYS.ed25519.fingerprint);
    });
});
