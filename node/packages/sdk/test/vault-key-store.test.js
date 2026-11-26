'use strict';

// The pin stores: atomic compare-and-set, no automatic re-pin, the latch set once, and for the file store its
// modes (0700 directory, 0600 file), atomic replacement, sharing between processes through the lock, and
// failing closed on a file it can't read or that others can write. The default store falls back to memory,
// loudly, only when the file can't be written; an explicit file never does.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it, beforeEach, afterEach } = require('node:test');

const { MemoryVaultKeyStore, FileVaultKeyStore, defaultVaultKeysFile, VaultKeyStoreError, Vaultody } = require('../src');
const { CREDENTIALS } = require('./helpers');

const ORIGIN = 'https://rest.vaultody.com';
const XPUB_A = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
const XPUB_B = 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw';
const pin = (vaultId, xpub, status = 'unverified') => ({
    vaultId, type: 'main', keys: { ECDSA: xpub, EDDSA: null }, status, firstSeenAt: 100,
    verifiedAt: status === 'verified' ? 200 : null, verification: status === 'verified' ? { rootId: 'r', timestamp: 200 } : null,
});
const posix = process.platform !== 'win32';

for (const [name, make] of [
    ['MemoryVaultKeyStore', () => new MemoryVaultKeyStore()],
    ['FileVaultKeyStore', dir => new FileVaultKeyStore({ file: path.join(dir, 'pins', 'vault-keys.json') })],
]) {
    describe(name, () => {
        let dir;
        beforeEach(() => {
            dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-pins-'));
        });
        afterEach(() => {
            fs.rmSync(dir, { recursive: true, force: true });
        });

        it('pins once: a second pinIfAbsent returns what is stored and changes nothing', async () => {
            const store = make(dir);
            assert.deepEqual(await store.pinIfAbsent(ORIGIN, pin('v1', XPUB_A)), pin('v1', XPUB_A));
            assert.deepEqual(await store.pinIfAbsent(ORIGIN, pin('v1', XPUB_B)), pin('v1', XPUB_A));
            assert.deepEqual(await store.get(ORIGIN, 'v1'), pin('v1', XPUB_A));
            assert.equal(await store.get('https://qa.example', 'v1'), null);
        });

        it('upgrades an unverified pin only to the same xpubs, keeping when it was first seen', async () => {
            const store = make(dir);
            await store.pinIfAbsent(ORIGIN, pin('v1', XPUB_A));
            assert.deepEqual(await store.upgradeTrust(ORIGIN, { ...pin('v1', XPUB_B, 'verified') }), pin('v1', XPUB_A));
            const upgraded = await store.upgradeTrust(ORIGIN, { ...pin('v1', XPUB_A, 'verified'), firstSeenAt: 150 });
            assert.equal(upgraded.status, 'verified');
            assert.equal(upgraded.firstSeenAt, 100);
        });

        it('replace is explicit and recorded in the origin\'s audit list', async () => {
            const store = make(dir);
            await store.pinIfAbsent(ORIGIN, pin('v1', XPUB_A));
            await assert.rejects(store.replace(ORIGIN, pin('v1', XPUB_B), ''), TypeError);
            await store.replace(ORIGIN, pin('v1', XPUB_B), 'confirmed with support');
            assert.deepEqual(await store.get(ORIGIN, 'v1'), pin('v1', XPUB_B));
            const { audit } = (await store.read()).origins[ORIGIN];
            assert.equal(audit.length, 1);
            assert.deepEqual({ ...audit[0], at: 0 }, { vaultId: 'v1', at: 0, reason: 'confirmed with support', removed: false });
        });

        it('latches once and never clears', async () => {
            const store = make(dir);
            assert.equal(await store.getResponseSignatureLatch(ORIGIN), null);
            assert.deepEqual(await store.latchResponseSignature(ORIGIN, { latchedAt: 1, rootId: 'a' }), { latchedAt: 1, rootId: 'a' });
            assert.deepEqual(await store.latchResponseSignature(ORIGIN, { latchedAt: 2, rootId: 'b' }), { latchedAt: 1, rootId: 'a' });
            // Only the latch the file can hold: { latchedAt, rootId }, nothing else.
            for (const bad of [true, { latchedAt: 1 }, { latchedAt: 1.5, rootId: 'a' }, { latchedAt: 1, rootId: 'a', responseTimestamp: 1 }, { latchedAt: 1, rootId: '' }, { latchedAt: 1, rootId: 1 }]) {
                await assert.rejects(store.latchResponseSignature('https://other.example', bad), error => error instanceof VaultKeyStoreError && error.code === 'invalid_pin');
            }
        });

        it('latches with rootId null: a signed answer that did not verify', async () => {
            const store = make(dir);
            assert.deepEqual(await store.latchResponseSignature(ORIGIN, { latchedAt: 1, rootId: null }), { latchedAt: 1, rootId: null });
            assert.deepEqual(await store.getResponseSignatureLatch(ORIGIN), { latchedAt: 1, rootId: null });
            assert.deepEqual(await store.latchResponseSignature(ORIGIN, { latchedAt: 2, rootId: 'a' }), { latchedAt: 1, rootId: null });
        });

        it('refuses a malformed pin', async () => {
            const store = make(dir);
            await assert.rejects(store.pinIfAbsent(ORIGIN, { ...pin('v1', XPUB_A), keys: { ECDSA: null, EDDSA: null } }), VaultKeyStoreError);
            await assert.rejects(store.pinIfAbsent(ORIGIN, { ...pin('v1', XPUB_A), status: 'trusted' }), VaultKeyStoreError);
            await assert.rejects(store.pinIfAbsent(ORIGIN, { ...pin('v1', XPUB_A), type: 'MAIN' }), VaultKeyStoreError);
            await assert.rejects(store.pinIfAbsent(ORIGIN, { ...pin('v1', XPUB_A), replaced: { reason: 'x' } }), error => error.code === 'invalid_pin');
            await assert.rejects(store.pinIfAbsent(ORIGIN, { ...pin('v1', XPUB_A), firstSeenAt: 1.5 }), error => error.code === 'invalid_pin');
            await assert.rejects(store.pinIfAbsent('not an origin', pin('v1', XPUB_A)), TypeError);
        });
    });
}

describe('FileVaultKeyStore on disk', () => {
    let dir;
    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-pins-'));
    });
    afterEach(() => {
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('writes mode 0600 in a 0700 directory, and nothing but the pins', { skip: !posix }, async () => {
        const file = path.join(dir, 'new', 'vault-keys.json');
        await new FileVaultKeyStore({ file }).pinIfAbsent(ORIGIN, pin('v1', XPUB_A));
        assert.equal(fs.statSync(file).mode & 0o777, 0o600);
        assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
        assert.deepEqual(fs.readdirSync(path.dirname(file)), ['vault-keys.json']);
    });

    it('is shared: two stores on one file see each other\'s pins, and concurrent pins all land', async () => {
        const file = path.join(dir, 'vault-keys.json');
        const a = new FileVaultKeyStore({ file });
        const b = new FileVaultKeyStore({ file });
        await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? a : b).pinIfAbsent(ORIGIN, pin(`v${i}`, XPUB_A))));
        assert.equal((await a.list(ORIGIN)).length, 10);
        assert.equal((await b.get(ORIGIN, 'v3')).keys.ECDSA, XPUB_A);
    });

    it('fails closed on a file it can\'t parse, and never treats it as empty', async () => {
        const file = path.join(dir, 'vault-keys.json');
        for (const [contents, code] of [
            ['{not json', 'not_json'],
            ['{"format":"other","origins":{}}', 'unknown_format'],
            [JSON.stringify({ format: 'vaultody vault keys v1', origins: { [ORIGIN]: { responseSignature: null, vaults: { v1: { vaultId: 'v2' } }, audit: [] } } }), 'malformed'],
        ]) {
            fs.writeFileSync(file, contents, { mode: 0o600 });
            const store = new FileVaultKeyStore({ file, fallbackToMemory: true });
            await assert.rejects(store.get(ORIGIN, 'v1'), error => error instanceof VaultKeyStoreError && error.code === code);
            await assert.rejects(store.pinIfAbsent(ORIGIN, pin('v1', XPUB_A)), error => error instanceof VaultKeyStoreError && error.code === code);
            assert.equal(fs.readFileSync(file, 'utf8'), contents, 'a refused file is left as it is');
        }
    });

    it('refuses a pin file others can write', { skip: !posix }, async () => {
        const file = path.join(dir, 'vault-keys.json');
        await new FileVaultKeyStore({ file }).pinIfAbsent(ORIGIN, pin('v1', XPUB_A));
        fs.chmodSync(file, 0o666);
        await assert.rejects(new FileVaultKeyStore({ file }).get(ORIGIN, 'v1'), error => error.code === 'insecure_permissions');
    });

    it('writes only on a change: reading, a pin already stored, a latch already set, or an upgrade of nothing write nothing', async () => {
        const file = path.join(dir, 'vault-keys.json');
        const store = new FileVaultKeyStore({ file });
        await store.get(ORIGIN, 'v1');
        await store.list(ORIGIN);
        await store.getResponseSignatureLatch(ORIGIN);
        assert.equal(await store.upgradeTrust(ORIGIN, pin('v1', XPUB_A, 'verified')), null);
        assert.ok(!fs.existsSync(file), 'no file before something is stored');
        await store.pinIfAbsent(ORIGIN, pin('v1', XPUB_A));
        await store.latchResponseSignature(ORIGIN, { latchedAt: 1, rootId: 'r' });
        const written = fs.statSync(file).mtimeMs;
        const text = fs.readFileSync(file, 'utf8');
        const old = new Date(Date.now() - 60000);
        fs.utimesSync(file, old, old);
        await store.pinIfAbsent(ORIGIN, pin('v1', XPUB_B));
        await store.latchResponseSignature(ORIGIN, { latchedAt: 2, rootId: 's' });
        assert.ok(fs.statSync(file).mtimeMs < written, 'not rewritten');
        assert.equal(fs.readFileSync(file, 'utf8'), text);
    });

    it('refuses a symbolic link and a directory at the path', { skip: !posix }, async () => {
        const target = path.join(dir, 'real.json');
        await new FileVaultKeyStore({ file: target }).pinIfAbsent(ORIGIN, pin('v1', XPUB_A));
        const link = path.join(dir, 'link.json');
        fs.symlinkSync(target, link);
        await assert.rejects(new FileVaultKeyStore({ file: link }).get(ORIGIN, 'v1'), error => error.code === 'not_regular_file');
        await assert.rejects(new FileVaultKeyStore({ file: dir }).list(ORIGIN), error => error.code === 'not_regular_file');
    });

    it('takes over a lock left by a dead process', async () => {
        const file = path.join(dir, 'vault-keys.json');
        fs.writeFileSync(`${file}.lock`, '1');
        const old = new Date(Date.now() - 60000);
        fs.utimesSync(`${file}.lock`, old, old);
        await new FileVaultKeyStore({ file }).pinIfAbsent(ORIGIN, pin('v1', XPUB_A));
        assert.ok(!fs.existsSync(`${file}.lock`));
    });

    it('an unwritable default location falls back to memory with a warning; an explicit file fails', { skip: !posix || process.getuid() === 0 }, async () => {
        const locked = path.join(dir, 'locked');
        fs.mkdirSync(locked, { mode: 0o500 });
        const file = path.join(locked, 'sub', 'vault-keys.json');
        const warnings = [];
        const fallback = new FileVaultKeyStore({ file, fallbackToMemory: true, onFallback: error => warnings.push(error.code) });
        assert.deepEqual(await fallback.pinIfAbsent(ORIGIN, pin('v1', XPUB_A)), pin('v1', XPUB_A));
        assert.deepEqual(await fallback.pinIfAbsent(ORIGIN, pin('v1', XPUB_B)), pin('v1', XPUB_A));
        assert.equal(warnings.length, 1);
        await assert.rejects(new FileVaultKeyStore({ file }).pinIfAbsent(ORIGIN, pin('v1', XPUB_A)), error => error instanceof VaultKeyStoreError && error.code === 'unwritable');
    });

    it('the default file is VAULTODY_VAULT_KEYS_FILE, else ~/.vaultody/vault-keys.json', () => {
        assert.equal(defaultVaultKeysFile({ VAULTODY_VAULT_KEYS_FILE: '/x/pins.json' }), '/x/pins.json');
        assert.equal(defaultVaultKeysFile({}), path.join(os.homedir(), '.vaultody', 'vault-keys.json'));
    });

    it('the client uses VAULTODY_VAULT_KEYS_FILE when no store is given', async () => {
        const saved = process.env.VAULTODY_VAULT_KEYS_FILE;
        process.env.VAULTODY_VAULT_KEYS_FILE = path.join(dir, 'env-pins.json');
        try {
            const client = new Vaultody({ apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase });
            assert.ok(client);
            assert.ok(!fs.existsSync(path.join(dir, 'env-pins.json')), 'nothing is written before a pin');
        } finally {
            if (saved === undefined) {
                delete process.env.VAULTODY_VAULT_KEYS_FILE;
            } else {
                process.env.VAULTODY_VAULT_KEYS_FILE = saved;
            }
        }
    });
});
