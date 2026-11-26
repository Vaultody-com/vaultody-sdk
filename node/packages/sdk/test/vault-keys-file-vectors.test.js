'use strict';

// test-vectors/vault-keys-file-v1.json: the pin file every SDK reads and writes (docs/vault-keys-file.md). Valid
// files parse to their pins and latches, through the parser and through the file store; refused files fail
// closed with the shared code; file modes, links and directories; and the canonical bytes a writer writes.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it, beforeEach, afterEach } = require('node:test');

const { FileVaultKeyStore, VaultKeyStoreError } = require('../src');
const { parseDocument, canonicalJson } = require('../src/vaultKeyStore');
const { load } = require('./vectors');

const VECTORS = load('vault-keys-file-v1.json');
const posix = process.platform !== 'win32';
const byVaultId = pins => [...pins].sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1));
const bytesOf = c => (c.base64 !== undefined ? Buffer.from(c.base64, 'base64') : Buffer.from(c.text, 'utf8'));

/** What the file store returns for each origin of an expected { origins }. */
async function readThroughStore(store, origins) {
    const out = {};
    for (const origin of Object.keys(origins)) {
        out[origin] = { responseSignature: await store.getResponseSignatureLatch(origin), pins: byVaultId(await store.list(origin)) };
    }

    return out;
}
const expectedThroughStore = origins => Object.fromEntries(Object.entries(origins).map(([origin, entry]) => [origin, {
    responseSignature: entry.responseSignature, pins: byVaultId(Object.values(entry.vaults)),
}]));

describe('test-vectors/vault-keys-file-v1.json', () => {
    let dir;
    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-vault-keys-'));
    });
    afterEach(() => {
        fs.rmSync(dir, { recursive: true, force: true });
    });
    const write = (name, bytes, mode = 0o600) => {
        const file = path.join(dir, name);
        fs.writeFileSync(file, bytes, { mode });
        fs.chmodSync(file, mode);

        return file;
    };

    it('has every kind of case', () => {
        assert.equal(VECTORS.format, 'vaultody vault keys file, v1');
        assert.ok(VECTORS.valid.length >= 10 && VECTORS.invalid.length >= 50 && VECTORS.files.length >= 8 && VECTORS.canonical.length >= 5);
    });

    for (const c of VECTORS.valid) {
        it(`valid: ${c.name}`, async () => {
            assert.deepEqual(parseDocument(bytesOf(c)).origins, c.expected.origins);
            const store = new FileVaultKeyStore({ file: write('vault-keys.json', bytesOf(c)) });
            assert.deepEqual(await readThroughStore(store, c.expected.origins), expectedThroughStore(c.expected.origins));
        });
    }

    for (const c of VECTORS.invalid) {
        it(`invalid: ${c.name} → ${c.expected.error}`, async () => {
            assert.throws(() => parseDocument(bytesOf(c)), error => error instanceof VaultKeyStoreError && error.code === c.expected.error);
            const file = write('vault-keys.json', bytesOf(c));
            const store = new FileVaultKeyStore({ file, fallbackToMemory: true });
            await assert.rejects(store.list('https://rest.vaultody.com'), error => error instanceof VaultKeyStoreError && error.code === c.expected.error);
            await assert.rejects(store.getResponseSignatureLatch('https://rest.vaultody.com'), error => error.code === c.expected.error);
        });
    }

    const contentOf = name => {
        const [kind, caseName] = name.startsWith('invalid:') ? ['invalid', name.slice('invalid:'.length)] : ['valid', name];

        return bytesOf(VECTORS[kind].find(c => c.name === caseName));
    };
    for (const c of VECTORS.files) {
        it(`file: ${c.name}`, { skip: c.posixOnly && !posix }, async () => {
            const file = path.join(dir, 'vault-keys.json');
            if (c.mode) {
                write('vault-keys.json', contentOf(c.content), Number.parseInt(c.mode, 8));
            } else if (c.symlinkTo) {
                fs.symlinkSync(write('target.json', contentOf(c.symlinkTo)), file);
            } else if (c.directory) {
                fs.mkdirSync(file);
            }
            const store = new FileVaultKeyStore({ file });
            if (c.expected.error) {
                await assert.rejects(store.list('https://rest.vaultody.com'), error => error instanceof VaultKeyStoreError && error.code === c.expected.error);
            } else {
                assert.deepEqual(await readThroughStore(store, c.expected.origins), expectedThroughStore(c.expected.origins));
                // Reading creates nothing.
                assert.equal(fs.existsSync(file), !c.absent);
            }
        });
    }

    for (const c of VECTORS.canonical) {
        it(`canonical: ${c.name}`, async () => {
            assert.equal(canonicalJson(c.document), c.text);
            assert.equal(canonicalJson(parseDocument(Buffer.from(c.text, 'utf8'))), c.text);

            // The store writes the same bytes when it stores the same content through its own calls.
            const origins = Object.entries(c.document.origins);
            if (origins.some(([, entry]) => entry.audit.length > 0)) {
                return; // audit entries are written by replace(), which stamps its own time
            }
            const file = path.join(dir, 'written', 'vault-keys.json');
            const store = new FileVaultKeyStore({ file });
            for (const [origin, entry] of origins) {
                for (const pin of Object.values(entry.vaults)) {
                    await store.pinIfAbsent(origin, pin);
                }
                if (entry.responseSignature) {
                    await store.latchResponseSignature(origin, entry.responseSignature);
                }
            }
            if (origins.length === 0) {
                assert.ok(!fs.existsSync(file), 'an empty store writes no file');
            } else {
                assert.equal(fs.readFileSync(file, 'utf8'), c.text);
                if (posix) {
                    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
                }
            }
        });
    }
});
