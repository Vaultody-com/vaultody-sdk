#!/usr/bin/env node
/**
 * The vault keys file across languages (docs/vault-keys-file.md): a file written by each SDK reads the same
 * in the other two, every SDK writes the same bytes for the same content, writers in different languages
 * take turns on one file, and concurrent writers in all three languages lose no pin.
 *
 *   node conformance/interop/run.mjs
 *
 * Each language has a helper that drives its own file store (vault-keys-file.js, vault_keys_file.py,
 * vault-keys-file.php). A helper reads one JSON command on stdin and writes one JSON answer on stdout:
 *
 *   { "op": "write", "file": path, "steps": [ { "pin": { "origin", "pin" } } | { "latch": { "origin", "latch" } } ] }
 *        each step is one store call (pinIfAbsent / latch the response signature), in order
 *     → { "ok": true }
 *   { "op": "read", "file": path, "origins": [origin, ...] }
 *     → { "ok": true, "origins": { origin: { "responseSignature": latch | null, "pins": [pin, ...] sorted by vaultId } } }
 *   any VaultKeyStoreError → { "ok": false, "error": code }
 *
 * The commands: VAULTODY_INTEROP_NODE (default node), VAULTODY_INTEROP_PYTHON (default python3, with
 * vaultody-verify and vaultody-sdk installed), VAULTODY_INTEROP_PHP (default php, or docker:<image>: the
 * repository is mounted read only and the temporary directory read-write, at the same paths; put it under
 * a directory the Docker VM mounts with VAULTODY_INTEROP_TMP). CI runs it in test.yml (vault-keys-interop).
 */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const VECTORS = JSON.parse(readFileSync(path.join(ROOT, 'test-vectors', 'vault-keys-file-v1.json'), 'utf8'));

const PROD = 'https://rest.vaultody.com';
const LOOPBACK = 'http://127.0.0.1:8080';
const TEST = 'https://rest.example.test';
// A content every writer writes: the vectors' two_origins case.
const TWO_ORIGINS = VECTORS.canonical.find(c => c.name === 'two_origins');

function command(language) {
    const php = process.env.VAULTODY_INTEROP_PHP || 'php';
    const commands = {
        node: [process.env.VAULTODY_INTEROP_NODE || process.execPath, path.join(HERE, 'vault-keys-file.js')],
        python: [process.env.VAULTODY_INTEROP_PYTHON || 'python3', '-I', path.join(HERE, 'vault_keys_file.py')],
        php: php.startsWith('docker:')
            ? ['docker', 'run', '--rm', '-i', '-v', `${ROOT}:${ROOT}:ro`, '-v', `${TMP}:${TMP}`, '-w', ROOT, php.slice('docker:'.length), 'php', path.join(HERE, 'vault-keys-file.php')]
            : [php, path.join(HERE, 'vault-keys-file.php')],
    };

    return commands[language];
}

const LANGUAGES = ['node', 'python', 'php'];
const base = process.env.VAULTODY_INTEROP_TMP || os.tmpdir();
mkdirSync(base, { recursive: true });
const TMP = mkdtempSync(path.join(base, 'vaultody-interop-'));

function helper(language, request) {
    const [bin, ...args] = command(language);

    return new Promise((resolve, reject) => {
        const child = spawn(bin, args, { stdio: ['pipe', 'pipe', 'pipe'] });
        let out = '';
        let err = '';
        child.stdout.on('data', chunk => { out += chunk; });
        child.stderr.on('data', chunk => { err += chunk; });
        child.on('error', reject);
        child.on('close', code => {
            try {
                const answer = JSON.parse(out);
                if (code !== 0 && answer.ok !== false) {
                    throw new Error(`exit ${code}`);
                }
                resolve(answer);
            } catch (e) {
                reject(new Error(`${language} helper failed (exit ${code}): ${err.trim().slice(0, 500) || out.slice(0, 500)}`));
            }
        });
        child.stdin.end(JSON.stringify(request));
    });
}

const pinSteps = document => Object.entries(document.origins).flatMap(([origin, entry]) => [
    ...Object.values(entry.vaults).map(pin => ({ pin: { origin, pin } })),
    ...(entry.responseSignature ? [{ latch: { origin, latch: entry.responseSignature } }] : []),
]);
const expectedOf = (document, origins) => Object.fromEntries(origins.map(origin => {
    const entry = document.origins[origin] || { responseSignature: null, vaults: {} };

    return [origin, { responseSignature: entry.responseSignature, pins: Object.values(entry.vaults).sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1)) }];
}));
const sha256 = file => createHash('sha256').update(readFileSync(file)).digest('hex');

const results = [];
async function check(name, fn) {
    try {
        const note = await fn();
        results.push({ name, ok: true, note });
    } catch (error) {
        results.push({ name, ok: false, note: error.message.split('\n')[0].slice(0, 300) });
    }
}

async function readAll(file, origins, expected) {
    for (const reader of LANGUAGES) {
        const answer = await helper(reader, { op: 'read', file, origins });
        assert.equal(answer.ok, true, `${reader} could not read it: ${answer.error}`);
        assert.deepEqual(answer.origins, expected, `${reader} reads other pins or another latch`);
    }
}

try {
    // 1. Each language writes the same content; the other two (and itself) read the same pins and latches,
    //    and the three files are byte for byte the vectors' canonical text.
    const origins = Object.keys(TWO_ORIGINS.document.origins);
    const hashes = {};
    for (const writer of LANGUAGES) {
        await check(`written by ${writer}, read by node, python and php`, async () => {
            const dir = path.join(TMP, `by-${writer}`);
            const file = path.join(dir, 'vault-keys.json');
            const answer = await helper(writer, { op: 'write', file, steps: pinSteps(TWO_ORIGINS.document) });
            assert.equal(answer.ok, true, `${writer} could not write: ${answer.error}`);
            await readAll(file, [...origins, TEST], expectedOf(TWO_ORIGINS.document, [...origins, TEST]));
            assert.equal(readFileSync(file, 'utf8'), TWO_ORIGINS.text, `${writer} did not write the canonical bytes`);
            hashes[writer] = sha256(file);

            return `${Object.values(TWO_ORIGINS.document.origins).reduce((n, e) => n + Object.keys(e.vaults).length, 0)} pins, 1 latch, sha256 ${hashes[writer].slice(0, 12)}`;
        });
    }
    await check('the three writers wrote identical bytes', async () => {
        assert.equal(new Set(Object.values(hashes)).size, 1, JSON.stringify(hashes));

        return Object.values(hashes)[0].slice(0, 12);
    });

    // A latch whose rootId is null (set by a signed answer that did not verify): each language writes it and reads
    // what the others wrote, byte for byte the vectors' canonical text.
    const UNVERIFIED = VECTORS.canonical.find(c => c.name === 'latch_unverified');
    const unverifiedOrigins = Object.keys(UNVERIFIED.document.origins);
    for (const writer of LANGUAGES) {
        await check(`a latch with rootId null, written by ${writer}, read by node, python and php`, async () => {
            const file = path.join(TMP, `latch-null-by-${writer}`, 'vault-keys.json');
            const answer = await helper(writer, { op: 'write', file, steps: pinSteps(UNVERIFIED.document) });
            assert.equal(answer.ok, true, `${writer} could not write: ${answer.error}`);
            await readAll(file, unverifiedOrigins, expectedOf(UNVERIFIED.document, unverifiedOrigins));
            assert.equal(readFileSync(file, 'utf8'), UNVERIFIED.text, `${writer} did not write the canonical bytes`);

            return `sha256 ${sha256(file).slice(0, 12)}`;
        });
    }

    // 2. Writers take turns on one file: each adds to what the others wrote, nothing is lost.
    await check('node, then python, then php add to one file', async () => {
        const file = path.join(TMP, 'turns', 'vault-keys.json');
        const pins = Object.values(TWO_ORIGINS.document.origins[PROD].vaults).concat(Object.values(TWO_ORIGINS.document.origins[LOOPBACK].vaults));
        const steps = [
            ['node', [{ pin: { origin: PROD, pin: pins[0] } }]],
            ['python', [{ pin: { origin: PROD, pin: pins[1] } }, { latch: { origin: PROD, latch: TWO_ORIGINS.document.origins[PROD].responseSignature } }]],
            ['php', [{ pin: { origin: LOOPBACK, pin: pins[2] } }]],
        ];
        for (const [writer, writeSteps] of steps) {
            const answer = await helper(writer, { op: 'write', file, steps: writeSteps });
            assert.equal(answer.ok, true, `${writer} could not write: ${answer.error}`);
        }
        await readAll(file, origins, expectedOf(TWO_ORIGINS.document, origins));
        assert.equal(readFileSync(file, 'utf8'), TWO_ORIGINS.text);

        return 'same content and bytes as one writer';
    });

    // 3. Concurrent writers in all three languages on one file: the shared lock keeps every pin.
    await check('node, python and php pin 15 vaults each at the same time', async () => {
        const file = path.join(TMP, 'concurrent', 'vault-keys.json');
        const template = TWO_ORIGINS.document.origins[PROD].vaults[Object.keys(TWO_ORIGINS.document.origins[PROD].vaults)[0]];
        const pinsOf = language => Array.from({ length: 15 }, (_, i) => ({ ...template, vaultId: `${language}-${String(i).padStart(2, '0')}` }));
        const answers = await Promise.all(LANGUAGES.map(language => helper(language, { op: 'write', file, steps: pinsOf(language).map(pin => ({ pin: { origin: TEST, pin } })) })));
        answers.forEach((answer, i) => assert.equal(answer.ok, true, `${LANGUAGES[i]} could not write: ${answer.error}`));
        const all = LANGUAGES.flatMap(pinsOf).sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1));
        await readAll(file, [TEST], { [TEST]: { responseSignature: null, pins: all } });

        return `${all.length} pins, every reader sees all`;
    });

    // 4. A file one language refuses, every language refuses with the same code.
    for (const name of ['php_layout', 'python_latch_key', 'no_audit', 'pin_unknown_field']) {
        await check(`${name}: refused by all three as malformed`, async () => {
            const c = VECTORS.invalid.find(v => v.name === name);
            const dir = path.join(TMP, `refused-${name}`);
            mkdirSync(dir, { recursive: true, mode: 0o700 });
            const file = path.join(dir, 'vault-keys.json');
            const { writeFileSync } = await import('node:fs');
            writeFileSync(file, c.text, { mode: 0o600 });
            for (const reader of LANGUAGES) {
                const answer = await helper(reader, { op: 'read', file, origins: [PROD] });
                assert.deepEqual(answer, { ok: false, error: c.expected.error }, `${reader}: ${JSON.stringify(answer)}`);
            }

            return c.expected.error;
        });
    }
} finally {
    rmSync(TMP, { recursive: true, force: true });
}

for (const r of results) {
    process.stdout.write(`${r.ok ? 'ok  ' : 'FAIL'} ${r.name}${r.note ? ` (${r.note})` : ''}\n`);
}
const failed = results.filter(r => !r.ok).length;
process.stdout.write(`vault keys interop: ${results.length - failed}/${results.length} ok\n`);
process.exitCode = failed === 0 ? 0 : 1;
