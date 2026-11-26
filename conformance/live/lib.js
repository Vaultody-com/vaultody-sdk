'use strict';

/**
 * What the Node pieces of the live conformance run share (discover.js, run-node.js, report.js): the
 * environment, the case list, the fixture and its references, and summaries that never carry a secret or an
 * xpub. The Python and PHP runners implement the same rules (run_python.py, run-php.php).
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const CASES = JSON.parse(fs.readFileSync(path.join(__dirname, 'cases.json'), 'utf8'));
// The production API: never a target of this run (it creates addresses and sends bursts).
const PRODUCTION_ORIGINS = new Set(['https://rest.vaultody.com']);

function env(name, { required = true } = {}) {
    const value = process.env[name];
    if (required && (typeof value !== 'string' || value === '')) {
        throw new Error(`${name} is not set (conformance/live/README.md)`);
    }

    return value;
}

/** The API key's credentials and the base URL, from the environment; refuses the production API. */
function settings() {
    const baseUrl = env('VAULTODY_BASE_URL');
    const origin = new URL(baseUrl).origin;
    if (PRODUCTION_ORIGINS.has(origin)) {
        throw new Error('the live conformance run never targets the production API');
    }

    return {
        baseUrl,
        origin,
        apiKey: env('VAULTODY_API_KEY'),
        apiSecret: env('VAULTODY_API_SECRET'),
        passphrase: env('VAULTODY_PASSPHRASE'),
        // Off unless asked for: on a small test environment a burst big enough for a 429 makes the API fail (README).
        burst: Number.parseInt(process.env.VAULTODY_CONFORMANCE_BURST || '0', 10),
        // The client's own rate limit for the cases (the SDK's default, 5 per second, when not set).
        rps: process.env.VAULTODY_CONFORMANCE_RPS ? Number(process.env.VAULTODY_CONFORMANCE_RPS) : undefined,
    };
}

/** A passphrase that is not the API key's: the same length, the last character changed. */
function wrongPassphrase(passphrase) {
    const last = passphrase.slice(-1);

    return passphrase.slice(0, -1) + (last === 'x' ? 'y' : 'x');
}

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * Resolves a case's params: "$name" from the fixture, "@caseId.field" from an earlier case's item, "{client}"
 * and "{run}" replaced by the client's name and the run's id. Returns { params } or { missing } naming the first
 * value that isn't there.
 */
function resolveParams(value, { fixture, results, client, run }) {
    let missing = null;
    const walk = v => {
        if (typeof v === 'string') {
            if (v.startsWith('$')) {
                const name = v.slice(1);
                if (fixture[name] === undefined || fixture[name] === null) {
                    missing = missing || `fixture.${name}`;
                    return undefined;
                }
                return fixture[name];
            }
            if (v.startsWith('@')) {
                const [caseId, field] = v.slice(1).split('.');
                const item = results[caseId];
                if (!isObject(item) || item[field] === undefined) {
                    missing = missing || `${caseId}.${field}`;
                    return undefined;
                }
                return item[field];
            }
            return v.split('{client}').join(client).split('{run}').join(run);
        }
        if (Array.isArray(v)) {
            return v.map(walk);
        }
        if (isObject(v)) {
            return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
        }
        return v;
    };
    const params = walk(value);

    return missing ? { missing } : { params };
}

const short = value => (typeof value === 'string' && value.length > 12 ? `${value.slice(0, 6)}…${value.slice(-4)}` : value);

/**
 * The pin file every client starts from: the vectors' canonical two_origins document (docs/vault-keys-file.md),
 * pins and a latch under the production and a loopback origin, never under the origin of the run. Each SDK
 * reads it on its first call (the latch) and on every vault list and address answer, so a client that can't
 * read the shared layout fails its cases; and since every client starts from the same bytes, their files can be
 * compared afterwards.
 */
/**
 * The TEST-ONLY response-signing root of test-vectors/v1.json, as SPKI PEM: the case rootsOnUnsignedOrigin gives it to
 * a client, which is then strict from its first answer (an environment that does not sign refuses it as missing).
 */
function testRootPem() {
    const roots = JSON.parse(fs.readFileSync(path.join(ROOT, 'test-vectors', 'v1.json'), 'utf8')).keys.roots;
    const base64 = roots.current.publicKeySpkiDerBase64;

    return `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
}

const SEED = JSON.parse(fs.readFileSync(path.join(ROOT, 'test-vectors', 'vault-keys-file-v1.json'), 'utf8')).canonical.find(c => c.name === 'two_origins');
const SEED_ORIGINS = Object.keys(SEED.document.origins);
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function seedPinFile(file) {
    fs.writeFileSync(file, SEED.text, { mode: 0o600 });
    fs.chmodSync(file, 0o600);
}

/** What the file is, without its content: mode, hash, and whether it is still the seed byte for byte. */
function pinFileFacts(file) {
    if (!fs.existsSync(file)) {
        return { file: path.basename(file), exists: false };
    }
    const hash = sha256(fs.readFileSync(file));

    return { file: path.basename(file), exists: true, mode: (fs.statSync(file).mode & 0o777).toString(8), sha256: hash, unchangedSinceSeed: hash === sha256(SEED.text) };
}

/**
 * What a client's own store read from its pin file, without the xpubs: per origin, the latch (set or not) and
 * each pin's vault id, type, status and algorithms. read: { origin: { responseSignature, pins } } in the shape
 * the interop helpers answer (conformance/interop/run.mjs).
 */
function summarizeRead(read) {
    return Object.fromEntries(Object.entries(read).map(([origin, entry]) => [origin, {
        latch: entry.responseSignature ? 'set' : null,
        vaults: entry.pins.map(pin => ({
            vaultId: short(pin.vaultId),
            type: pin.type,
            status: pin.status,
            algorithms: Object.keys(pin.keys).filter(k => pin.keys[k]).sort(),
        })),
    }]));
}

function writeJson(file, value) {
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

module.exports = {
    ROOT,
    testRootPem,
    CASES,
    settings,
    wrongPassphrase,
    resolveParams,
    SEED,
    SEED_ORIGINS,
    seedPinFile,
    pinFileFacts,
    summarizeRead,
    short,
    isObject,
    writeJson,
};
