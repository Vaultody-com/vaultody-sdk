'use strict';

/**
 * Where vault xpub pins, and the response-signature latch, are kept between calls and restarts.
 *
 * A store is any object with these async methods. Everything is scoped by the API origin (such as
 * https://rest.vaultody.com), so pins from a test environment and from production never mix:
 *
 *   get(origin, vaultId)                 → Pin | null
 *   list(origin)                         → Pin[]
 *   pinIfAbsent(origin, pin)             → Pin     atomic: stores the pin only when the vault has none, and
 *                                                    returns what is stored either way
 *   upgradeTrust(origin, pin)            → Pin     atomic: replaces an unverified pin by `pin` (verified) only
 *                                                    when type and xpubs are equal; returns what is stored
 *   replace(origin, pin, reason)         → void    an explicit re-pin, after an out-of-band check (support, the
 *                                                    command line); the transport never calls it
 *   getResponseSignatureLatch(origin)    → Latch | null
 *   latchResponseSignature(origin, latch)→ Latch   atomic: set once, never cleared; returns what is stored
 *
 *   Pin   = { vaultId, type: 'main'|'test', keys: { ECDSA: xpub|null, EDDSA: xpub|null },
 *             status: 'verified'|'unverified', firstSeenAt, verifiedAt|null, verification: { rootId, timestamp }|null }
 *   Latch = { latchedAt, rootId|null }   rootId: the root that verified the answer that set it; null when that
 *                                        answer carried a signature that did not verify (responseVerification.js)
 *
 * A store that can't be read or parsed fails closed: it throws, and is never treated as empty, because an
 * empty store would accept any xpub as new. A custom store (Redis, SQL) must keep the same rules; for
 * containers and serverless functions, a shared custom store keeps pins across instances.
 *
 * The xpub is sensitive: it reveals every address of the vault. The file store writes mode 0600 in a 0700
 * directory, and nothing here logs an xpub.
 *
 * The file is the "vaultody vault keys v1" document every SDK reads and writes (docs/vault-keys-file.md,
 * test-vectors/vault-keys-file-v1.json): the same layout, the same refusals (VaultKeyStoreError codes
 * not_json, unknown_format, malformed, insecure_permissions, not_regular_file, too_large), the same canonical
 * bytes and the same lock file, so Node, Python and PHP clients can share one file.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { VaultKeyStoreError } = require('./errors');
const { PIN_STATUS, ALGORITHMS } = require('./vaultKeys');

const FORMAT = 'vaultody vault keys v1';
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;
const LOCK_RETRY_MS = 20;
const LOCK_TIMEOUT_MS = 10000;
// A lock file older than this was left by a process that died while holding it.
const LOCK_STALE_MS = 30000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TIME = Number.MAX_SAFE_INTEGER;
const ORIGIN = /^https?:\/\/[^/?#@\s]+$/;
// Write errors after which the default store keeps pins in memory instead (with a loud warning).
const UNWRITABLE = new Set(['EACCES', 'EPERM', 'EROFS', 'ENOTDIR', 'ENOENT', 'ENOSPC', 'EISDIR']);

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const isText = value => typeof value === 'string' && value !== '';
const isTime = value => Number.isSafeInteger(value) && value >= 0 && value <= MAX_TIME;
const clone = value => JSON.parse(JSON.stringify(value));
const hasExactly = (object, keys) => isObject(object) && Object.keys(object).length === keys.length && keys.every(key => Object.hasOwn(object, key));

const emptyState = () => ({ format: FORMAT, origins: {} });
const emptyEntry = () => ({ responseSignature: null, vaults: {}, audit: [] });

const malformed = where => new VaultKeyStoreError('malformed', `the vault key store is malformed (${where}); refusing to treat it as empty`);

/** A latch exactly as the file holds it: { latchedAt, rootId }, rootId text or null. */
const isLatch = latch => hasExactly(latch, ['latchedAt', 'rootId']) && isTime(latch.latchedAt) && (latch.rootId === null || isText(latch.rootId));

/** A pin exactly as the file holds it (docs/vault-keys-file-v1.schema.json); false otherwise. */
function isPin(pin) {
    if (!hasExactly(pin, ['vaultId', 'type', 'keys', 'status', 'firstSeenAt', 'verifiedAt', 'verification'])
        || !isText(pin.vaultId) || !['main', 'test'].includes(pin.type) || !isTime(pin.firstSeenAt)
        || !hasExactly(pin.keys, ALGORITHMS) || !ALGORITHMS.every(algorithm => pin.keys[algorithm] === null || isText(pin.keys[algorithm]))
        || !ALGORITHMS.some(algorithm => pin.keys[algorithm] !== null)) {
        return false;
    }
    if (pin.status === PIN_STATUS.VERIFIED) {
        return isTime(pin.verifiedAt) && hasExactly(pin.verification, ['rootId', 'timestamp']) && isText(pin.verification.rootId) && isTime(pin.verification.timestamp);
    }

    return pin.status === PIN_STATUS.UNVERIFIED && pin.verifiedAt === null && pin.verification === null;
}

const isAuditEntry = entry => hasExactly(entry, ['vaultId', 'at', 'reason', 'removed']) && isText(entry.vaultId) && isTime(entry.at)
    && typeof entry.reason === 'string' && /\S/.test(entry.reason) && typeof entry.removed === 'boolean';

/** A pin handed to the store: the same rules, reported as a bad argument rather than a bad file. */
function checkNewPin(pin) {
    if (!isPin(pin)) {
        throw new VaultKeyStoreError('invalid_pin', 'the pin to store is malformed: vaultId, type main|test, keys { ECDSA, EDDSA } with at least one xpub, '
            + 'status verified (with verifiedAt and verification { rootId, timestamp }) or unverified (both null), integer Unix seconds, no other field');
    }
}

/** Checks a whole document (docs/vault-keys-file.md): the format tag first (unknown_format), then the layout (malformed). */
function checkState(state, where) {
    if (!isObject(state) || state.format !== FORMAT) {
        throw new VaultKeyStoreError('unknown_format', `the vault key store is not a "${FORMAT}" document (${where}); refusing to treat it as empty`);
    }
    if (!hasExactly(state, ['format', 'origins']) || !isObject(state.origins)) {
        throw malformed(where);
    }
    for (const [origin, entry] of Object.entries(state.origins)) {
        if (!ORIGIN.test(origin) || !hasExactly(entry, ['responseSignature', 'vaults', 'audit'])
            || !(entry.responseSignature === null || isLatch(entry.responseSignature))
            || !isObject(entry.vaults) || !Array.isArray(entry.audit) || !entry.audit.every(isAuditEntry)) {
            throw malformed(`${where}, origin ${origin}`);
        }
        for (const [vaultId, pin] of Object.entries(entry.vaults)) {
            if (!isPin(pin) || pin.vaultId !== vaultId) {
                throw malformed(`${where}, origin ${origin}`);
            }
        }
    }

    return state;
}

/**
 * Reads the bytes of a vault keys file into its document: strict UTF-8 (no byte-order mark), JSON, the v1
 * layout. Times must be integer tokens (no fraction, no exponent), as the other languages read them.
 *
 * @param {Buffer|Uint8Array} bytes
 * @returns {Object} the document
 * @throws {VaultKeyStoreError} not_json, unknown_format or malformed
 */
function parseDocument(bytes, where = 'the vault key file') {
    let text;
    try {
        text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch (e) {
        throw new VaultKeyStoreError('not_json', `${where} is not UTF-8; refusing to treat it as empty`);
    }
    if (text.startsWith('\uFEFF')) {
        throw new VaultKeyStoreError('not_json', `${where} starts with a byte-order mark; refusing to treat it as empty`);
    }
    let fraction = false;
    let state;
    try {
        state = JSON.parse(text, function reviver(key, value, context) {
            // Only integer tokens make integers, as in Python and PHP: 1.0 and 1e3 are not times.
            if (typeof value === 'number' && context && typeof context.source === 'string' && !/^-?(0|[1-9][0-9]*)$/.test(context.source)) {
                fraction = true;
            }

            return value;
        });
    } catch (e) {
        throw new VaultKeyStoreError('not_json', `${where} is not JSON; refusing to treat it as empty`);
    }
    checkState(state, where);
    if (fraction) {
        throw malformed(`${where}: a number that is not an integer`);
    }

    return state;
}

/** The canonical bytes every SDK writes: keys sorted at every level, two-space indent, a final newline. */
function canonicalJson(value) {
    const sorted = v => {
        if (Array.isArray(v)) {
            return v.map(sorted);
        }
        if (v !== null && typeof v === 'object') {
            return Object.fromEntries(Object.keys(v).sort().map(key => [key, sorted(v[key])]));
        }

        return v;
    };

    return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

const originOf = (state, origin) => state.origins[origin] || emptyEntry();
const isEmptyEntry = entry => entry.responseSignature === null && Object.keys(entry.vaults).length === 0 && entry.audit.length === 0;
const sameKeys = (a, b) => a.type === b.type && ALGORITHMS.every(algorithm => a.keys[algorithm] === b.keys[algorithm]);

/**
 * The store logic over one state document; subclasses only read and write the document.
 */
class StateStore {
    constructor() {
        // One update at a time in this process; the file store also locks across processes.
        this.queue = Promise.resolve();
    }

    async get(origin, vaultId) {
        const pin = originOf(await this.read(), origin).vaults[vaultId];

        return pin ? clone(pin) : null;
    }

    async list(origin) {
        return Object.values(originOf(await this.read(), origin).vaults).map(clone);
    }

    async pinIfAbsent(origin, pin) {
        checkNewPin(pin);

        return this.change(origin, entry => {
            if (!entry.vaults[pin.vaultId]) {
                entry.vaults[pin.vaultId] = clone(pin);
            }

            return entry.vaults[pin.vaultId];
        });
    }

    async upgradeTrust(origin, pin) {
        checkNewPin(pin);
        if (pin.status !== PIN_STATUS.VERIFIED) {
            throw new TypeError('upgradeTrust stores a verified pin');
        }

        return this.change(origin, entry => {
            const stored = entry.vaults[pin.vaultId];
            if (stored && stored.status === PIN_STATUS.UNVERIFIED && sameKeys(stored, pin)) {
                entry.vaults[pin.vaultId] = { ...clone(pin), firstSeenAt: stored.firstSeenAt };
            }

            return entry.vaults[pin.vaultId] || null;
        });
    }

    /**
     * The administrative re-pin, after the new xpub was confirmed out of band; recorded in the origin's audit
     * list ({ vaultId, at, reason, removed: false }).
     */
    async replace(origin, pin, reason) {
        checkNewPin(pin);
        if (typeof reason !== 'string' || reason.trim() === '') {
            throw new TypeError('replace needs the reason the pin is replaced, for the record');
        }
        const at = Math.floor(Date.now() / 1000);

        await this.change(origin, entry => {
            entry.vaults[pin.vaultId] = clone(pin);
            entry.audit.push({ vaultId: pin.vaultId, at, reason, removed: false });
        });
    }

    async getResponseSignatureLatch(origin) {
        const latch = originOf(await this.read(), origin).responseSignature;

        return latch ? clone(latch) : null;
    }

    async latchResponseSignature(origin, latch) {
        if (!isLatch(latch)) {
            throw new VaultKeyStoreError('invalid_pin', 'the latch must be { latchedAt: Unix seconds, rootId: text or null }');
        }

        return this.change(origin, entry => {
            if (!entry.responseSignature) {
                entry.responseSignature = clone(latch);
            }

            return entry.responseSignature;
        });
    }

    /** Runs fn on one origin's entry under the lock and writes the result (only what changed is written). */
    change(origin, fn) {
        if (typeof origin !== 'string' || !ORIGIN.test(origin)) {
            return Promise.reject(new TypeError('origin must be an API origin, such as https://rest.vaultody.com'));
        }
        const run = this.queue.then(() => this.update(state => {
            const entry = clone(originOf(state, origin));
            const result = fn(entry);
            if (Object.hasOwn(state.origins, origin) || !isEmptyEntry(entry)) {
                state.origins[origin] = entry;
            }

            return result === undefined ? undefined : clone(result);
        }));
        this.queue = run.catch(() => {});

        return run;
    }
}

/** Pins kept in memory: they last as long as the process. */
class MemoryVaultKeyStore extends StateStore {
    constructor(initialState) {
        super();
        this.state = initialState ? checkState(clone(initialState), 'the initial state') : emptyState();
    }

    async read() {
        return clone(this.state);
    }

    async update(fn) {
        const state = clone(this.state);
        const result = fn(state);
        this.state = checkState(state, 'the new state');

        return result;
    }
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const notRegular = file => new VaultKeyStoreError('not_regular_file', `the vault key store ${file} is not a regular file (a symbolic link or a directory); refusing to use it`);

/**
 * Pins in a JSON file, by default ~/.vaultody/vault-keys.json (or VAULTODY_VAULT_KEYS_FILE). Writes go to a
 * temporary file that is synced and renamed over the old one, under a lock file created exclusively, so
 * several processes can share the file.
 */
class FileVaultKeyStore extends StateStore {
    /**
     * @param {{ file: string, fallbackToMemory?: boolean, onFallback?: function(Error): void }} options
     *        fallbackToMemory: when the file can't be written, keep pins in memory from then on (with
     *        onFallback called once) instead of failing; the default store does, an explicit path does not
     */
    constructor({ file, fallbackToMemory = false, onFallback = () => {} }) {
        super();
        if (typeof file !== 'string' || file === '') {
            throw new TypeError('file must be the path of the vault key store');
        }
        this.file = path.resolve(file);
        this.fallbackToMemory = fallbackToMemory;
        this.onFallback = onFallback;
        this.memory = null;
    }

    async read() {
        if (this.memory) {
            return this.memory.read();
        }
        let bytes;
        let handle;
        try {
            // A symbolic link is refused, not followed: O_NOFOLLOW where the platform has it, and the open file's
            // own stat after that, so the file checked is the file read.
            handle = await fs.promises.open(this.file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
            const stat = await handle.stat();
            if (!stat.isFile()) {
                throw notRegular(this.file);
            }
            // Pins anyone else can rewrite are no pins: refuse rather than trust them.
            if (process.platform !== 'win32' && (stat.mode & 0o022) !== 0) {
                throw new VaultKeyStoreError('insecure_permissions', `the vault key store ${this.file} is writable by other users; `
                    + 'set its mode to 0600 (chmod 600) before using it');
            }
            if (stat.size > MAX_FILE_BYTES) {
                throw new VaultKeyStoreError('too_large', `the vault key store ${this.file} is larger than ${MAX_FILE_BYTES} bytes`);
            }
            bytes = await handle.readFile();
        } catch (error) {
            if (error && error.code === 'ENOENT') {
                return emptyState();
            }
            if (error instanceof VaultKeyStoreError) {
                throw error;
            }
            if (error && ['ELOOP', 'EISDIR', 'EMLINK'].includes(error.code)) {
                throw notRegular(this.file);
            }
            throw new VaultKeyStoreError('unreadable', `the vault key store ${this.file} can't be read (${error && error.code ? error.code : 'error'}); `
                + 'refusing to treat it as empty', { cause: error });
        } finally {
            await handle?.close().catch(() => {});
        }
        if (bytes.length > MAX_FILE_BYTES) {
            throw new VaultKeyStoreError('too_large', `the vault key store ${this.file} is larger than ${MAX_FILE_BYTES} bytes`);
        }

        return parseDocument(bytes, this.file);
    }

    async update(fn) {
        if (this.memory) {
            return this.memory.update(fn);
        }
        let release;
        try {
            await fs.promises.mkdir(path.dirname(this.file), { recursive: true, mode: DIR_MODE });
            release = await this.lock();
        } catch (error) {
            return this.fallBack(error, fn, null);
        }
        try {
            const before = await this.read();
            const state = clone(before);
            const result = fn(state);
            checkState(state, 'the new state');
            // Written only when something changed: a client that only reads never creates the file.
            if (canonicalJson(state) !== canonicalJson(before)) {
                try {
                    await this.write(state);
                } catch (error) {
                    return await this.fallBack(error, fn, before);
                }
            }

            return result;
        } finally {
            await release();
        }
    }

    /** The file can't be written: keep pins in memory from now on (default store only), else fail. */
    async fallBack(error, fn, before) {
        if (!this.fallbackToMemory || !error || !UNWRITABLE.has(error.code)) {
            throw error instanceof VaultKeyStoreError ? error
                : new VaultKeyStoreError('unwritable', `the vault key store ${this.file} can't be written (${error && error.code ? error.code : 'error'})`, { cause: error });
        }
        if (!this.memory) {
            // Start from what the file holds, so no pin read so far is lost; an unreadable file still fails closed.
            this.memory = new MemoryVaultKeyStore(before || await this.read());
            this.onFallback(error);
        }

        return this.memory.update(fn);
    }

    async lock() {
        const lockFile = `${this.file}.lock`;
        const started = Date.now();
        for (;;) {
            try {
                const handle = await fs.promises.open(lockFile, 'wx', FILE_MODE);
                await handle.writeFile(String(process.pid));
                await handle.close();

                return async () => {
                    await fs.promises.unlink(lockFile).catch(() => {});
                };
            } catch (error) {
                if (error.code !== 'EEXIST') {
                    throw error;
                }
            }
            try {
                const stat = await fs.promises.stat(lockFile);
                if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) {
                    await fs.promises.unlink(lockFile).catch(() => {});
                    continue;
                }
            } catch (e) {
                continue;
            }
            if (Date.now() - started > LOCK_TIMEOUT_MS) {
                throw new VaultKeyStoreError('locked', `the vault key store ${this.file} stayed locked for ${LOCK_TIMEOUT_MS / 1000} s (${lockFile})`);
            }
            await sleep(LOCK_RETRY_MS);
        }
    }

    async write(state) {
        const temp = `${this.file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
        const handle = await fs.promises.open(temp, 'wx', FILE_MODE);
        try {
            // The mode given to open is narrowed by the umask; set it exactly.
            await handle.chmod(FILE_MODE);
            await handle.writeFile(canonicalJson(state));
            await handle.sync();
        } finally {
            await handle.close();
        }
        try {
            await fs.promises.rename(temp, this.file);
        } catch (error) {
            await fs.promises.unlink(temp).catch(() => {});
            throw error;
        }
        // Make the rename itself durable; not every platform can open a directory.
        try {
            const dir = await fs.promises.open(path.dirname(this.file), 'r');
            await dir.sync().catch(() => {});
            await dir.close();
        } catch (e) {
            // best effort
        }
    }
}

/**
 * The default pin file: VAULTODY_VAULT_KEYS_FILE, else ~/.vaultody/vault-keys.json; null when there is no home
 * directory (pins then stay in memory, with a warning). Never a shared directory such as /tmp, where another
 * user could plant the file first.
 */
function defaultVaultKeysFile(env = process.env) {
    if (typeof env.VAULTODY_VAULT_KEYS_FILE === 'string' && env.VAULTODY_VAULT_KEYS_FILE !== '') {
        return env.VAULTODY_VAULT_KEYS_FILE;
    }
    let home;
    try {
        home = os.homedir();
    } catch (e) {
        home = '';
    }

    return home ? path.join(home, '.vaultody', 'vault-keys.json') : null;
}

module.exports = {
    FORMAT,
    parseDocument,
    canonicalJson,
    MemoryVaultKeyStore,
    FileVaultKeyStore,
    defaultVaultKeysFile,
};
