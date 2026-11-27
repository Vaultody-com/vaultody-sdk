'use strict';

// Shared by the pipeline tests: the TEST-ONLY credentials and keys of test-vectors/request-full-v1.json, a mock
// gateway (conformance/mock-gateway) on a fake clock, and a client wired to both. node --test also loads this
// file, finds no tests in it and moves on.

const assert = require('node:assert/strict');
const path = require('node:path');
const { after } = require('node:test');

const { Vaultody, MemoryVaultKeyStore, pemSigner } = require('../src');
const { startMockGateway, fakeClock, rootPem, ROOT_IDS } = require('../../../../conformance/mock-gateway');
const { load } = require('./vectors');

const FULL = load('request-full-v1.json');
const EVENTS = new Map(load('security-events-v1.json').events.map(event => [event.type, event.fields]));

/**
 * Every security event any pipeline test sees has a catalogued type and exactly its fields
 * (test-vectors/security-events-v1.json), so the names and fields can't drift from Python's and PHP's.
 */
const strayEvents = [];
function checkedEvent(event) {
    const fields = EVENTS.get(event.type);
    if (!fields || JSON.stringify(Object.keys(event).sort()) !== JSON.stringify([...fields].sort())) {
        strayEvents.push(event);
    }

    return event;
}
// The client swallows what the hook throws (it must never hide the error it reports), so the check fails the
// test file at its end instead.
after(() => {
    assert.deepEqual(strayEvents, [], 'security events that are not in security-events-v1.json with exactly their fields');
});
const CREDENTIALS = FULL.credentials;
const KEYS = FULL.keys;
// The clock every gateway vector was made at.
const T0 = 1794201000 * 1000;
// The TEST-ONLY response-signing roots the mock gateway signs with.
const ROOTS = [rootPem('current'), rootPem('next')];
// A release candidate's version, for a client that embeds the roots and still bridges to signing.
const RELEASE_CANDIDATE = '0.9.0-rc.1';
const VAULT = '6630f1c2a9e4b5d7c8e9f0a1';

/**
 * A mock gateway knowing the TEST-ONLY API key, and a client for it, both on one fake clock. Sleeping advances
 * the clock, so backoffs cost no time; every sleep is recorded.
 *
 * @param {Object} [options]
 * @param {'ed25519'|'p256'|null} [options.key] a key pair registered on the API key and used by the client
 * @param {Object|false} [options.signing] the gateway's response signing (default: signed by the current root)
 * @param {'option'|'embedded'|'none'} [options.roots] the client's response-signing roots: 'option' the roots option
 *        (strict from the first answer), 'embedded' a release candidate that embeds them (when-present until the first
 *        signed answer latches it), 'none' (a release candidate before production signs). Default: 'option' when the
 *        gateway signs, 'none' when it does not
 * @param {boolean} [options.latched] the store holds the latch for the gateway's origin already (a client that has had
 *        a signed answer from it before), so a client with roots makes no signed read before its first write
 * @param {Object} [options.client] more client options (unsupported ones merged)
 * @param {Object} [options.gateway] more gateway options
 */
async function setup({ key = null, signing = { root: 'current' }, roots = signing === false ? 'none' : 'option', latched = false, client = {}, gateway = {}, replay } = {}) {
    if (!['option', 'embedded', 'none'].includes(roots)) {
        throw new TypeError(`roots must be option, embedded or none, not ${roots}`);
    }
    const clock = fakeClock(T0);
    const gw = await startMockGateway({
        clock,
        signing,
        keys: { [CREDENTIALS.apiKey]: { secret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, keypairs: key ? [KEYS[key].publicKeySpkiPem] : [], replay } },
        ...gateway,
    });
    const sleeps = [];
    const trace = [];
    const events = [];
    const warnings = [];
    const { unsupported = {}, ...clientOptions } = client;
    const store = clientOptions.vaultKeyStore || new MemoryVaultKeyStore();
    if (latched) {
        await store.latchResponseSignature(new URL(gw.url).origin, { latchedAt: T0 / 1000 - 3600, rootId: ROOT_IDS.current });
    }
    const vaultody = new Vaultody({
        apiKey: CREDENTIALS.apiKey,
        apiSecret: CREDENTIALS.apiSecret,
        passphrase: CREDENTIALS.passphrase,
        baseUrl: gw.url,
        ...(roots === 'option' ? { roots: ROOTS } : {}),
        vaultKeyStore: store,
        maxRequestsPerSecond: 1000,
        onSecurityEvent: event => events.push(checkedEvent(event)),
        logger: { warn: message => warnings.push(message) },
        ...(key ? { signer: pemSigner(KEYS[key].privateKeyPkcs8Pem) } : {}),
        ...clientOptions,
        unsupported: {
            clock,
            sleep: async ms => {
                sleeps.push(ms);
                clock.advance(ms);
            },
            random: () => 0,
            trace: event => trace.push(event),
            ...(roots === 'embedded' ? { embeddedRoots: ROOTS, sdkVersion: RELEASE_CANDIDATE } : {}),
            // 'none' plays a build that embeds no root, not this build's production root.
            ...(roots === 'none' ? { embeddedRoots: [] } : {}),
            ...unsupported,
        },
    });

    return { gw, clock, client: vaultody, sleeps, trace, events, warnings, close: () => gw.close() };
}

/** A store that holds the latch for the gateway's origin: a client that had a signed answer from it before. */
async function latchedStore(gw) {
    const store = new MemoryVaultKeyStore();
    await store.latchResponseSignature(new URL(gw.url).origin, { latchedAt: T0 / 1000 - 3600, rootId: ROOT_IDS.current });

    return store;
}

/** The decisions the transport made, in order. */
const decisions = trace => trace.filter(event => event.type === 'decision');

/** An error fetch would throw for a connection refused before anything was sent. */
function refused() {
    const cause = new Error('connect ECONNREFUSED 127.0.0.1:1');
    cause.code = 'ECONNREFUSED';

    return new TypeError('fetch failed', { cause });
}

/**
 * A fetch that, for the requests `match` picks (all by default), throws the given errors first, then behaves
 * like fetch. An entry may be a function: it runs (to move a fake clock, say) and returns the error.
 */
function failingFetch(errors, match = () => true) {
    const queue = [...errors];
    const calls = [];
    const fn = (url, init) => {
        calls.push({ url: String(url), method: init.method, headers: { ...init.headers } });
        if (queue.length > 0 && match(init)) {
            const entry = queue.shift();

            return Promise.reject(typeof entry === 'function' ? entry() : entry);
        }

        return fetch(url, init);
    };
    fn.calls = calls;

    return fn;
}

const json = body => Buffer.from(JSON.stringify(body), 'utf8');

module.exports = {
    checkedEvent,
    FULL,
    CREDENTIALS,
    KEYS,
    T0,
    VAULT,
    ROOTS,
    RELEASE_CANDIDATE,
    VECTORS_DIR: path.resolve(__dirname, '..', '..', '..', '..', 'test-vectors'),
    setup,
    latchedStore,
    decisions,
    refused,
    failingFetch,
    json,
    rootPem,
};
