'use strict';

// Vault xpub pins and the address check through the pipeline.
//  - test-vectors/vault-key-pins-v1.json: every step is a real listVaults call, signed with the vectors' clock
//    and nonce so the vector's signed answer binds to it; the mock gateway returns that answer as received.
//    The pins after each step, the outcomes and the alarms must be the vector's; a case's configured pins are the
//    client's pinnedVaultKeys, and a configured vault's status is verified. (The vectors assume no
//    response-signature latch and accept unsigned answers, so each step runs on a new client of a release candidate
//    that embeds the roots: when-present, checking every signed answer with the roots, on a store that never latches;
//    the latch has its own tests.)
//  - test-vectors/address-v1.json: all 511 addresses come back in paged answers of listAddressesByVaultAccountId
//    and must verify against xpubs pinned on first sight; a swapped address refuses the whole page.
//  - first sight, trust on first use and its confirmation, SMART vaults, unknown vaults, the alarm hook, what is
//    refused until the client re-pins (a new algorithm on a pinned vault, a vault type change), and pins given in
//    configuration.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const util = require('node:util');

const {
    Vaultody, MemoryVaultKeyStore, VaultKeyChangedError, ResponseVerificationError, AddressVerificationError, ConfigurationError,
} = require('../src');
const { setup, CREDENTIALS, T0, VAULT, RELEASE_CANDIDATE, rootPem } = require('./helpers');
const { load } = require('./vectors');
const internal = require('../src/internal');

const PINS = load('vault-key-pins-v1.json');
const ADDRESSES = load('address-v1.json');
const NONCE = '0c9b8a7f6e5d4c3b2a1908f7e6d5c4b3';
const ORIGIN = 'https://vectors.example.test';
const ACCOUNT = '6630f1c2a9e4b5d7c8e9f0e2';

/** A pin store that keeps the vectors' pins under one origin and never latches. */
function vectorStore(initialPins) {
    const inner = new MemoryVaultKeyStore({
        format: 'vaultody vault keys v1',
        origins: { [ORIGIN]: { responseSignature: null, vaults: Object.fromEntries(initialPins.map(pin => [pin.vaultId, pin])), audit: [] } },
    });

    return {
        inner,
        get: (origin, vaultId) => inner.get(ORIGIN, vaultId),
        list: () => inner.list(ORIGIN),
        pinIfAbsent: (origin, pin) => inner.pinIfAbsent(ORIGIN, pin),
        upgradeTrust: (origin, pin) => inner.upgradeTrust(ORIGIN, pin),
        getResponseSignatureLatch: async () => null,
        latchResponseSignature: async (origin, latch) => latch,
    };
}

const byVaultId = pins => [...pins].sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1));

describe('test-vectors/vault-key-pins-v1.json through the pipeline', () => {
    for (const vector of PINS.cases) {
        it(vector.name, async () => {
            const env = await setup();
            const store = vectorStore(vector.initialPins);
            try {
                for (const step of vector.steps) {
                    const events = [];
                    const client = new Vaultody({
                        apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: env.gw.url,
                        vaultKeyStore: store, pinnedVaultKeys: vector.configuredPins,
                        logger: { warn() {} }, onSecurityEvent: event => events.push(event),
                        unsupported: { clock: env.clock, nonce: () => NONCE, embeddedRoots: PINS.pinnedRoots.map(rootPem), sdkVersion: RELEASE_CANDIDATE },
                    });
                    env.gw.requests.length = 0;
                    env.gw.mitm = () => {
                        env.clock.set(step.now * 1000);

                        return { status: step.response.status, headers: step.response.headers, body: Buffer.from(step.response.bodyBase64, 'base64') };
                    };
                    env.clock.set(T0);
                    const run = internal.request(client, 'listVaults', { networkType: 'main', limit: 50 });
                    const { expected } = step;
                    if (expected.signature.error) {
                        await assert.rejects(run, error => error instanceof ResponseVerificationError && error.reason === expected.signature.error);
                    } else if (expected.alarms) {
                        await assert.rejects(run, error => error instanceof VaultKeyChangedError && assert.deepEqual(error.alarms, expected.alarms) === undefined);
                        const alarm = events.find(event => event.type === 'vault_key_changed');
                        assert.deepEqual(alarm.alarms, expected.alarms);
                        // Short hashes only: no xpub in the event or the error.
                        for (const pin of [...vector.initialPins, ...vector.configuredPins, ...expected.pinsAfter]) {
                            for (const xpub of Object.values(pin.keys).filter(Boolean)) {
                                assert.ok(!JSON.stringify(alarm).includes(xpub));
                            }
                        }
                    } else {
                        const page = await run;
                        assert.equal(page.meta.signature, expected.signature);
                        // The vectors' outcomes, each with the status of the vault's pin after the answer: a configured
                        // pin counts as verified.
                        const after = new Map([...expected.pinsAfter.map(pin => [pin.vaultId, pin.status]), ...vector.configuredPins.map(pin => [pin.vaultId, 'verified'])]);
                        assert.deepEqual(page.meta.vaultKeys, expected.outcomes.map(({ vaultId, outcome }) => ({
                            vaultId, status: outcome === 'not_verifiable' ? 'not_verifiable' : after.get(vaultId), outcome,
                        })));
                    }
                    assert.equal(env.gw.requests[0].headers['x-api-sign'], step.request.apiSign);
                    assert.deepEqual(byVaultId(await store.inner.list(ORIGIN)), expected.pinsAfter);
                }
            } finally {
                await env.close();
            }
        });
    }
});

const vaultIdOf = (xpubName, type) => `${type}:${xpubName}`;

/** The vaults of address-v1.json: one main and one test vault per xpub. */
function vectorVaults() {
    const vaults = { main: [], test: [] };
    for (const { name, algorithm, xpub } of ADDRESSES.xpubs) {
        for (const type of ['main', 'test']) {
            vaults[type].push({ id: vaultIdOf(name, type), type, name, mpcKeys: [{ algorithm, xpub }] });
        }
    }

    return vaults;
}

/** The addresses of each vault, as list-addresses items with their derivation path. */
function vectorAddresses() {
    const lists = new Map();
    ADDRESSES.cases.forEach((c, index) => {
        const type = ADDRESSES.chains[c.blockchain].networks[c.network].vaultType.toLowerCase();
        const vaultId = vaultIdOf(c.xpubName, type);
        if (!lists.has(vaultId)) {
            lists.set(vaultId, []);
        }
        lists.get(vaultId).push({
            addressId: `a${String(index).padStart(4, '0')}`,
            address: c.address,
            blockchain: c.blockchain,
            network: c.network,
            accountIndex: c.accountIndex,
            isChange: c.change,
            addressIndex: String(c.addressIndex),
            addressFormat: c.addressFormatWire,
        });
    });

    return lists;
}

function listAddressesRoute(gw, lists, transform = items => items) {
    gw.route('GET', /\/vault-accounts\/[^/]+\/list-addresses$/, request => {
        const vaultId = decodeURIComponent(request.path.split('/')[2]);
        const all = lists.get(vaultId) || [];
        const query = new URLSearchParams(request.query);
        const limit = Number(query.get('limit') || 50);
        const after = query.get('startingAfter');
        const start = after ? all.findIndex(item => item.addressId === after) + 1 : 0;
        const items = transform(all.slice(start, start + limit));

        return { status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data: { limit, hasMore: start + limit < all.length, items } } };
    });
}

describe('test-vectors/address-v1.json through the pipeline', () => {
    it('all 511 addresses verify against xpubs pinned on first sight, page by page', async () => {
        const env = await setup();
        try {
            env.gw.vaults = vectorVaults();
            const lists = vectorAddresses();
            listAddressesRoute(env.gw, lists);
            let checked = 0;
            for (const vaultId of lists.keys()) {
                let page = await internal.request(env.client, 'listAddressesByVaultAccountId', { vaultId, vaultAccountId: ACCOUNT, limit: 50 });
                while (page) {
                    assert.equal(page.meta.addressChecks.length, page.items.length);
                    for (const check of page.meta.addressChecks) {
                        assert.equal(check.status, 'verified');
                        assert.equal(check.vaultId, vaultId);
                        checked += 1;
                    }
                    page = await page.nextPage();
                }
            }
            assert.equal(checked, ADDRESSES.cases.length);
            // Two listings pinned every vault (one per type), and only those.
            assert.equal(env.gw.requests.filter(request => /^\/vaults\/(main|test)$/.test(request.path)).length, 2);
            assert.ok(env.events.filter(event => event.type === 'vault_key_pinned').length === 10);
        } finally {
            await env.close();
        }
    });

    it('one swapped address refuses the whole page', async () => {
        const env = await setup();
        try {
            env.gw.vaults = vectorVaults();
            const lists = vectorAddresses();
            const [vaultId] = lists.keys();
            const other = ADDRESSES.cases.find(c => c.blockchain === lists.get(vaultId)[3].blockchain && c.address !== lists.get(vaultId)[3].address);
            listAddressesRoute(env.gw, lists, items => items.map((item, index) => (index === 3 ? { ...item, address: other.address } : item)));
            await assert.rejects(internal.request(env.client, 'listAddressesByVaultAccountId', { vaultId, vaultAccountId: ACCOUNT }),
                error => error instanceof AddressVerificationError && error.code === 'mismatch');
            assert.ok(env.events.some(event => event.type === 'address_verification_failed' && event.code === 'mismatch'));
        } finally {
            await env.close();
        }
    });
});

describe('pins and address checks', () => {
    const c = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.addressFormatWire === 'p2wpkh');
    const xpub = c.xpub;
    const vault = (keys, extra = {}) => ({ id: VAULT, type: 'main', name: 'Vault', ...(keys === null ? {} : { mpcKeys: keys }), ...extra });
    const deposit = (fields = {}) => ({
        address: c.address, label: 'deposit', accountIndex: c.accountIndex, isChange: c.change, addressIndex: c.addressIndex, addressFormat: c.addressFormatWire, ...fields,
    });
    const depositRoute = (gw, item) => gw.route('POST', /\/addresses$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item } } }));
    const generate = client => internal.request(client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'deposit', vaultAccountId: ACCOUNT });

    it('an address without its derivation path is not verifiable, and costs no vault listing', async () => {
        // Latched before, so no signed read precedes the write: the deposit is the only request.
        const env = await setup({ latched: true });
        try {
            depositRoute(env.gw, { address: c.address, label: 'deposit' });
            const result = await generate(env.client);
            assert.deepEqual(result.meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'not_verifiable' }]);
            assert.equal(env.gw.requests.length, 1);
        } finally {
            await env.close();
        }
    });

    it('trust on first use from an unsigned list, confirmed by the first signed answer', async () => {
        // A release candidate that embeds the roots: unsigned answers until the gateway signs, then verified.
        const env = await setup({ signing: false, roots: 'embedded' });
        try {
            env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
            depositRoute(env.gw, deposit());
            const first = await generate(env.client);
            assert.deepEqual(first.meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'unverified' }]);
            assert.deepEqual((await internal.request(env.client, 'listVaults', { networkType: 'main' })).meta.vaultKeys, [{ vaultId: VAULT, status: 'unverified', outcome: 'unchanged' }]);

            env.gw.signing = { root: 'current' };
            const second = await generate(env.client);
            assert.equal(second.meta.signature, 'verified');
            assert.deepEqual(second.meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'verified' }]);
            assert.ok(env.events.some(event => event.type === 'vault_key_verified' && event.vaultId === VAULT && event.status === 'verified'));
            assert.deepEqual((await internal.request(env.client, 'listVaults', { networkType: 'main' })).meta.vaultKeys, [{ vaultId: VAULT, status: 'verified', outcome: 'unchanged' }]);
        } finally {
            await env.close();
        }
    });

    it('an xpub changed on the server is the alarm: hook first, pin untouched, nothing returned, never re-pinned', async () => {
        const env = await setup();
        try {
            env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
            await internal.request(env.client, 'listVaults', { networkType: 'main' });
            const other = ADDRESSES.xpubs.find(item => item.algorithm === 'ECDSA' && item.xpub !== xpub).xpub;
            env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub: other }])];
            for (let i = 0; i < 2; i += 1) {
                await assert.rejects(internal.request(env.client, 'listVaults', { networkType: 'main' }), error => error instanceof VaultKeyChangedError
                    && error.alarms[0].reason === 'xpub_changed' && !error.message.includes(other));
            }
            assert.equal(env.events.filter(event => event.type === 'vault_key_changed').length, 2);
            const store = env.client;
            assert.ok(store);
            // The pinned xpub still decides: the address of the old xpub verifies.
            depositRoute(env.gw, deposit());
            assert.equal((await generate(env.client)).meta.addressChecks[0].status, 'verified');
        } finally {
            await env.close();
        }
    });

    it('refuses a new algorithm on a pinned vault and a vault type change until the client re-pins', async () => {
        const env = await setup();
        try {
            env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
            await internal.request(env.client, 'listVaults', { networkType: 'main' });
            const eddsa = ADDRESSES.xpubs.find(item => item.algorithm === 'EDDSA').xpub;
            env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }, { algorithm: 'EDDSA', xpub: eddsa }])];
            await assert.rejects(internal.request(env.client, 'listVaults', { networkType: 'main' }), error => error instanceof VaultKeyChangedError && error.alarms[0].reason === 'xpub_added');
            env.gw.vaults.test = [vault([{ algorithm: 'ECDSA', xpub }], { type: 'test' })];
            await assert.rejects(internal.request(env.client, 'listVaults', { networkType: 'test' }), error => error instanceof VaultKeyChangedError && error.alarms[0].reason === 'type_changed');
        } finally {
            await env.close();
        }
    });

    describe('pins given in configuration (pinnedVaultKeys)', () => {
        const configured = (keys = { ECDSA: xpub, EDDSA: null }) => [{ vaultId: VAULT, type: 'main', keys }];

        it('are checked when the client is made, and an error never names an xpub', () => {
            const make = pinnedVaultKeys => new Vaultody({ ...CREDENTIALS, vaultKeyStore: new MemoryVaultKeyStore(), pinnedVaultKeys });
            for (const bad of [
                { vaultId: VAULT, type: 'main', keys: { ECDSA: xpub, EDDSA: null } },
                [{ vaultId: VAULT, type: 'main', keys: { ECDSA: xpub } }],
                [{ vaultId: VAULT, type: 'main', keys: { ECDSA: null, EDDSA: null } }],
                [{ vaultId: VAULT, type: 'MAIN', keys: { ECDSA: xpub, EDDSA: null } }],
                [{ vaultId: '', type: 'main', keys: { ECDSA: xpub, EDDSA: null } }],
                [{ vaultId: VAULT, type: 'main', keys: { ECDSA: xpub, EDDSA: null }, status: 'verified' }],
                [{ vaultId: VAULT, type: 'main', keys: { ECDSA: xpub, EDDSA: null, SCHNORR: xpub } }],
                [{ vaultId: VAULT, type: 'main', keys: { ECDSA: '', EDDSA: null } }],
                [...configured(), ...configured()],
                [null],
            ]) {
                assert.throws(() => make(bad), error => error instanceof ConfigurationError && error.code === 'invalid_option' && !error.message.includes(xpub), JSON.stringify(bad));
            }
            const client = make(configured());
            assert.ok(!util.inspect(client).includes(xpub) && !JSON.stringify(client).includes(xpub));
        });

        it('count as verified with an unsigned list, and are never written to the store', async () => {
            const store = new MemoryVaultKeyStore();
            const env = await setup({ signing: false, client: { vaultKeyStore: store, pinnedVaultKeys: configured() } });
            try {
                env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
                const page = await internal.request(env.client, 'listVaults', { networkType: 'main' });
                assert.equal(page.meta.signature, 'absent');
                assert.deepEqual(page.meta.vaultKeys, [{ vaultId: VAULT, status: 'verified', outcome: 'unchanged' }]);
                assert.deepEqual(await store.list(env.client.origin), []);
                assert.ok(!env.events.some(event => event.type === 'vault_key_pinned'));
            } finally {
                await env.close();
            }
        });

        it('check addresses as verified, with no vault listing', async () => {
            const env = await setup({ signing: false, client: { pinnedVaultKeys: configured() } });
            try {
                depositRoute(env.gw, deposit());
                const result = await generate(env.client);
                assert.deepEqual(result.meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'verified' }]);
                assert.equal(env.gw.requests.length, 1);
            } finally {
                await env.close();
            }
        });

        it('a swapped address is refused, and a changed xpub is the alarm; the stored pin of the vault is not used', async () => {
            const other = ADDRESSES.xpubs.find(item => item.algorithm === 'ECDSA' && item.xpub !== xpub).xpub;
            const store = new MemoryVaultKeyStore();
            const env = await setup({ client: { vaultKeyStore: store, pinnedVaultKeys: configured() } });
            try {
                // A stored pin of the same vault, with another xpub: the configured pin takes its place.
                await store.pinIfAbsent(env.client.origin, {
                    vaultId: VAULT, type: 'main', keys: { ECDSA: other, EDDSA: null }, status: 'unverified', firstSeenAt: 1, verifiedAt: null, verification: null,
                });
                const before = await store.list(env.client.origin);
                const swapped = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.xpub !== xpub);
                depositRoute(env.gw, deposit({ address: swapped.address }));
                await assert.rejects(generate(env.client), error => error instanceof AddressVerificationError && error.code === 'mismatch');

                env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub: other }])];
                await assert.rejects(internal.request(env.client, 'listVaults', { networkType: 'main' }),
                    error => error instanceof VaultKeyChangedError && error.alarms[0].reason === 'xpub_changed' && !error.message.includes(other));
                assert.ok(env.events.some(event => event.type === 'vault_key_changed'));
                assert.deepEqual(await store.list(env.client.origin), before);
            } finally {
                await env.close();
            }
        });
    });

    it('a SMART vault (no MPC keys) is not verifiable, never verified', async () => {
        const env = await setup();
        try {
            env.gw.vaults.main = [vault(null, { type: 'main' })];
            depositRoute(env.gw, deposit());
            assert.deepEqual((await generate(env.client)).meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'not_verifiable' }]);
        } finally {
            await env.close();
        }
    });

    describe('requireAddressPaths', () => {
        const pathless = { address: c.address, label: 'deposit' };

        it('on: generateDepositAddress without a path for a vault with MPC keys is refused (path_missing), after the event', async () => {
            const env = await setup({ client: { requireAddressPaths: true } });
            try {
                env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
                let answer = pathless;
                env.gw.route('POST', /\/addresses$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item: answer } } }));
                await assert.rejects(generate(env.client), error => error instanceof AddressVerificationError && error.code === 'path_missing');
                const event = env.events.find(item => item.type === 'address_verification_failed');
                assert.deepEqual({ code: event.code, vaultId: event.vaultId, operationId: event.operationId }, { code: 'path_missing', vaultId: VAULT, operationId: 'generateDepositAddress' });
                // With the path it is checked as always.
                answer = deposit();
                assert.deepEqual((await generate(env.client)).meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'verified' }]);
            } finally {
                await env.close();
            }
        });

        it('on: a SMART vault, a chain the SDK can\'t derive and an address list stay not verifiable', async () => {
            const env = await setup({ client: { requireAddressPaths: true } });
            try {
                env.gw.vaults.main = [vault(null, { type: 'main' })];
                depositRoute(env.gw, pathless);
                assert.deepEqual((await generate(env.client)).meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'not_verifiable' }]);
            } finally {
                await env.close();
            }
            const keyed = await setup({ client: { requireAddressPaths: true } });
            try {
                keyed.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
                depositRoute(keyed.gw, pathless);
                const unknown = await internal.request(keyed.client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'no-such-chain', network: 'mainnet', label: 'deposit', vaultAccountId: ACCOUNT });
                assert.deepEqual(unknown.meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'not_verifiable' }]);
                keyed.gw.route('GET', /\/list-addresses$/, () => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data: { limit: 50, hasMore: false, items: [pathless] } } }));
                const list = await internal.request(keyed.client, 'listAddressesByVaultAccountId', { vaultId: VAULT, vaultAccountId: ACCOUNT, blockchain: 'bitcoin' });
                assert.deepEqual(list.meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'not_verifiable' }]);
            } finally {
                await keyed.close();
            }
        });

        it('off by default while the paths are hidden; only true or false', async () => {
            const env = await setup();
            try {
                env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
                depositRoute(env.gw, pathless);
                assert.deepEqual((await generate(env.client)).meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'not_verifiable' }]);
            } finally {
                await env.close();
            }
            assert.throws(() => new Vaultody({ ...CREDENTIALS, vaultKeyStore: new MemoryVaultKeyStore(), requireAddressPaths: 'yes' }),
                error => error instanceof ConfigurationError && error.code === 'invalid_option');
        });
    });

    it('a vault missing from the list fails closed', async () => {
        const env = await setup();
        try {
            depositRoute(env.gw, deposit());
            await assert.rejects(generate(env.client), error => error instanceof AddressVerificationError && error.code === 'unknown_vault');
        } finally {
            await env.close();
        }
    });

    it('a swapped deposit address, a network that does not match, an unknown chain: refused', async () => {
        const other = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.address !== c.address && item.xpub !== xpub);
        for (const [item, code] of [
            [deposit({ address: other.address }), 'mismatch'],
            [deposit({ network: 'testnet' }), 'network_mismatch'],
            [deposit({ blockchain: 'litecoin' }), 'mismatch'],
            [deposit({ addressFormat: 'p2sh-cash' }), 'unsupported'],
            [deposit({ accountIndex: 'x' }), 'invalid'],
        ]) {
            const env = await setup();
            try {
                env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
                depositRoute(env.gw, item);
                await assert.rejects(generate(env.client), error => error instanceof AddressVerificationError && error.code === code, JSON.stringify(item));
            } finally {
                await env.close();
            }
        }
    });

    it('add asset: the address answered must be the one sent, and one with a path but no chain is refused', async () => {
        const env = await setup();
        try {
            env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }])];
            let item = { address: 'bc1qother', assetUnit: 'BTC' };
            env.gw.route('PUT', /\/add-asset$/, () => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item } } }));
            const add = () => internal.request(env.client, 'addAssetToVaultAccount', { vaultId: VAULT, vaultAccountId: ACCOUNT, assetId: 'btc', address: c.address });
            await assert.rejects(add(), error => error instanceof AddressVerificationError && error.code === 'mismatch');
            item = deposit({ assetUnit: 'BTC' });
            await assert.rejects(add(), error => error instanceof AddressVerificationError && error.code === 'unsupported');
            item = deposit({ assetUnit: 'BTC', blockchain: 'bitcoin', network: 'mainnet' });
            assert.equal((await add()).meta.addressChecks[0].status, 'verified');
        } finally {
            await env.close();
        }
    });

    it('vault types are read case-insensitively in the route, and pins are kept per origin', async () => {
        const env = await setup();
        try {
            env.gw.vaults.main = [vault([{ algorithm: 'ECDSA', xpub }], { type: 'MAIN' })];
            const page = await internal.request(env.client, 'listVaults', { networkType: 'MAIN' });
            assert.deepEqual(page.meta.vaultKeys, [{ vaultId: VAULT, status: 'verified', outcome: 'pinned' }]);
        } finally {
            await env.close();
        }
    });
});
