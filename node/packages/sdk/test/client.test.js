'use strict';

// The client's setup and its guards: options, base URL, credentials kept out of every output, params refused
// rather than dropped, the pinned x-api-version and User-Agent, the rate limiter.

const assert = require('node:assert/strict');
const util = require('node:util');
const net = require('node:net');
const { describe, it } = require('node:test');

const { Vaultody, MemoryVaultKeyStore, ConfigurationError, ParameterError, TransportError, API_VERSION, SDK_VERSION } = require('../src');
const { RateLimiter } = require('../src/rateLimiter');
const { setup, CREDENTIALS, KEYS, VAULT } = require('./helpers');
const internal = require('../src/internal');

const base = { apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, vaultKeyStore: new MemoryVaultKeyStore() };
const make = options => new Vaultody({ ...base, ...options });
const code = expected => error => error instanceof ConfigurationError && error.code === expected;
const noSleep = { sleep: async () => {} };

/** A port that was just free: nothing listens on it any more. */
async function closedPort() {
    const server = net.createServer();
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    await new Promise(resolve => server.close(resolve));

    return port;
}

describe('client options', () => {
    it('https only; plain http only to this machine; no credentials, query or fragment in the base URL', () => {
        for (const url of ['https://rest.vaultody.com', 'https://rest.vaultody.com/', 'http://localhost:8080', 'http://127.0.0.1:1', 'http://[::1]:2']) {
            assert.ok(make({ baseUrl: url }));
        }
        for (const url of ['http://rest.vaultody.com', 'ftp://x', 'https://user:pw@rest.vaultody.com', 'https://rest.vaultody.com/?a=1', 'https://rest.vaultody.com/#x', 'not a url']) {
            assert.throws(() => make({ baseUrl: url }), code('invalid_base_url'), url);
        }
        assert.equal(make({ baseUrl: 'https://rest.vaultody.com/' }).origin, 'https://rest.vaultody.com');
    });

    it('refuses unknown options, and credentials that are missing or malformed', () => {
        assert.throws(() => make({ responseSignatures: 'required' }), code('unknown_option'));
        assert.throws(() => make({ unsupported: { verifyTls: false } }), code('unknown_option'));
        assert.throws(() => make({ apiKey: '' }), code('invalid_credentials'));
        assert.throws(() => make({ passphrase: 'line\nbreak' }), code('invalid_credentials'));
        assert.throws(() => make({ apiSecret: 'not base64!' }), code('invalid_api_secret'));
        assert.throws(() => make({ maxRequestsPerSecond: 0 }), code('invalid_option'));
        assert.throws(() => make({ timeoutMs: -1 }), code('invalid_option'));
        assert.throws(() => make({ vaultKeyStore: {} }), code('invalid_option'));
        assert.throws(() => make({ vaultKeysFile: '/tmp/x' }), code('invalid_option'));
        assert.throws(() => make({ unsupported: { apiVersion: 'latest' } }), code('invalid_option'));
    });

    it('keeps the API secret, passphrase and key out of inspect, JSON and errors', async () => {
        const secretParts = [CREDENTIALS.apiSecret, CREDENTIALS.passphrase, CREDENTIALS.apiKey];
        const client = make({ signer: require('../src').pemSigner(KEYS.ed25519.privateKeyPkcs8Pem), baseUrl: `http://127.0.0.1:${await closedPort()}`, unsupported: noSleep });
        const outputs = [util.inspect(client, { depth: 10, showHidden: true }), JSON.stringify(client), String(client), util.inspect(client.webhooks, { depth: 10 })];
        for (const failing of [
            () => internal.request(client, 'getTransactionRequestDetails', { transactionRequestId: 'x' }),
            () => internal.request(client, 'createSingleTransfer', { vaultId: VAULT, nope: 1 }),
            () => make({ apiSecret: `${CREDENTIALS.apiSecret}!` }),
        ]) {
            try {
                await failing();
            } catch (error) {
                outputs.push(util.inspect(error, { depth: 10, showHidden: true }), String(error.stack));
            }
        }
        for (const output of outputs) {
            for (const secret of secretParts) {
                assert.ok(!output.includes(secret), `${secret.slice(0, 4)}… found in ${output.slice(0, 80)}`);
            }
            assert.ok(!output.includes('PRIVATE KEY'));
        }
    });

    it('refuses unknown params, call options and operations rather than dropping them', async () => {
        const client = make({ baseUrl: `http://127.0.0.1:${await closedPort()}`, unsupported: noSleep });
        await assert.rejects(internal.request(client, 'createSingleTransfer', { vaultId: VAULT, amont: '1' }), error => error instanceof ParameterError && error.code === 'unknown_param');
        await assert.rejects(internal.request(client, 'createSingleTransfer', { vaultId: VAULT }, { idempotencyKey: 'x' }), error => error instanceof ParameterError && error.code === 'unknown_option');
        await assert.rejects(internal.request(client, 'noSuchOperation'), error => error instanceof ParameterError && error.code === 'unknown_operation');
        await assert.rejects(internal.request(client, { ...require('../src').operationById('listVaults'), path: '/vaults/x' }, {}), error => error.code === 'unknown_operation');
        await assert.rejects(internal.request(client, 'getTransactionRequestDetails', {}), error => error instanceof ParameterError && error.code === 'missing_path_param');
        await assert.rejects(internal.request(client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'x'.repeat(1024 * 1024) }), error => error.code === 'body_too_large');
    });

    it('sends the pinned x-api-version, a User-Agent naming the SDK, JSON content type, and the context', async () => {
        // Latched before, so no signed read precedes the write: the deposit is the first request.
        const env = await setup({ latched: true });
        try {
            env.gw.route('POST', /\/addresses$/, () => ({ status: 201, body: { apiVersion: API_VERSION, requestId: 'r', context: 'mine', data: { item: { address: 'a' } } } }));
            const result = await internal.request(env.client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'l', vaultAccountId: 'v' }, { context: 'mine' });
            assert.equal(result.meta.context, 'mine');
            const [sent] = env.gw.requests;
            assert.equal(sent.headers['x-api-version'], API_VERSION);
            assert.match(sent.headers['user-agent'], new RegExp(`^vaultody-sdk-node/${SDK_VERSION.replace(/\./g, '\\.')} \\(node/`));
            assert.equal(sent.headers['content-type'], 'application/json');
            assert.equal(sent.body.toString(), '{"context":"mine","data":{"item":{"label":"l","vaultAccountId":"v"}}}');
            assert.equal(env.gw.requests[0].headers['x-api-nonce'].length, 32);
            await internal.request(env.client, 'listVaults', { networkType: 'main' }, { context: 'q' });
            assert.equal(env.gw.requests[1].query, 'context=q');
        } finally {
            await env.close();
        }
    });

    it('a fresh 16-byte nonce on every request', async () => {
        const env = await setup();
        try {
            for (let i = 0; i < 5; i += 1) {
                await internal.request(env.client, 'listVaults', { networkType: 'main' });
            }
            const nonces = env.gw.requests.map(request => request.headers['x-api-nonce']);
            assert.equal(new Set(nonces).size, 5);
            assert.ok(nonces.every(nonce => /^[0-9a-f]{32}$/.test(nonce)));
        } finally {
            await env.close();
        }
    });

    it('never follows a redirect with the credentials', async () => {
        const env = await setup({ signing: false });
        try {
            env.gw.route('GET', /^\/vaults\/main$/, () => ({ status: 302, headers: { location: 'https://elsewhere.example/' }, body: '' }));
            await assert.rejects(internal.request(env.client, 'listVaults', { networkType: 'main' }), error => error.status === 302);
            assert.equal(env.gw.requests.length, 1);
        } finally {
            await env.close();
        }
    });

    it('a connection refused on a real port is not sent', async () => {
        const client = make({ baseUrl: `http://127.0.0.1:${await closedPort()}`, unsupported: noSleep });
        await assert.rejects(internal.request(client, 'listVaults', { networkType: 'main' }), error => error instanceof TransportError && error.sent === false);
    });
});

describe('rate limiter', () => {
    it('lets a burst of 5 through, then spaces requests at the configured rate', async () => {
        let now = 0;
        const waits = [];
        const limiter = new RateLimiter({ perSecond: 5, clock: () => now, sleep: async ms => { waits.push(ms); now += ms; } });
        for (let i = 0; i < 20; i += 1) {
            await limiter.take();
        }
        assert.equal(waits.length, 15);
        assert.ok(waits.every(ms => ms === 200));
        assert.equal(now, 3000);
    });

    it('a 20-call burst through the client: the gateway sees at most 5 a second', async () => {
        const env = await setup({ client: { maxRequestsPerSecond: 5 } });
        try {
            env.gw.route('GET', /^\/transaction-requests\//, () => ({ status: 200, body: { apiVersion: API_VERSION, requestId: 'r', data: { item: {} } } }));
            const started = env.clock();
            await Promise.all(Array.from({ length: 20 }, (_, i) => internal.request(env.client, 'getTransactionRequestDetails', { transactionRequestId: `t${i}` })));
            // The first 5 go at once; each of the other 15 waits its 200 ms turn (no 429 needed).
            assert.deepEqual(env.sleeps, Array(15).fill(200));
            assert.equal(env.clock() - started, 3000);
            assert.equal(env.gw.requests.length, 20);
        } finally {
            await env.close();
        }
    });
});

describe('what the client exposes', () => {
    it('no low-level call: not on the client, not exported by the package', async () => {
        const client = make({});
        for (const name of ['request', 'paginate']) {
            assert.equal(client[name], undefined, name);
            assert.ok(!(name in client), name);
        }
        const pkg = require('@vaultody-com/sdk');
        for (const name of ['request', 'internal', 'lowLevelCalls']) {
            assert.equal(pkg[name], undefined, name);
        }
        // Internal modules are not reachable through the package name.
        for (const subpath of ['@vaultody-com/sdk/src/internal', '@vaultody-com/sdk/src/internal.js', '@vaultody-com/sdk/src/client.js']) {
            assert.throws(() => require(subpath), error => error.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED', subpath);
        }
        assert.throws(() => internal.request({}, 'listVaults'), TypeError);
    });

    it('a page keeps the call that fetched it private: only nextPage() and autoPaging() ask again', async () => {
        const env = await setup();
        try {
            env.gw.route('GET', /\/transactions$/, () => ({ status: 200, body: { apiVersion: API_VERSION, requestId: 'r', data: { limit: 1, hasMore: false, items: [{ id: 'a' }] } } }));
            const page = await env.client.vaults.listTransactionsByVault({ vaultId: VAULT });
            assert.equal(page.context, undefined);
            assert.ok(!Object.getOwnPropertyNames(page).some(name => typeof page[name] === 'function'));
            assert.equal(await page.nextPage(), null);
        } finally {
            await env.close();
        }
    });
});
