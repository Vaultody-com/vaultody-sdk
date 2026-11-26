'use strict';

// Every API method through the whole pipeline, against the mock gateway (conformance/mock-gateway), with the
// API reference's own examples (contract/openapi.json):
//  - the documented example request: the method and path on the wire, query fields in the query, body fields
//    in { context, data: { item } }, the context in the query of a GET and the body of a POST or PUT, and a
//    request the mock's signature check accepts;
//  - the documented success answer comes back as the item or page, with meta;
//  - every documented error answer becomes its typed error with its code;
//  - the retry class: a read (and a POST that changes nothing) is re-signed and retried after a 503, a write is
//    never sent twice;
//  - params refused before anything is sent: each required field missing, each field of the wrong type or
//    value, an unknown field;
//  - lists: iterating gives every item, page after page, from the documented cursor field;
//  - the address-returning operations: addresses checked against the pinned vault xpub, and refused whole when
//    one does not derive from it; listVaults pins.

const assert = require('node:assert/strict');
const path = require('node:path');
const { readFileSync } = require('node:fs');
const { describe, it } = require('node:test');

const sdk = require('../src');
const { setup, VAULT } = require('./helpers');
const { load } = require('./vectors');

const ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const OPENAPI = JSON.parse(readFileSync(path.join(ROOT, 'contract', 'openapi.json'), 'utf8'));
const ADDRESSES = load('address-v1.json');
const CONTEXT = 'order-1842';
const SIGNING_KEYS = '/api-keys/current/signing-keys';

/** Namespace of each docs group (method names are the operationIds, grouped by docs group). */
const NAMESPACE = { vaults: 'vaults', 'vault-accounts': 'vaultAccounts', 'assets-addresses': 'assetsAddresses', transactions: 'transactions', 'api-keys': 'apiKeys' };

/** The documented operations: method, path, group, example request and answers. */
function documentedOperations() {
    const out = new Map();
    for (const [template, item] of Object.entries(OPENAPI.paths)) {
        for (const method of ['get', 'post', 'put']) {
            const op = item[method];
            if (!op) {
                continue;
            }
            const params = {};
            const placement = {};
            for (const param of op.parameters || []) {
                if (param.$ref) {
                    continue;
                }
                params[param.name] = param.example !== undefined ? param.example : param.schema.example;
                placement[param.name] = param.in;
            }
            const bodyItem = op.requestBody ? op.requestBody.content['application/json'].example.data.item : null;
            Object.assign(params, bodyItem || {});
            const status = op.responses['200'] ? 200 : 201;
            const errors = [];
            for (const [code, response] of Object.entries(op.responses)) {
                const content = response.content && response.content['application/json'];
                if (Number(code) >= 400 && content && content.examples) {
                    for (const example of Object.values(content.examples)) {
                        errors.push({ status: Number(code), body: example.value });
                    }
                }
            }
            out.set(op.operationId, {
                operationId: op.operationId,
                namespace: NAMESPACE[op.tags[0]],
                method: method.toUpperCase(),
                template,
                params,
                placement,
                bodyItem,
                success: { status, body: op.responses[String(status)].content['application/json'].examples.success.value },
                errors,
            });
        }
    }
    // Pending in the docs: no parameters; the mock answers it from the API key's registered keys.
    out.set('listApiKeySigningKeys', {
        operationId: 'listApiKeySigningKeys',
        namespace: 'apiKeys',
        method: 'GET',
        template: '/api-keys/current/signing-keys',
        params: {},
        placement: {},
        bodyItem: null,
        success: null,
        errors: [
            { status: 401, body: { requestId: '601c1710034ed6d407996b30', error: { code: 'invalid_api_key', message: 'The API key is not valid.' } } },
            { status: 403, body: { requestId: '601c1710034ed6d407996b30', error: { code: 'ip_address_not_whitelisted', message: 'This IP address is not allowed.' } } },
        ],
    });

    return out;
}

const DOCUMENTED = documentedOperations();

/** The request target the API expects for these params. */
function expectedTarget(doc, params) {
    const pathPart = doc.template.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name) => encodeURIComponent(params[name]));
    const query = Object.entries(params).filter(([name]) => doc.placement[name] === 'query').map(([name, value]) => [name, String(value)]);

    return { path: pathPart, query };
}

/** The error class of a status and code, written out here independently of the SDK's own mapping. */
function expectedClass(status, code) {
    if (['api_keypair_required', 'missing_api_keypair_sign', 'missing_api_nonce', 'unknown_api_keypair_id', 'invalid_api_keypair_sign'].includes(code)) {
        return 'RequestSigningError';
    }
    if (code === 'double_spending') {
        return 'DuplicateTransferError';
    }
    if (['invalid_data', 'missing_required_attributes', 'extra_body_attributes', 'extra_query_attributes', 'invalid_api_version'].includes(code)) {
        return 'InvalidRequestError';
    }

    return { 400: 'InvalidRequestError', 401: 'AuthenticationError', 403: 'PermissionDeniedError', 404: 'NotFoundError', 409: 'ConflictError', 415: 'InvalidRequestError', 422: 'InvalidRequestError' }[status];
}

const pattern = doc => new RegExp(`^${doc.template.replace(/\{[A-Za-z0-9_]+\}/g, '[^/]+')}$`);
const call = (client, doc, params, options) => client[doc.namespace][doc.operationId](params, options);

/** A value of the wrong type for a schema, or outside its documented values. */
function wrongValue(schema) {
    if (schema.enum) {
        return 'not-a-documented-value';
    }

    return { string: 1, integer: '1', boolean: 'true', object: 'x', array: {} }[schema.type];
}

describe('every operation has its method, in its docs group', () => {
    it('32 methods: 4 vaults, 7 vaultAccounts, 9 assetsAddresses, 11 transactions, 1 apiKeys', async () => {
        const env = await setup();
        try {
            const counts = {};
            for (const entry of sdk.OPERATIONS) {
                const doc = DOCUMENTED.get(entry.operationId);
                const fn = env.client[doc.namespace][entry.operationId];
                assert.equal(typeof fn, 'function', `${doc.namespace}.${entry.operationId}`);
                assert.equal(fn.operationId, entry.operationId);
                counts[doc.namespace] = (counts[doc.namespace] || 0) + 1;
            }
            assert.deepEqual(counts, { vaults: 4, vaultAccounts: 7, assetsAddresses: 9, transactions: 11, apiKeys: 1 });
            for (const namespace of Object.values(NAMESPACE)) {
                assert.ok(Object.isFrozen(env.client[namespace]));
            }
        } finally {
            await env.close();
        }
    });
});

for (const entry of sdk.OPERATIONS) {
    const doc = DOCUMENTED.get(entry.operationId);
    const isList = entry.paging !== null;
    const hasBody = entry.method === 'POST' || entry.method === 'PUT';

    describe(`${doc.namespace}.${entry.operationId}`, () => {
        it('the documented example: request on the wire, answer back, through the whole pipeline', async () => {
            const env = await setup({ key: entry.operationId === 'listApiKeySigningKeys' ? 'ed25519' : null });
            try {
                if (doc.success) {
                    env.gw.route(doc.method, pattern(doc), () => ({ status: doc.success.status, body: doc.success.body }));
                }
                const run = call(env.client, doc, { ...doc.params }, { context: CONTEXT });
                assert.ok(run instanceof Promise);
                assert.equal(typeof run[Symbol.asyncIterator], isList ? 'function' : 'undefined');
                const result = await run;

                // A client with response-signing roots makes one signed read before its first write (client.js); it and
                // the vault lists read for the address check are not this operation's request.
                const signedReads = env.gw.requests.filter(request => request.path === SIGNING_KEYS && entry.operationId !== 'listApiKeySigningKeys');
                assert.equal(signedReads.length, entry.retry === 'write' ? 1 : 0);
                // The request: the mock checked its signatures; method, path, query and body are the documented ones.
                const requests = env.gw.requests.filter(request => (!/^\/vaults\/(main|test)$/.test(request.path) || entry.operationId === 'listVaults')
                    && (request.path !== SIGNING_KEYS || entry.operationId === 'listApiKeySigningKeys'));
                assert.equal(requests.length, 1);
                const [request] = requests;
                const expected = expectedTarget(doc, doc.params);
                assert.equal(request.method, doc.method);
                assert.equal(request.path, expected.path);
                const query = [...new URLSearchParams(request.query)];
                if (hasBody) {
                    assert.deepEqual(query, expected.query);
                    assert.equal(request.headers['content-type'], 'application/json');
                    assert.deepEqual(JSON.parse(request.body.toString('utf8')), { context: CONTEXT, data: { item: doc.bodyItem } });
                } else {
                    assert.deepEqual(query, [...expected.query, ['context', CONTEXT]]);
                    assert.equal(request.body.length, 0);
                }
                assert.equal(request.headers['x-api-version'], sdk.API_VERSION);

                // The answer.
                assert.equal(result.meta.operationId, entry.operationId);
                assert.equal(result.meta.signature, 'verified');
                if (doc.success) {
                    const { body } = doc.success;
                    assert.equal(result.meta.requestId, body.requestId);
                    assert.equal(result.meta.apiVersion, body.apiVersion);
                    assert.equal(result.meta.context, body.context === undefined ? null : body.context);
                    if (isList) {
                        assert.ok(result instanceof sdk.Page);
                        assert.deepEqual(result.items, body.data.items);
                        assert.equal(result.hasMore, body.data.hasMore);
                        assert.equal(result.limit, body.data.limit);
                    } else {
                        assert.deepEqual(result.item, body.data.item);
                    }
                } else {
                    assert.deepEqual(result.items.map(item => item.fingerprint), [env.client.signerFingerprint]);
                    assert.equal(result.hasMore, false);
                }
                if (['generateDepositAddress', 'listAddressesByVaultAccountId', 'addAssetToVaultAccount'].includes(entry.operationId)) {
                    // The documented examples carry no derivation path (the API hides it for now).
                    const items = isList ? result.items : [result.item];
                    assert.deepEqual(result.meta.addressChecks, items.map(item => ({ vaultId: doc.params.vaultId, address: item.address, status: 'not_verifiable' })));
                } else {
                    assert.equal(result.meta.addressChecks, undefined);
                }
                if (entry.operationId === 'listVaults') {
                    assert.deepEqual(result.meta.vaultKeys.map(item => item.vaultId), doc.success.body.data.items.map(item => item.id));
                }
            } finally {
                await env.close();
            }
        });

        it('every documented error answer: its typed error and code', async () => {
            const env = await setup();
            try {
                let answer = null;
                env.gw.route(doc.method, pattern(doc), () => answer);
                const errors = doc.errors.filter(error => error.status !== 429 && error.status < 500);
                assert.ok(errors.length > 0);
                for (const error of errors) {
                    answer = { status: error.status, body: error.body };
                    if (entry.operationId === 'listApiKeySigningKeys') {
                        env.gw.mitm = ({ request, response }) => (request.path === doc.template ? env.gw.finish(request, answer) : response);
                    }
                    const thrown = await call(env.client, doc, { ...doc.params }).then(() => null, e => e);
                    assert.ok(thrown instanceof sdk.ApiError, `${error.status} ${error.body.error.code}: ${thrown}`);
                    assert.equal(thrown.name, expectedClass(error.status, error.body.error.code), `${error.status} ${error.body.error.code}`);
                    assert.equal(thrown.status, error.status);
                    assert.equal(thrown.code, error.body.error.code);
                    assert.equal(thrown.message, error.body.error.message);
                    assert.equal(thrown.requestId, error.body.requestId);
                    assert.equal(thrown.signature, 'verified');
                }
            } finally {
                await env.close();
            }
        });

        it(`retry class ${entry.retry}: ${entry.retry === 'read' ? 're-signed and retried after a 503' : 'never sent twice'}`, async () => {
            const env = await setup({ key: entry.operationId === 'listApiKeySigningKeys' ? 'ed25519' : null });
            try {
                if (doc.success) {
                    env.gw.route(doc.method, pattern(doc), () => ({ status: doc.success.status, body: doc.success.body }));
                }
                env.gw.fault({ status: 503, match: request => request.path === expectedTarget(doc, doc.params).path });
                const run = call(env.client, doc, { ...doc.params });
                const sent = () => env.gw.requests.filter(request => request.path === expectedTarget(doc, doc.params).path);
                if (entry.retry === 'read') {
                    await run;
                    assert.equal(sent().length, 2);
                    assert.notEqual(sent()[0].headers['x-api-nonce'], sent()[1].headers['x-api-nonce'], 're-signed');
                } else {
                    await assert.rejects(run, sdk.RequestOutcomeUnknownError);
                    assert.equal(sent().length, 1);
                }
            } finally {
                await env.close();
            }
        });

        it('params checked before anything is sent: each required field, each type and value, unknown fields', async () => {
            const env = await setup();
            try {
                const rejects = async (params, code, param) => {
                    const error = await call(env.client, doc, params).then(() => null, e => e);
                    assert.ok(error instanceof sdk.ParameterError, `${param}: ${error}`);
                    assert.equal(error.code, code, `${param}: ${error.message}`);
                    assert.equal(error.param, param);
                };
                for (const param of entry.params) {
                    if (param.required) {
                        const { [param.name]: dropped, ...rest } = doc.params;
                        assert.ok(dropped !== undefined);
                        await rejects(rest, 'missing_param', param.name);
                    }
                    await rejects({ ...doc.params, [param.name]: wrongValue(param.schema) }, 'invalid_param', param.name);
                }
                await rejects({ ...doc.params, notAField: 'x' }, 'unknown_param', 'notAField');
                if (isList) {
                    // A list's iterator refuses the same way.
                    await assert.rejects(async () => {
                        // eslint-disable-next-line no-unused-vars
                        for await (const item of call(env.client, doc, { ...doc.params, notAField: 'x' })) {
                            // never reached
                        }
                    }, error => error instanceof sdk.ParameterError && error.code === 'unknown_param');
                }
                await assert.rejects(call(env.client, doc, null), error => error instanceof sdk.ParameterError && error.code === 'invalid_params');
                await assert.rejects(call(env.client, doc, { ...doc.params }, { idempotencyKey: 'k' }), error => error instanceof sdk.ParameterError && error.code === 'unknown_option');
                assert.equal(env.gw.requests.length, 0);
            } finally {
                await env.close();
            }
        });

        if (entry.paging === 'cursor' && entry.cursorField) {
            it(`iterating gives every item, the next page after the last item's ${entry.cursorField}`, async () => {
                const env = await setup();
                try {
                    const { startingAfter, ...params } = doc.params;
                    assert.ok(startingAfter !== undefined);
                    const networkType = params.networkType;
                    const itemOf = n => ({
                        [entry.cursorField]: `c${n}`,
                        ...(entry.operationId === 'listVaults' ? { id: `c${n}`, type: networkType } : {}),
                        // Every address answer item names its address (one without is refused, in every language).
                        ...(entry.operationId === 'listAddressesByVaultAccountId' ? { address: `address-${n}` } : {}),
                    });
                    const pages = [
                        { limit: 2, hasMore: true, startingAfter: 'c2', items: [itemOf(1), itemOf(2)] },
                        { limit: 2, hasMore: false, items: [itemOf(3)] },
                    ];
                    env.gw.route('GET', pattern(doc), () => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data: pages.shift() } }));
                    const seen = [];
                    for await (const item of call(env.client, doc, params)) {
                        seen.push(item[entry.cursorField]);
                    }
                    assert.deepEqual(seen, ['c1', 'c2', 'c3']);
                    const requests = env.gw.requests.filter(request => request.path === expectedTarget(doc, params).path);
                    assert.equal(requests.length, 2);
                    const first = Object.fromEntries(new URLSearchParams(requests[0].query));
                    const second = Object.fromEntries(new URLSearchParams(requests[1].query));
                    assert.equal(first.startingAfter, undefined);
                    assert.deepEqual(second, { ...first, limit: '2', startingAfter: 'c2' });
                } finally {
                    await env.close();
                }
            });
        }
    });
}

describe('lists that are not paged automatically', () => {
    it('getAddressBalance: the cursor field is not documented, so iterating refuses after the first page', async () => {
        const env = await setup();
        try {
            const doc = DOCUMENTED.get('getAddressBalance');
            env.gw.route('GET', pattern(doc), () => ({ status: 200, body: doc.success.body }));
            const page = await env.client.assetsAddresses.getAddressBalance(doc.params);
            assert.deepEqual(page.items, doc.success.body.data.items);
            await assert.rejects(async () => {
                // eslint-disable-next-line no-unused-vars
                for await (const item of env.client.assetsAddresses.getAddressBalance(doc.params)) {
                    // never reached
                }
            }, error => error instanceof sdk.PaginationError && error.code === 'cursor_unknown');
            assert.equal(env.gw.requests.length, 2);
        } finally {
            await env.close();
        }
    });

    it('listApiKeySigningKeys: takes no params, sends no query, and its one page is the whole list', async () => {
        const env = await setup({ key: 'p256' });
        try {
            const items = [];
            for await (const item of env.client.apiKeys.listApiKeySigningKeys()) {
                items.push(item);
            }
            assert.deepEqual(items.map(item => [item.fingerprint, item.algorithm, item.status]), [[env.client.signerFingerprint, 'p-256', 'active']]);
            assert.equal(env.gw.requests.length, 1);
            assert.equal(env.gw.requests[0].query, '');
            const page = await env.client.apiKeys.listApiKeySigningKeys({}, { context: 'mine' });
            assert.equal(page.hasMore, false);
            assert.equal(await page.nextPage(), null);
            assert.equal(env.gw.requests[1].query, 'context=mine');
            await assert.rejects(env.client.apiKeys.listApiKeySigningKeys({ limit: 2 }), error => error instanceof sdk.ParameterError && error.code === 'unknown_param');
        } finally {
            await env.close();
        }
    });
});

describe('addresses through the methods: checked against the pinned vault xpub', () => {
    const ACCOUNT = '6630f1c2a9e4b5d7c8e9f0e2';
    const c = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.addressFormatWire === 'p2wpkh');
    const other = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.address !== c.address && item.xpub !== c.xpub);
    const withPath = (fields = {}) => ({
        address: c.address, label: 'deposit', accountIndex: c.accountIndex, isChange: c.change, addressIndex: c.addressIndex, addressFormat: c.addressFormatWire, ...fields,
    });
    const answer = data => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data } });
    async function withVault(fn) {
        const env = await setup();
        env.gw.vaults.main = [{ id: VAULT, type: 'main', name: 'Vault', mpcKeys: [{ algorithm: 'ECDSA', xpub: c.xpub }] }];
        try {
            await fn(env);
        } finally {
            await env.close();
        }
    }

    it('listVaults pins the vault keys; a changed xpub is the alarm', () => withVault(async env => {
        const page = await env.client.vaults.listVaults({ networkType: 'main' });
        assert.deepEqual(page.meta.vaultKeys, [{ vaultId: VAULT, status: 'verified', outcome: 'pinned' }]);
        env.gw.vaults.main = [{ id: VAULT, type: 'main', name: 'Vault', mpcKeys: [{ algorithm: 'ECDSA', xpub: other.xpub }] }];
        await assert.rejects(env.client.vaults.listVaults({ networkType: 'main' }), error => error instanceof sdk.VaultKeyChangedError);
        await assert.rejects(async () => {
            // eslint-disable-next-line no-unused-vars
            for await (const vault of env.client.vaults.listVaults({ networkType: 'main' })) {
                // never reached
            }
        }, sdk.VaultKeyChangedError);
    }));

    it('generateDepositAddress: verified on first sight of the vault; a swapped address refused', () => withVault(async env => {
        let item = withPath();
        env.gw.route('POST', /\/addresses$/, () => ({ ...answer({ item }), status: 201 }));
        const params = { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'deposit', vaultAccountId: ACCOUNT };
        const result = await env.client.assetsAddresses.generateDepositAddress(params);
        assert.deepEqual(result.meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'verified' }]);
        assert.deepEqual(result.item, item);
        item = withPath({ address: other.address });
        await assert.rejects(env.client.assetsAddresses.generateDepositAddress(params), error => error instanceof sdk.AddressVerificationError && error.code === 'mismatch');
    }));

    it('listAddressesByVaultAccountId: every page checked as it is iterated; one swapped address refuses the page', () => withVault(async env => {
        const items = ADDRESSES.cases.filter(item => item.xpub === c.xpub && item.blockchain === 'bitcoin' && item.network === 'mainnet').slice(0, 3)
            .map((item, index) => ({
                addressId: `a${index}`, address: item.address, blockchain: 'bitcoin', accountIndex: item.accountIndex, isChange: item.change,
                addressIndex: String(item.addressIndex), addressFormat: item.addressFormatWire,
            }));
        assert.equal(items.length, 3);
        let swap = false;
        env.gw.route('GET', /\/list-addresses$/, request => {
            const after = new URLSearchParams(request.query).get('startingAfter');
            const start = after ? items.findIndex(item => item.addressId === after) + 1 : 0;
            const page = items.slice(start, start + 2).map((item, index) => (swap && start + index === 2 ? { ...item, address: other.address } : item));

            return answer({ limit: 2, hasMore: start + 2 < items.length, items: page });
        });
        const params = { vaultId: VAULT, vaultAccountId: ACCOUNT, limit: 2 };
        const checks = [];
        const first = await env.client.assetsAddresses.listAddressesByVaultAccountId(params);
        for (let page = first; page; page = await page.nextPage()) {
            checks.push(...page.meta.addressChecks.map(check => check.status));
        }
        assert.deepEqual(checks, ['verified', 'verified', 'verified']);
        const seen = [];
        for await (const item of env.client.assetsAddresses.listAddressesByVaultAccountId(params)) {
            seen.push(item.address);
        }
        assert.deepEqual(seen, items.map(item => item.address));

        swap = true;
        const iterated = [];
        await assert.rejects(async () => {
            for await (const item of env.client.assetsAddresses.listAddressesByVaultAccountId(params)) {
                iterated.push(item.address);
            }
        }, error => error instanceof sdk.AddressVerificationError && error.code === 'mismatch');
        // The first page passed; nothing of the refused page reached the loop.
        assert.deepEqual(iterated, items.slice(0, 2).map(item => item.address));
    }));

    it('addAssetToVaultAccount: the answer must name the address sent, and it is checked', () => withVault(async env => {
        let item = { address: other.address, assetUnit: 'BTC' };
        env.gw.route('PUT', /\/add-asset$/, () => answer({ item }));
        const add = () => env.client.vaultAccounts.addAssetToVaultAccount({ vaultId: VAULT, vaultAccountId: ACCOUNT, assetId: 'btc', address: c.address });
        await assert.rejects(add(), error => error instanceof sdk.AddressVerificationError && error.code === 'mismatch');
        item = withPath({ assetUnit: 'BTC', blockchain: 'bitcoin', network: 'mainnet', label: undefined });
        assert.deepEqual((await add()).meta.addressChecks, [{ vaultId: VAULT, address: c.address, status: 'verified' }]);
    }));
});

describe('the README', () => {
    it('has one example per method, under its group, with its endpoint, each a call the params check accepts', () => {
        const { validateParams } = require('../src/params');
        const readme = readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
        // Placeholders for the variables the examples use.
        const names = ['vaultId', 'vaultAccountId', 'assetId', 'address', 'fromAddress', 'toAddress', 'payer', 'utxoId', 'classicAddress', 'xAddress', 'transactionId', 'transactionRequestId'];
        const seen = new Set();
        let group = null;
        for (const line of readme.split('\n')) {
            const heading = /^### ([A-Za-z]+)$/.exec(line);
            if (heading) {
                group = heading[1];
                continue;
            }
            const row = /^\| `([A-Za-z]+)` \| `(GET|POST|PUT) ([^`]+)`[^|]*\| `(.+)` \|$/.exec(line);
            if (!row) {
                continue;
            }
            const [, method, httpMethod, endpoint, example] = row;
            const entry = sdk.operationById(method);
            assert.ok(entry, method);
            assert.equal(DOCUMENTED.get(method).namespace, group, `${method} is listed under ${group}`);
            assert.equal(`${httpMethod} ${endpoint}`, `${entry.method} ${entry.path}`);
            const start = example.indexOf(`vaultody.${group}.${method}(`);
            assert.notEqual(start, -1, `${method}'s example calls vaultody.${group}.${method}`);
            let depth = 0;
            let end = start + `vaultody.${group}.${method}`.length;
            do {
                depth += example[end] === '(' ? 1 : example[end] === ')' ? -1 : 0;
                end += 1;
            } while (depth > 0);
            const args = example.slice(start + `vaultody.${group}.${method}(`.length, end - 1);
            // eslint-disable-next-line no-new-func
            const [params = {}] = new Function(...names, `return [${args}];`)(...names.map(name => `${name}-value`));
            validateParams(entry, params);
            assert.ok(!seen.has(method), `${method} twice`);
            seen.add(method);
        }
        assert.equal(seen.size, sdk.OPERATIONS.length);
    });
});
