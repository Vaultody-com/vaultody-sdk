'use strict';

// Answers, pages and request targets through the pipeline:
//  - test-vectors/envelope-errors-v1.json: the mock gateway answers each case's status, headers and body
//    (signed); the client returns the item or page, or throws the typed error with every field (after the
//    retries a 429 or 5xx gets on a read);
//  - test-vectors/pagination-v1.json: the mock serves each case's pages for its operation and records what it
//    was asked; the client's paging must ask exactly that and yield exactly the items, and stop the same way;
//  - test-vectors/path-encoding-v1.json: the request line the mock receives is the vector's target, and its
//    signature check passes on it (the signed path and query are the ones on the wire).

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const errors = require('../src');
const { setup } = require('./helpers');
const { load } = require('./vectors');
const internal = require('../src/internal');

const ENVELOPES = load('envelope-errors-v1.json');
const PAGINATION = load('pagination-v1.json');
const PATHS = load('path-encoding-v1.json');
const TX = '6630f1c2a9e4b5d7c8e9f0c4';

describe('test-vectors/envelope-errors-v1.json through the pipeline', () => {
    for (const vector of ENVELOPES.cases) {
        it(vector.name, async () => {
            const env = await setup();
            try {
                env.gw.route('GET', /^\/transaction-requests\//, () => ({ status: vector.status, headers: vector.headers, body: vector.body }));
                const { expected } = vector;
                let result;
                let error;
                try {
                    result = await internal.request(env.client, 'getTransactionRequestDetails', { transactionRequestId: TX });
                } catch (e) {
                    error = e;
                }
                if (expected.kind === 'error') {
                    assert.ok(error instanceof errors[expected.class], `${error && error.name} is not ${expected.class}`);
                    assert.equal(error.name, expected.class);
                    assert.equal(error.status, vector.status);
                    for (const field of ['code', 'message', 'requestId', 'apiVersion', 'replayed', 'retryable']) {
                        if (field === 'message' && expected.message === null) {
                            continue;
                        }
                        assert.deepEqual(error[field], expected[field], field);
                    }
                    if ('details' in expected) {
                        assert.deepEqual(error.details, expected.details);
                    }
                    assert.equal(error.signature, 'verified');
                } else {
                    assert.equal(error, undefined, String(error));
                    const meta = result.meta;
                    for (const field of ['apiVersion', 'requestId', 'context', 'replayed']) {
                        assert.deepEqual(meta[field], expected[field], field);
                    }
                    if (expected.kind === 'item') {
                        assert.equal(typeof result.item, 'object');
                    } else {
                        assert.ok(result instanceof errors.Page);
                        for (const field of ['limit', 'hasMore', 'startingAfter', 'offset', 'total']) {
                            if (field in expected) {
                                assert.deepEqual(result[field], expected[field], field);
                            }
                        }
                        assert.equal(result.items.length, expected.count);
                        assert.equal(expected.paging === 'offset' ? 'offset' in result : 'startingAfter' in result, true);
                    }
                }
            } finally {
                await env.close();
            }
        });
    }
});

const PATH_PARAMS = { vaultId: '6630f1c2a9e4b5d7c8e9f0a1', vaultAccountId: '6630f1c2a9e4b5d7c8e9f0e2', networkType: 'main', address: 'addr' };

// The vectors' offset cases are written for listApiKeySigningKeys, which takes no limit or offset (its list fits
// in one page, test/methods.test.js): they run here on an offset-paged stand-in at its path that takes both.
const OFFSET_STAND_IN = Object.freeze({
    operationId: 'offsetPagingVector',
    method: 'GET',
    path: '/api-keys/current/signing-keys',
    retry: 'read',
    paging: 'offset',
    maxLimit: 2,
    params: [{ name: 'limit', in: 'query', required: false }, { name: 'offset', in: 'query', required: false }],
});

/** Runs one pagination case against `operationId` (the vector's own unless given). */
async function page(vector, operationId = vector.operationId) {
    const operation = vector.paging === 'offset' ? OFFSET_STAND_IN : errors.operationById(operationId);
    const env = await setup();
    try {
        const asked = [];
        let next = 0;
        env.gw.route('GET', /./, request => {
            const query = new URLSearchParams(request.query);
            asked.push(vector.paging === 'offset'
                ? { offset: Number(query.get('offset')), limit: Number(query.get('limit')) }
                : { startingAfter: query.get('startingAfter'), limit: Number(query.get('limit')) });
            const data = vector.pages[next].response;
            next += 1;
            // listVaults items are vaults: they say their type, as the API's always do; address items name their
            // address (an item without one is refused, in every language).
            const items = operationId === 'listVaults' ? data.items.map(item => ({ ...item, type: 'main' }))
                : operationId === 'listAddressesByVaultAccountId' ? data.items.map((item, i) => ({ address: `address-${i}`, ...item }))
                    : data.items;

            return { status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data: { ...data, items } } };
        });
        const params = {};
        for (const param of operation.params.filter(item => item.in === 'path')) {
            params[param.name] = PATH_PARAMS[param.name];
        }
        const pager = internal.paginate(env.client, vector.paging === 'offset' ? operation : operationId, params, {
            ...(vector.limit === null || vector.limit === undefined ? {} : { limit: vector.limit }),
            ...(vector.maxItems === undefined ? {} : { maxItems: vector.maxItems }),
        });
        const field = vector.paging === 'offset' ? vector.itemField : vector.cursorField;
        const items = [];
        let error;
        try {
            for await (const item of pager) {
                items.push(item[field] === undefined ? null : item[field]);
            }
        } catch (e) {
            error = e;
        }

        return { asked, items, error, stop: pager.stop };
    } finally {
        await env.close();
    }
}

describe('test-vectors/pagination-v1.json through the pipeline', () => {
    for (const vector of PAGINATION.cases) {
        const fn = async operationId => {
            const { asked, items, error, stop } = await page(vector, operationId);
            assert.deepEqual(asked, vector.pages.map(item => item.request));
            assert.deepEqual(items, vector.expected.items);
            if (vector.expected.error) {
                assert.ok(error instanceof errors.PaginationError && error.code === vector.expected.error, String(error));
            } else {
                assert.equal(error, undefined, String(error));
                assert.equal(stop, vector.expected.stop);
            }
        };
        if (vector.name === 'cursor_field_missing' && vector.operationId === 'listVaults') {
            it(`${vector.name}: a listVaults page with a vault without id is refused whole (it is a key source)`, async () => {
                const { error, items } = await page(vector);
                // Refused as an answer of the API that is wrong (ApiError, no code), as in Python and PHP.
                assert.ok(error instanceof errors.ApiError && error.code === null && error.status === 200, String(error));
                assert.deepEqual(items, []);
            });
            it(`${vector.name}: on listTransactionsByVault, the same cursor field "id"`, () => fn('listTransactionsByVault'));
        } else {
            it(vector.name, () => fn());
        }
    }

    it('getAddressBalance has no documented cursor field: not paged automatically', async () => {
        const env = await setup();
        try {
            assert.throws(() => internal.paginate(env.client, 'getAddressBalance', { vaultId: PATH_PARAMS.vaultId, address: 'a' }), error => error instanceof errors.PaginationError && error.code === 'cursor_unknown');
        } finally {
            await env.close();
        }
    });

    it('page.nextPage() and page.autoPaging() continue from a page already fetched', async () => {
        const vector = PAGINATION.cases.find(item => item.name === 'listTransactionsByVault_three_pages');
        const env = await setup();
        try {
            let next = 0;
            env.gw.route('GET', /\/transactions$/, () => {
                const data = vector.pages[next].response;
                next += 1;

                return { status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data } };
            });
            const first = await internal.request(env.client, 'listTransactionsByVault', { vaultId: PATH_PARAMS.vaultId, limit: 2 });
            const ids = [];
            for await (const item of first.autoPaging()) {
                ids.push(item.id);
            }
            assert.deepEqual(ids, vector.expected.items);
            assert.equal(env.gw.requests.length, 3);
        } finally {
            await env.close();
        }
    });
});

describe('test-vectors/path-encoding-v1.json through the pipeline', () => {
    for (const vector of PATHS.cases) {
        it(vector.name, async () => {
            const env = await setup();
            try {
                env.gw.route('GET', /./, () => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item: {} } } }));
                const names = [...vector.template.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map(match => match[1]);
                const operation = {
                    operationId: 'pathEncodingVector',
                    method: 'GET',
                    path: vector.template,
                    retry: 'read',
                    params: [...names.map(name => ({ name, in: 'path', required: true })), ...vector.query.map(([name]) => ({ name, in: 'query', required: false }))],
                };
                const params = { ...vector.pathParams };
                for (const [name, value] of vector.query) {
                    params[name] = value === null ? undefined : value;
                }
                const run = internal.request(env.client, operation, params);
                if (vector.expected.error) {
                    await assert.rejects(run, error => error instanceof errors.ParameterError && error.code === vector.expected.error);
                    assert.equal(env.gw.requests.length, 0);
                } else {
                    await run;
                    const [received] = env.gw.requests;
                    assert.equal(received.query === '' ? received.path : `${received.path}?${received.query}`, vector.expected.target);
                }
            } finally {
                await env.close();
            }
        });
    }

    it('a lone UTF-16 surrogate has no UTF-8 form: refused', async () => {
        const env = await setup();
        try {
            await assert.rejects(internal.request(env.client, 'getTransactionRequestDetails', { transactionRequestId: 'a\ud800' }), error => error instanceof errors.ParameterError && error.code === 'invalid_path_param');
        } finally {
            await env.close();
        }
    });
});
