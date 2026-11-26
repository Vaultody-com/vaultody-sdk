'use strict';

// test-vectors/pagination-v1.json: sequences of pages → the requests made, the items yielded, why it stopped.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { paginate } = require('../src/pagination');
const { PaginationError } = require('../src/errors');
const { load } = require('./vectors');

const VECTORS = load('pagination-v1.json');

describe('test-vectors/pagination-v1.json', () => {
    for (const vector of VECTORS.cases) {
        it(vector.name, async () => {
            const requests = [];
            const fetchPage = async request => {
                const page = vector.pages[requests.length];
                requests.push(request);
                assert.ok(page, `an extra request: ${JSON.stringify(request)}`);
                assert.deepEqual(request, page.request);

                return page.response;
            };
            const field = vector.paging === 'offset' ? vector.itemField : vector.cursorField;
            const iterator = paginate({
                paging: vector.paging, cursorField: vector.cursorField, limit: vector.limit, maxLimit: vector.maxLimit, maxItems: vector.maxItems,
            }, fetchPage);

            const items = [];
            let stop;
            let error;
            try {
                for (;;) {
                    const next = await iterator.next();
                    if (next.done) {
                        stop = next.value;
                        break;
                    }
                    items.push(next.value[field] === undefined ? null : next.value[field]);
                }
            } catch (e) {
                if (!(e instanceof PaginationError)) {
                    throw e;
                }
                error = e.code;
            }

            assert.deepEqual(items, vector.expected.items);
            assert.equal(requests.length, vector.pages.length, 'every page and no more');
            if (vector.expected.error) {
                assert.equal(error, vector.expected.error);
            } else {
                assert.equal(error, undefined);
                assert.equal(stop, vector.expected.stop);
            }
        });
    }

    it('works with for await', async () => {
        const vector = VECTORS.cases.find(candidate => candidate.name === 'listVaults_three_pages');
        let index = 0;
        const seen = [];
        for await (const item of paginate({ cursorField: 'id', limit: 2, maxLimit: 50 }, async () => vector.pages[index++].response)) {
            seen.push(item.id);
        }
        assert.deepEqual(seen, vector.expected.items);
    });
});
