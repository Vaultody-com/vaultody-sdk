'use strict';

// test-vectors/path-encoding-v1.json: path and query parameters → the exact request target.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { buildRequestTarget } = require('../src/requestTarget');
const { ParameterError } = require('../src/errors');
const { load } = require('./vectors');

const VECTORS = load('path-encoding-v1.json');

describe('test-vectors/path-encoding-v1.json', () => {
    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            const build = () => buildRequestTarget(vector.template, vector.pathParams, vector.query);
            if (vector.expected.error) {
                assert.throws(build, error => error instanceof ParameterError && error.code === vector.expected.error);

                return;
            }
            const target = build();
            assert.equal(target, vector.expected.target);
            // What fetch puts on the request line is exactly this target.
            const url = new URL(`https://rest.vaultody.com${target}`);
            assert.equal(url.pathname + url.search, target);
        });
    }

    it('refuses text with no UTF-8 form (a lone surrogate), in the path and in the query', () => {
        assert.throws(() => buildRequestTarget('/vaults/{vaultId}/utxos', { vaultId: '\ud800' }), { code: 'invalid_path_param' });
        assert.throws(() => buildRequestTarget('/supported-assets', {}, [['assetUnit', 'a\udc00']]), { code: 'invalid_query_param' });
    });
});
