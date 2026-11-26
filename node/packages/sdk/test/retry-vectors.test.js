'use strict';

// test-vectors/retry-v1.json: one finished attempt → retry (re-signed or resent), return, fail or outcome unknown.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { RETRY, decideRetry } = require('../src/retry');
const { load } = require('./vectors');

const VECTORS = load('retry-v1.json');

describe('test-vectors/retry-v1.json', () => {
    it('uses the constants of the vectors', () => {
        assert.deepEqual({ ...RETRY }, VECTORS.constants);
    });

    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            assert.deepEqual(decideRetry(vector.input), vector.expected);
        });
    }
});
