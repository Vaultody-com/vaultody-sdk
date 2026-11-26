'use strict';

// Response headers reach the helper in whatever shape the HTTP client uses: Node's http gives a plain
// object with lowercase names, fetch gives a Headers object, other code builds objects or Maps by hand.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { verifyResponse } = require('../src/response');
const { caseNamed, exchangeOf, optionsOf, verdictOf } = require('./helpers');

const vector = caseNamed('valid_current_root');
const signed = vector.verify.response.headers;
const run = headers => {
    const exchange = exchangeOf(vector);
    exchange.response.headers = headers;

    return verdictOf(() => verifyResponse(exchange, optionsOf(vector)));
};

const renamed = rename => Object.fromEntries(Object.entries(signed).map(([name, value]) => [rename(name), value]));
const titleCase = name => name.replace(/(^|-)([a-z])/g, (all, dash, letter) => dash + letter.toUpperCase());

describe('response header shapes', () => {
    it('accepts a plain object with lowercase names', () => {
        assert.deepEqual(run({ ...signed }), { valid: true });
    });

    it('accepts a plain object with upper-case or mixed-case names', () => {
        assert.deepEqual(run(renamed(name => name.toUpperCase())), { valid: true });
        assert.deepEqual(run(renamed(titleCase)), { valid: true });
    });

    it('accepts a fetch Headers object', () => {
        assert.deepEqual(run(new Headers(renamed(titleCase))), { valid: true });
    });

    it('accepts a Map, with names in any case', () => {
        assert.deepEqual(run(new Map(Object.entries(renamed(titleCase)))), { valid: true });
    });

    it('accepts a single value wrapped in an array', () => {
        const wrapped = Object.fromEntries(Object.entries(signed).map(([name, value]) => [name, [value]]));
        assert.deepEqual(run(wrapped), { valid: true });
        assert.deepEqual(run(new Map(Object.entries(wrapped))), { valid: true });
    });

    it('ignores other headers', () => {
        assert.deepEqual(run({ ...signed, 'content-type': 'application/json', 'x-api-response-signature': 'unrelated' }), { valid: true });
    });

    it('refuses a header given twice under names that differ only in case', () => {
        const twice = { ...signed, 'X-Api-Response-Sign': signed['x-api-response-sign'] };
        assert.deepEqual(run(twice), { valid: false, reason: 'invalid' });
        assert.deepEqual(run(new Map(Object.entries(twice))), { valid: false, reason: 'invalid' });
    });

    it('refuses a header with two values', () => {
        const value = signed['x-api-response-cert'];
        assert.deepEqual(run({ ...signed, 'x-api-response-cert': [value, value] }), { valid: false, reason: 'invalid' });

        // fetch joins repeated values into one string, which then isn't a valid header value.
        const headers = new Headers(signed);
        headers.append('x-api-response-cert', value);
        assert.deepEqual(run(headers), { valid: false, reason: 'invalid' });
    });

    it('refuses a header value that is not a string', () => {
        assert.deepEqual(run({ ...signed, 'x-api-response-timestamp': Number(signed['x-api-response-timestamp']) }), { valid: false, reason: 'invalid' });
    });

    it('reports missing headers whatever the container', () => {
        for (const headers of [undefined, null, {}, new Headers(), new Map(), { 'x-api-response-sign': [] }]) {
            assert.deepEqual(run(headers), { valid: false, reason: 'missing' });
        }
    });

    it('treats a header given as null or undefined as absent', () => {
        assert.deepEqual(run({ ...signed, 'x-api-response-sign': null }), { valid: false, reason: 'missing' });
        assert.deepEqual(run({ ...signed, 'x-api-response-sign': undefined }), { valid: false, reason: 'missing' });
    });

    it('refuses headers that are not an object', () => {
        assert.throws(() => run('x-api-response-sign: abc'), TypeError);
    });
});
