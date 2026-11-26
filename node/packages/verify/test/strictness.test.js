'use strict';

// Strict by default: an unsigned response is an error. A caller can opt out only for responses that carry
// no signature at all (for example while signing is being rolled out); every other failure, including a
// partly stripped signature, still throws.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { verifyResponse } = require('../src/response');
const {
    VECTORS, SIGN_HEADERS, caseNamed, exchangeOf, optionsOf, verdictOf, withoutSignHeaders,
} = require('./helpers');

const relaxed = vector => optionsOf(vector, { requireResponseSignature: false });

describe('requireResponseSignature', () => {
    const unsigned = caseNamed('missing_all');

    it('is on by default: no signature headers throws missing', () => {
        assert.deepEqual(verdictOf(() => verifyResponse(exchangeOf(unsigned), optionsOf(unsigned))), { valid: false, reason: 'missing' });
        assert.deepEqual(verdictOf(() => verifyResponse(exchangeOf(unsigned), optionsOf(unsigned, { requireResponseSignature: true }))), { valid: false, reason: 'missing' });
    });

    it('when false, returns { verified: false, reason: "missing" } for a response with no signature headers', () => {
        assert.deepEqual(verifyResponse(exchangeOf(unsigned), relaxed(unsigned)), { verified: false, reason: 'missing' });

        const vector = caseNamed('valid_current_root');
        const empty = Object.fromEntries(SIGN_HEADERS.map(name => [name, '']));
        for (const headers of [withoutSignHeaders(vector.verify.response.headers), empty, undefined, null, new Headers()]) {
            const exchange = exchangeOf(vector);
            exchange.response.headers = headers;
            assert.deepEqual(verifyResponse(exchange, relaxed(vector)), { verified: false, reason: 'missing' });
        }
    });

    it('when false, still throws when only some signature headers are missing', () => {
        for (const name of ['missing_sign', 'missing_timestamp', 'missing_version', 'missing_cert', 'empty_sign_header']) {
            const vector = caseNamed(name);
            assert.deepEqual(verdictOf(() => verifyResponse(exchangeOf(vector), relaxed(vector))), { valid: false, reason: 'missing' }, name);
        }
    });

    it('when false, changes no other vector verdict', () => {
        for (const vector of VECTORS.cases.filter(candidate => candidate.name !== 'missing_all')) {
            assert.deepEqual(verdictOf(() => verifyResponse(exchangeOf(vector), relaxed(vector))), vector.expected, vector.name);
        }
    });
});
