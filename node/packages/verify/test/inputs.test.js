'use strict';

// How verifyResponse reads its arguments: body types, the request-line target, the clock and options,
// and the package entry points.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { verifyResponse } = require('../src/response');
const { ResponseSignatureError } = require('../src/errors');
const {
    caseNamed, exchangeOf, optionsOf, verdictOf, signFresh, FRESH_OPTIONS,
} = require('./helpers');

const isReason = reason => error => error instanceof ResponseSignatureError && error.reason === reason;

describe('bodies', () => {
    const vector = caseNamed('valid_utf8_body');
    const base = exchangeOf(vector);
    // A view into the middle of a larger buffer must contribute only its own bytes.
    const viewInside = bytes => {
        const padded = Buffer.concat([Buffer.from('xx'), bytes, Buffer.from('yy')]);

        return new Uint8Array(padded.buffer, padded.byteOffset + 2, bytes.length);
    };
    const forms = bytes => [
        bytes,
        new Uint8Array(bytes),
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length),
        bytes.toString('utf8'),
        viewInside(bytes),
    ];

    it('takes request and response bodies as Buffer, Uint8Array, ArrayBuffer or a UTF-8 string', () => {
        assert.match(base.response.body.toString('utf8'), /[^\x00-\x7f]/, 'the vector should have a non-ASCII body');
        for (const requestBody of forms(base.request.body)) {
            for (const responseBody of forms(base.response.body)) {
                const exchange = { request: { ...base.request, body: requestBody }, response: { ...base.response, body: responseBody } };
                assert.equal(verifyResponse(exchange, optionsOf(vector)).verified, true);
            }
        }
    });

    it('treats a missing body as empty', () => {
        const empty = caseNamed('valid_head_empty_body');
        for (const body of [undefined, null, '', Buffer.alloc(0)]) {
            const exchange = exchangeOf(empty);
            exchange.request.body = body;
            exchange.response.body = body;
            assert.equal(verifyResponse(exchange, optionsOf(empty)).verified, true);
        }
    });

    it('refuses a parsed JSON body, telling the caller to verify the raw bytes first', () => {
        const json = caseNamed('valid_current_root');
        const exchange = exchangeOf(json);
        const parsed = JSON.parse(exchange.response.body.toString('utf8'));
        assert.throws(() => verifyResponse({ ...exchange, response: { ...exchange.response, body: parsed } }, optionsOf(json)),
            error => error instanceof TypeError && /before parsing/.test(error.message));
        assert.throws(() => verifyResponse({ ...exchange, request: { ...exchange.request, body: { amount: 1 } } }, optionsOf(json)), TypeError);
    });

    it('rejects a response body that differs by one byte', () => {
        const body = Buffer.from(base.response.body);
        body[body.length - 1] ^= 1;
        assert.throws(() => verifyResponse({ ...base, response: { ...base.response, body } }, optionsOf(vector)), isReason('invalid'));
    });
});

describe('the request url', () => {
    const fresh = (signedUrl, verifiedUrl) => verifyResponse({
        request: { method: 'GET', url: verifiedUrl },
        response: { status: 200, headers: signFresh({ method: 'GET', url: signedUrl }), body: '' },
    }, FRESH_OPTIONS);

    it('splits path and query at the first "?" and keeps the rest of the query as is', () => {
        assert.equal(fresh('/vaults?a=1?b=2&c=%2f', '/vaults?a=1?b=2&c=%2f').verified, true);
        assert.throws(() => fresh('/vaults?a=1?b=2&c=%2f', '/vaults?a=1%3Fb=2&c=%2f'), isReason('invalid'));
    });

    it('does not normalise percent-encoding', () => {
        assert.throws(() => fresh('/vaults/a%2fb', '/vaults/a%2Fb'), isReason('invalid'));
        assert.throws(() => fresh('/vaults/a%20b', '/vaults/a b'), isReason('invalid'));
    });

    it('treats a trailing "?" as an empty query, as the gateway does', () => {
        assert.equal(fresh('/vaults', '/vaults?').verified, true);
    });

    it('rejects non-ASCII text, which can never be on the request line', () => {
        assert.throws(() => fresh('/vaults/%C3%BC', '/vaults/ü'), isReason('invalid'));
    });

    it('refuses a full URL or anything not starting with "/"', () => {
        for (const url of ['https://rest.vaultody.com/vaults', 'vaults', '', undefined, new URL('https://rest.vaultody.com/vaults')]) {
            assert.throws(() => fresh('/vaults', url), TypeError, String(url));
        }
    });
});

describe('request fields', () => {
    it('treats an absent x-api-sign as empty', () => {
        const vector = caseNamed('valid_unauthenticated_error');
        assert.equal(vector.verify.request.apiSign, '');
        for (const apiSign of [undefined, null, '']) {
            const exchange = exchangeOf(vector);
            exchange.request.apiSign = apiSign;
            assert.equal(verifyResponse(exchange, optionsOf(vector)).verified, true);
        }
    });

    it('treats an absent x-api-keypair-sign as empty', () => {
        const vector = caseNamed('valid_current_root');
        assert.equal(vector.verify.request.keypairSign, '');
        for (const keypairSign of [undefined, null, '']) {
            const exchange = exchangeOf(vector);
            exchange.request.keypairSign = keypairSign;
            assert.equal(verifyResponse(exchange, optionsOf(vector)).verified, true);
        }
    });

    it('binds x-api-keypair-sign: a response for a request with one does not verify without it', () => {
        const vector = caseNamed('valid_with_keypair_sign');
        assert.equal(verifyResponse(exchangeOf(vector), optionsOf(vector)).verified, true);
        for (const keypairSign of [undefined, '', vector.verify.request.apiSign]) {
            const exchange = exchangeOf(vector);
            exchange.request.keypairSign = keypairSign;
            assert.throws(() => verifyResponse(exchange, optionsOf(vector)), isReason('invalid'));
        }
    });

    it('refuses an x-api-keypair-sign that is not printable ASCII', () => {
        const vector = caseNamed('valid_with_keypair_sign');
        for (const keypairSign of [`${vector.verify.request.keypairSign}\n`, 'tab\there', 'ü']) {
            const exchange = exchangeOf(vector);
            exchange.request.keypairSign = keypairSign;
            assert.throws(() => verifyResponse(exchange, optionsOf(vector)), isReason('invalid'));
        }
    });

    it('takes the method exactly as sent', () => {
        const vector = caseNamed('valid_current_root');
        const exchange = exchangeOf(vector);
        exchange.request.method = 'post';
        assert.throws(() => verifyResponse(exchange, optionsOf(vector)), isReason('invalid'));
    });

    it('refuses arguments of the wrong type', () => {
        const vector = caseNamed('valid_current_root');
        const exchange = exchangeOf(vector);
        const broken = [
            undefined,
            {},
            { ...exchange, request: { ...exchange.request, method: undefined } },
            { ...exchange, request: { ...exchange.request, apiSign: 42 } },
            { ...exchange, request: { ...exchange.request, keypairSign: 42 } },
            { ...exchange, response: { ...exchange.response, status: '201' } },
            { ...exchange, response: undefined },
        ];
        for (const value of broken) {
            assert.throws(() => verifyResponse(value, optionsOf(vector)), TypeError);
        }
    });
});

describe('options', () => {
    const vector = caseNamed('valid_current_root');

    it('takes now as Unix seconds or a Date, and refuses milliseconds', () => {
        const { now } = vector.verify;
        assert.equal(verifyResponse(exchangeOf(vector), optionsOf(vector, { now: new Date(now * 1000) })).verified, true);
        assert.throws(() => verifyResponse(exchangeOf(vector), optionsOf(vector, { now: now * 1000 })), /milliseconds/);
        assert.throws(() => verifyResponse(exchangeOf(vector), optionsOf(vector, { now: String(now) })), TypeError);
        assert.throws(() => verifyResponse(exchangeOf(vector), optionsOf(vector, { now: new Date(NaN) })), TypeError);
    });

    it('uses the real clock when now is not given', () => {
        const { now, ...rest } = optionsOf(vector);
        assert.ok(now);
        const withDefault = verdictOf(() => verifyResponse(exchangeOf(vector), rest));
        const withRealClock = verdictOf(() => verifyResponse(exchangeOf(vector), { ...rest, now: Math.floor(Date.now() / 1000) }));
        assert.deepEqual(withDefault, withRealClock);
    });

    it('applies maxClockSkewSeconds', () => {
        const late = caseNamed('now_beyond_skew');
        const overrun = late.verify.now - late.signed.certificate.notAfter;
        assert.throws(() => verifyResponse(exchangeOf(late), optionsOf(late)), isReason('expired'));
        assert.equal(verifyResponse(exchangeOf(late), optionsOf(late, { maxClockSkewSeconds: overrun })).verified, true);
        assert.throws(() => verifyResponse(exchangeOf(late), optionsOf(late, { maxClockSkewSeconds: overrun - 1 })), isReason('expired'));
    });

    it('refuses option values of the wrong type', () => {
        for (const bad of [{ maxClockSkewSeconds: -1 }, { maxClockSkewSeconds: '300' }, { requireResponseSignature: 'false' }, { requireResponseSignature: 0 }]) {
            assert.throws(() => verifyResponse(exchangeOf(vector), optionsOf(vector, bad)), TypeError, JSON.stringify(bad));
        }
    });
});

describe('package entry points', () => {
    it('exports the response API from the package root and from ./response', () => {
        const root = require('@vaultody/verify');
        const response = require('@vaultody/verify/response');
        for (const name of ['verifyResponse', 'verifyFetchResponse', 'ResponseSignatureError', 'ConfigurationError', 'REASONS']) {
            assert.ok(root[name], name);
            assert.equal(root[name], response[name], name);
        }
        assert.deepEqual(Object.values(root.REASONS).sort(), ['expired', 'invalid', 'missing', 'request_unbound', 'unknown_root', 'unsupported_version']);
    });

    it('does not expose internal files', () => {
        assert.throws(() => require('@vaultody/verify/src/roots.js'), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
    });

    it('is publishable and has no runtime dependencies', () => {
        const manifest = require('@vaultody/verify/package.json');
        assert.equal(manifest.private, undefined);
        assert.equal(manifest.dependencies, undefined);
        assert.equal(manifest.engines.node, '>=22');
    });

    it('errors carry the reason and a readable name', () => {
        const vector = caseNamed('tampered_response_body');
        try {
            verifyResponse(exchangeOf(vector), optionsOf(vector));
            assert.fail('expected a rejection');
        } catch (error) {
            assert.ok(error instanceof ResponseSignatureError);
            assert.ok(error instanceof Error);
            assert.equal(error.name, 'ResponseSignatureError');
            assert.equal(error.reason, 'invalid');
            assert.match(error.message, /\(invalid\)/);
        }
    });
});
