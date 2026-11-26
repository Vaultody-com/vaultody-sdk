'use strict';

// verifyFetchResponse against a real fetch() and a local HTTP server, so the request it reconstructs is
// checked against what actually went over the wire, not against what the test thinks fetch sends.

const assert = require('node:assert/strict');
const http = require('node:http');
const { after, before, describe, it } = require('node:test');

const { verifyFetchResponse, verifyResponse } = require('../src/response');
const { ResponseSignatureError } = require('../src/errors');
const {
    VECTORS, caseNamed, urlOf, optionsOf, withoutSignHeaders, signFresh, FRESH_OPTIONS,
} = require('./helpers');

const isReason = reason => error => error instanceof ResponseSignatureError && error.reason === reason;

describe('verifyFetchResponse over a local HTTP server', () => {
    let server;
    let origin;
    // Each test sets how the server answers and reads back what it received.
    let respond;
    let seen;

    before(async () => {
        server = http.createServer((req, res) => {
            const chunks = [];
            req.on('data', chunk => chunks.push(chunk));
            req.on('end', () => {
                const body = Buffer.concat(chunks);
                seen = {
                    method: req.method,
                    url: req.url,
                    body,
                    apiSign: req.headers['x-api-sign'] || '',
                    keypairSign: req.headers['x-api-keypair-sign'] || '',
                };
                const { status, headers, body: responseBody } = respond(seen);
                res.writeHead(status, headers);
                res.end(responseBody);
            });
        });
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        origin = `http://127.0.0.1:${server.address().port}`;
    });

    after(() => {
        server.closeAllConnections();
        server.close();
    });

    const replay = (vector, change = {}) => ({
        status: vector.verify.response.status,
        headers: change.headers || vector.verify.response.headers,
        body: change.body || Buffer.from(vector.verify.response.bodyBase64, 'base64'),
    });

    const fetchInitOf = request => {
        const body = Buffer.from(request.bodyBase64, 'base64');

        return {
            method: request.method,
            headers: {
                ...(request.apiSign ? { 'x-api-sign': request.apiSign } : {}),
                ...(request.keypairSign ? { 'x-api-keypair-sign': request.keypairSign } : {}),
            },
            body: body.length > 0 ? body : undefined,
        };
    };

    describe('replays each valid vector', () => {
        for (const vector of VECTORS.cases.filter(candidate => candidate.expected.valid)) {
            it(vector.name, async () => {
                const { request } = vector.verify;
                respond = () => replay(vector);
                const url = origin + urlOf(request);
                const init = fetchInitOf(request);

                const result = await verifyFetchResponse({ url, ...init }, await fetch(url, init), optionsOf(vector));

                // The server got exactly the request the vector's response was signed for.
                assert.deepEqual(seen, {
                    method: request.method,
                    url: urlOf(request),
                    body: Buffer.from(request.bodyBase64, 'base64'),
                    apiSign: request.apiSign,
                    keypairSign: request.keypairSign,
                });
                assert.equal(result.verified, true);
                assert.equal(result.keyId, vector.signed.certificate.keyId);
                assert.ok(Buffer.isBuffer(result.body));
                assert.deepEqual(result.body, Buffer.from(vector.verify.response.bodyBase64, 'base64'));
            });
        }
    });

    it('takes method, URL, x-api-sign and body from a Request whose clone was sent', async () => {
        const vector = caseNamed('valid_current_root');
        respond = () => replay(vector);
        const request = new Request(origin + urlOf(vector.verify.request), fetchInitOf(vector.verify.request));

        const result = await verifyFetchResponse(request, await fetch(request.clone()), optionsOf(vector));

        assert.equal(result.verified, true);
        assert.equal(JSON.parse(result.body.toString('utf8')).data.item.label, 'deposit-7');
    });

    it('takes x-api-keypair-sign from a Request whose clone was sent', async () => {
        const vector = caseNamed('valid_with_keypair_sign');
        assert.notEqual(vector.verify.request.keypairSign, '');
        respond = () => replay(vector);
        const request = new Request(origin + urlOf(vector.verify.request), fetchInitOf(vector.verify.request));

        const result = await verifyFetchResponse(request, await fetch(request.clone()), optionsOf(vector));

        assert.equal(seen.keypairSign, vector.verify.request.keypairSign);
        assert.equal(result.verified, true);
    });

    it('rejects a response signed for a request whose x-api-keypair-sign was stripped on the way', async () => {
        const vector = caseNamed('keypair_sign_dropped');
        respond = () => replay(vector);
        const url = origin + urlOf(vector.verify.request);
        const init = fetchInitOf(vector.verify.request);

        await assert.rejects(verifyFetchResponse({ url, ...init }, await fetch(url, init), optionsOf(vector)), isReason('invalid'));
    });

    it('refuses a Request whose body was already sent, since it cannot be read back', async () => {
        const vector = caseNamed('valid_current_root');
        respond = () => replay(vector);
        const request = new Request(origin + urlOf(vector.verify.request), fetchInitOf(vector.verify.request));
        const response = await fetch(request);

        await assert.rejects(verifyFetchResponse(request, response, optionsOf(vector)), TypeError);
    });

    it('rejects a body changed on the way', async () => {
        const vector = caseNamed('valid_current_root');
        const original = Buffer.from(vector.verify.response.bodyBase64, 'base64').toString('utf8');
        const swapped = Buffer.from(original.replace('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', 'bc1qattackerattackerattackerattackerattack'), 'utf8');
        assert.notEqual(swapped.toString('utf8'), original);
        respond = () => replay(vector, { body: swapped });
        const url = origin + urlOf(vector.verify.request);
        const init = fetchInitOf(vector.verify.request);

        await assert.rejects(verifyFetchResponse({ url, ...init }, await fetch(url, init), optionsOf(vector)), isReason('invalid'));
    });

    it('rejects a response whose signature headers were stripped, unless the caller is not strict', async () => {
        const vector = caseNamed('valid_current_root');
        respond = () => replay(vector, { headers: withoutSignHeaders(vector.verify.response.headers) });
        const url = origin + urlOf(vector.verify.request);
        const init = fetchInitOf(vector.verify.request);

        await assert.rejects(verifyFetchResponse({ url, ...init }, await fetch(url, init), optionsOf(vector)), isReason('missing'));

        const relaxed = await verifyFetchResponse({ url, ...init }, await fetch(url, init), optionsOf(vector, { requireResponseSignature: false }));
        assert.deepEqual(relaxed, { verified: false, reason: 'missing', body: Buffer.from(vector.verify.response.bodyBase64, 'base64') });
    });

    it('rejects a partly stripped signature even when the caller is not strict', async () => {
        const vector = caseNamed('valid_current_root');
        const { 'x-api-response-sign': dropped, ...rest } = vector.verify.response.headers;
        assert.ok(dropped);
        respond = () => replay(vector, { headers: rest });
        const url = origin + urlOf(vector.verify.request);
        const init = fetchInitOf(vector.verify.request);

        await assert.rejects(
            verifyFetchResponse({ url, ...init }, await fetch(url, init), optionsOf(vector, { requireResponseSignature: false })),
            isReason('missing'),
        );
    });

    describe('derives path and query the way fetch serialises them', () => {
        // The server signs whatever it received, as the gateway does. Each typed URL differs from what
        // fetch sends, so verifying against the typed text would fail.
        const typed = [
            "/vaults/a b/ü?label=a b&quote='x'&u=ü&keep=%7e%2B#fragment",
            '/vaults/./x/../y?',
            '/vaults\\back\\slash?a=1',
            '/vaults/{}|^`?k={}|^`"<>',
        ];

        for (const target of typed) {
            it(JSON.stringify(target), async () => {
                respond = received => ({
                    status: 200,
                    headers: signFresh({ ...received, requestBody: received.body, body: '{"ok":true}' }),
                    body: '{"ok":true}',
                });
                const init = { method: 'POST', headers: { 'X-Api-Sign': 'c2lnbmF0dXJl' }, body: '{"amount":"1.5"}' };

                const result = await verifyFetchResponse({ url: origin + target, ...init }, await fetch(origin + target, init), FRESH_OPTIONS);

                const parsed = new URL(origin + target);
                // Node 26's fetch keeps an empty "?" on the request line and older ones drop it. Both give
                // the gateway the same path and an empty query, which is all the signature covers.
                assert.equal(seen.url.replace(/\?$/, ''), parsed.pathname + parsed.search);
                assert.notEqual(seen.url, target);
                assert.equal(result.verified, true);

                // The same response checked against the URL as typed does not verify.
                assert.throws(() => verifyResponse({
                    request: { method: 'POST', url: target, body: init.body, apiSign: 'c2lnbmF0dXJl' },
                    response: { status: 200, headers: signFresh({ ...seen, requestBody: seen.body, body: '{"ok":true}' }), body: '{"ok":true}' },
                }, FRESH_OPTIONS), isReason('invalid'));
            });
        }

        it('also from a Request', async () => {
            respond = received => ({ status: 200, headers: signFresh({ ...received, requestBody: received.body, body: '' }), body: '' });
            const request = new Request(`${origin}/vaults/a b/ü?x=ü#fragment`);

            const result = await verifyFetchResponse(request, await fetch(request.clone()), FRESH_OPTIONS);

            assert.equal(seen.url, '/vaults/a%20b/%C3%BC?x=%C3%BC');
            assert.equal(result.verified, true);
        });
    });
});

describe('verifyFetchResponse with in-memory responses', () => {
    const respondTo = (signedAs, init = {}) => new Response('{"ok":true}', {
        status: 200,
        headers: signFresh({ method: signedAs, url: '/vaults', body: '{"ok":true}', ...init }),
    });

    it('upper-cases the methods fetch upper-cases', async () => {
        for (const method of ['get', 'Post', 'put', 'delete', 'options']) {
            const result = await verifyFetchResponse({ url: 'https://rest.example.test/vaults', method }, respondTo(method.toUpperCase()), FRESH_OPTIONS);
            assert.equal(result.verified, true, method);
        }
    });

    it('keeps any other method exactly as written, as fetch sends it', async () => {
        const result = await verifyFetchResponse({ url: 'https://rest.example.test/vaults', method: 'patch' }, respondTo('patch'), FRESH_OPTIONS);
        assert.equal(result.verified, true);

        await assert.rejects(
            verifyFetchResponse({ url: 'https://rest.example.test/vaults', method: 'patch' }, respondTo('PATCH'), FRESH_OPTIONS),
            isReason('invalid'),
        );
    });

    it('reads x-api-sign from the init headers in any shape fetch accepts, or from apiSign', async () => {
        const url = 'https://rest.example.test/vaults';
        const signed = () => respondTo('GET', { apiSign: 'c2lnbg==' });
        for (const headers of [{ 'x-api-sign': 'c2lnbg==' }, { 'X-API-SIGN': ' c2lnbg== ' }, [['X-Api-Sign', 'c2lnbg==']], new Headers({ 'x-api-sign': 'c2lnbg==' })]) {
            assert.equal((await verifyFetchResponse({ url, headers }, signed(), FRESH_OPTIONS)).verified, true);
        }
        assert.equal((await verifyFetchResponse({ url, apiSign: 'c2lnbg==' }, signed(), FRESH_OPTIONS)).verified, true);
        await assert.rejects(verifyFetchResponse({ url }, signed(), FRESH_OPTIONS), isReason('invalid'));
    });

    it('reads x-api-keypair-sign from the init headers in any shape fetch accepts, or from keypairSign', async () => {
        const url = 'https://rest.example.test/vaults';
        const keypairSign = 'a2V5LXBhaXI=';
        const signed = () => respondTo('GET', { apiSign: 'c2lnbg==', keypairSign });
        for (const headers of [
            { 'x-api-sign': 'c2lnbg==', 'x-api-keypair-sign': keypairSign },
            { 'X-API-SIGN': 'c2lnbg==', 'X-API-KEYPAIR-SIGN': ` ${keypairSign} ` },
            [['X-Api-Sign', 'c2lnbg=='], ['X-Api-Keypair-Sign', keypairSign]],
            new Headers({ 'x-api-sign': 'c2lnbg==', 'x-api-keypair-sign': keypairSign }),
        ]) {
            assert.equal((await verifyFetchResponse({ url, headers }, signed(), FRESH_OPTIONS)).verified, true);
        }
        assert.equal((await verifyFetchResponse({ url, apiSign: 'c2lnbg==', keypairSign }, signed(), FRESH_OPTIONS)).verified, true);
        // signed for a request with one, checked as a request without it, and the other way round
        await assert.rejects(verifyFetchResponse({ url, apiSign: 'c2lnbg==' }, signed(), FRESH_OPTIONS), isReason('invalid'));
        await assert.rejects(
            verifyFetchResponse({ url, apiSign: 'c2lnbg==', keypairSign }, respondTo('GET', { apiSign: 'c2lnbg==' }), FRESH_OPTIONS),
            isReason('invalid'),
        );
    });

    it('refuses a response whose body was already read', async () => {
        const response = respondTo('GET');
        await response.text();

        await assert.rejects(verifyFetchResponse({ url: 'https://rest.example.test/vaults' }, response, FRESH_OPTIONS), TypeError);
    });

    it('refuses a relative URL, which fetch could not have sent', async () => {
        await assert.rejects(verifyFetchResponse({ url: '/vaults' }, respondTo('GET'), FRESH_OPTIONS), TypeError);
    });
});
