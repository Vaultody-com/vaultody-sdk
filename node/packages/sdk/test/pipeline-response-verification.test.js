'use strict';

// Response verification in the pipeline (test-vectors/v1.json): the mock gateway signs every answer with the
// TEST-ONLY roots and pod keys of v1.json over the request it received, and each refusal reason of the vectors
// is produced end to end: a tampered body or status, a stripped or partly stripped signature, an unknown root,
// an expired certificate, an unread request body, an unknown signature version. Then the modes: when-present
// with its latch, required, and the latch surviving a restart through the store. Every v1.json case also runs
// through the transport's verification stage.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { Vaultody, MemoryVaultKeyStore, ResponseVerificationError, ConfigurationError, NotFoundError } = require('../src');
const { ResponseVerifier } = require('../src/responseVerification');
const { setup, failingFetch, refused, CREDENTIALS, ROOTS, VAULT, rootPem } = require('./helpers');
const { load } = require('./vectors');
const internal = require('../src/internal');

const VECTORS = load('v1.json');
const TX = '6630f1c2a9e4b5d7c8e9f0c4';

const route = gw => gw.route('GET', new RegExp(`^/transaction-requests/${TX}$`), () => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1c1', data: { item: { transactionRequestId: TX, status: 'created' } } } }));
const call = client => internal.request(client, 'getTransactionRequestDetails', { transactionRequestId: TX });
const rejectsWith = reason => error => error instanceof ResponseVerificationError && error.reason === reason;

async function withGateway(options, fn) {
    const env = await setup(options);
    route(env.gw);
    try {
        await fn(env);
    } finally {
        await env.close();
    }
}

describe('test-vectors/v1.json refusals, end to end', () => {
    const cases = [
        ['a body changed on the way', 'invalid', { mitm: ({ response }) => ({ ...response, body: Buffer.from(response.body.toString().replace('created', 'approved')) }) }],
        ['a status changed on the way', 'invalid', { mitm: ({ response }) => ({ ...response, status: 202 }) }],
        ['one signature header stripped', 'missing', { mitm: ({ response }) => { const { 'x-api-response-cert': drop, ...headers } = response.headers; return { ...response, headers }; } }],
        ['a certificate from a root that is not pinned', 'unknown_root', { signing: { root: 'unpinned' } }],
        ['the next root, pinned beside the current one', null, { signing: { root: 'next' } }],
        ['an expired certificate', 'expired', { signing: { root: 'current', notBefore: 1794100000, notAfter: 1794100100 } }],
        ['the request body unread by the gateway', 'request_unbound', { signing: { root: 'current', unreadBody: true } }],
        ['an unknown signature version', 'unsupported_version', { signing: { root: 'current', version: '2' } }],
        ['the response to another request', 'invalid', { mitm: ({ response }) => ({ ...response, headers: { ...response.headers, 'x-api-response-timestamp': String(Number(response.headers['x-api-response-timestamp']) + 1) } }) }],
    ];
    for (const [name, reason, { mitm, signing }] of cases) {
        it(`${name}: ${reason || 'verified'}`, async () => {
            await withGateway({ signing: signing || { root: 'current' } }, async ({ gw, client, events }) => {
                if (mitm) {
                    gw.mitm = mitm;
                }
                if (reason === null) {
                    const result = await call(client);
                    assert.equal(result.meta.signature, 'verified');
                    assert.equal(result.meta.rootId, require('../../../../conformance/mock-gateway').ROOT_IDS.next);

                    return;
                }
                await assert.rejects(call(client), rejectsWith(reason));
                // Never retried, and reported.
                assert.equal(gw.requests.length, 1);
                assert.ok(events.some(event => event.type === 'response_verification_failed' && event.reason === reason));
            });
        });
    }

    it('an error answer is verified too: a forged 404 is refused, a genuine one is a NotFoundError', async () => {
        await withGateway({}, async ({ gw, client }) => {
            gw.route('GET', /^\/transaction-requests\/missing/, () => ({ status: 404, body: { requestId: 'r', error: { code: 'resource_not_found', message: 'no' } } }));
            await assert.rejects(internal.request(client, 'getTransactionRequestDetails', { transactionRequestId: 'missing' }), NotFoundError);
            gw.mitm = ({ response }) => ({ ...response, body: Buffer.from(response.body.toString().replace('no', 'gone')) });
            await assert.rejects(internal.request(client, 'getTransactionRequestDetails', { transactionRequestId: 'missing' }), rejectsWith('invalid'));
        });
    });
});

describe('response signature modes', () => {
    it('when-present accepts an unsigned answer as absent, reports it once, and turns strict after the first signed one', async () => {
        // A release candidate that embeds the roots: the bridge from unsigned to signed answers.
        await withGateway({ signing: false, roots: 'embedded' }, async ({ gw, client, events, warnings }) => {
            assert.equal(client.responseSignature, 'when-present');
            const first = await call(client);
            assert.equal(first.meta.signature, 'absent');
            await call(client);
            // Once per client: the security event with exactly these fields, then one warning.
            assert.deepEqual(events.filter(event => event.type === 'unsigned_response_accepted'),
                [{ type: 'unsigned_response_accepted', origin: client.origin, operationId: first.meta.operationId }]);
            assert.equal(warnings.filter(message => message.includes('not signed')).length, 1);
            assert.ok(warnings.find(message => message.includes('not signed')).includes(client.origin));

            gw.signing = { root: 'current' };
            assert.equal((await call(client)).meta.signature, 'verified');
            assert.ok(events.some(event => event.type === 'response_signature_latched'));

            // A signature stripped from now on is caught.
            gw.signing = false;
            await assert.rejects(call(client), rejectsWith('missing'));
        });
    });

    it('the unsigned notice is per client: each new client reports it once', async () => {
        await withGateway({ signing: false }, async ({ gw, clock }) => {
            const events = [];
            const warnings = [];
            const make = () => new Vaultody({
                apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: gw.url,
                vaultKeyStore: new MemoryVaultKeyStore(), logger: { warn: message => warnings.push(message) }, onSecurityEvent: event => events.push(event), unsupported: { clock },
            });
            const first = make();
            await call(first);
            await call(first);
            await call(make());
            assert.equal(events.filter(event => event.type === 'unsigned_response_accepted').length, 2);
            assert.equal(warnings.filter(message => message.includes('not signed')).length, 2);
        });
    });

    it('the latch survives a restart: a new client on the same store is strict at once', async () => {
        const store = new MemoryVaultKeyStore();
        await withGateway({ client: { vaultKeyStore: store } }, async ({ gw, clock }) => {
            const first = new Vaultody({ apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: gw.url, roots: [rootPem('current')], vaultKeyStore: store, logger: { warn() {} }, unsupported: { clock } });
            await call(first);
            assert.ok(await store.getResponseSignatureLatch(first.origin));
            gw.signing = false;
            const second = new Vaultody({ apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: gw.url, roots: [rootPem('current')], vaultKeyStore: store, logger: { warn() {} }, unsupported: { clock } });
            await assert.rejects(call(second), rejectsWith('missing'));
        });
    });

    it('a partly stripped signature is refused even before the latch', async () => {
        await withGateway({}, async ({ gw, client }) => {
            gw.mitm = ({ response }) => {
                const { 'x-api-response-sign': drop, ...headers } = response.headers;

                return { ...response, headers };
            };
            await assert.rejects(call(client), rejectsWith('missing'));
        });
    });

    it('required refuses an unsigned answer from the first call (also through VAULTODY_RESPONSE_SIGNATURE)', async () => {
        await withGateway({ signing: false, client: { responseSignature: 'required' } }, async ({ client }) => {
            await assert.rejects(call(client), rejectsWith('missing'));
        });
        const saved = process.env.VAULTODY_RESPONSE_SIGNATURE;
        process.env.VAULTODY_RESPONSE_SIGNATURE = 'required';
        try {
            await withGateway({ signing: false }, async ({ client }) => {
                assert.equal(client.responseSignature, 'required');
                await assert.rejects(call(client), rejectsWith('missing'));
            });
            process.env.VAULTODY_RESPONSE_SIGNATURE = 'sometimes';
            assert.throws(() => new Vaultody({ apiKey: 'k', apiSecret: CREDENTIALS.apiSecret, passphrase: 'p', vaultKeyStore: new MemoryVaultKeyStore() }), error => error instanceof ConfigurationError);
        } finally {
            if (saved === undefined) {
                delete process.env.VAULTODY_RESPONSE_SIGNATURE;
            } else {
                process.env.VAULTODY_RESPONSE_SIGNATURE = saved;
            }
        }
    });

    it('without root keys an unsigned answer passes and a signed one fails closed', async () => {
        await withGateway({ signing: false, client: { roots: undefined } }, async ({ gw, client }) => {
            assert.equal((await call(client)).meta.signature, 'absent');
            gw.signing = { root: 'current' };
            await assert.rejects(call(client), error => error instanceof ConfigurationError && error.code === 'no_root_keys');
        });
    });
});

describe('roots configured, and the latch on any signed answer', () => {
    const TRANSFER = { vaultId: VAULT, amount: '0.1', assetId: '6630f1c2a9e4b5d7c8e9f0b7', fromAddress: 'from', toAddress: 'to', note: 'test', vaultAccountId: '6630f1c2a9e4b5d7c8e9f0e2' };
    const SIGNING_KEYS = '/api-keys/current/signing-keys';
    const transferRoute = gw => gw.route('POST', /\/single-transfer$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item: { transactionRequestId: TX } } } }));
    const transfer = client => internal.request(client, 'createSingleTransfer', TRANSFER);
    const stripAll = ({ response }) => {
        const headers = Object.fromEntries(Object.entries(response.headers).filter(([name]) => !name.toLowerCase().startsWith('x-api-response-')));

        return { ...response, headers };
    };
    const make = (gw, clock, extra = {}) => new Vaultody({
        apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, baseUrl: gw.url, logger: { warn() {} }, ...extra,
        unsupported: { clock, ...(extra.unsupported || {}) },
    });

    it('no roots and a signing gateway: ConfigurationError, the origin latched with rootId null; a stripped answer next is missing; a new client on the store is strict', async () => {
        const store = new MemoryVaultKeyStore();
        await withGateway({ roots: 'none', client: { vaultKeyStore: store } }, async ({ gw, clock, client, events }) => {
            assert.equal(client.responseSignature, 'when-present');
            await assert.rejects(call(client), error => error instanceof ConfigurationError && error.code === 'no_root_keys');
            assert.deepEqual(await store.getResponseSignatureLatch(client.origin), { latchedAt: Math.floor(clock() / 1000), rootId: null });
            assert.deepEqual(events.map(event => event.type), ['response_signature_latched']);
            assert.equal(events[0].rootId, null);

            gw.mitm = stripAll;
            await assert.rejects(call(client), rejectsWith('missing'));
            const restarted = make(gw, clock, { vaultKeyStore: store, unsupported: { embeddedRoots: [] } });
            await assert.rejects(call(restarted), rejectsWith('missing'));
        });
    });

    it('roots given and every signature stripped from the first answer: refused as missing, one request, never retried', async () => {
        await withGateway({ signing: false, roots: 'option' }, async ({ gw, client, events }) => {
            assert.equal(client.responseSignature, 'required');
            await assert.rejects(call(client), rejectsWith('missing'));
            assert.equal(gw.requests.length, 1);
            assert.deepEqual(events.map(event => event.type), ['response_verification_failed']);
        });
    });

    it('a write with roots against an origin that does not sign: the signed read before it is refused, and the write is never sent', async () => {
        await withGateway({ signing: false, roots: 'option' }, async ({ gw, client }) => {
            transferRoute(gw);
            await assert.rejects(transfer(client), rejectsWith('missing'));
            assert.deepEqual(gw.requests.map(request => request.path), [SIGNING_KEYS]);
            assert.equal(gw.executions.filter(execution => execution.method === 'POST').length, 0);
        });
    });

    it('a signing origin: one signed read before the first write, none before the next ones', async () => {
        await withGateway({}, async ({ gw, client }) => {
            transferRoute(gw);
            await transfer(client);
            await transfer(client);
            assert.deepEqual(gw.requests.map(request => request.method), ['GET', 'POST', 'POST']);
            assert.equal(gw.requests[0].path, SIGNING_KEYS);
        });
    });

    it('no signed read for an origin latched before, for a client without roots, or for a read', async () => {
        await withGateway({ latched: true }, async ({ gw, client }) => {
            transferRoute(gw);
            await transfer(client);
            assert.deepEqual(gw.requests.map(request => request.method), ['POST']);
        });
        await withGateway({ signing: false }, async ({ gw, client }) => {
            transferRoute(gw);
            await transfer(client);
            assert.deepEqual(gw.requests.map(request => request.method), ['POST']);
        });
        await withGateway({}, async ({ gw, client }) => {
            await call(client);
            assert.deepEqual(gw.requests.map(request => request.method), ['GET']);
            assert.notEqual(gw.requests[0].path, SIGNING_KEYS);
        });
    });

    it('with a signer the key-pair check is that read: one GET before the first write', async () => {
        await withGateway({ key: 'ed25519' }, async ({ gw, client }) => {
            transferRoute(gw);
            await transfer(client);
            await transfer(client);
            assert.deepEqual(gw.requests.map(request => request.method), ['GET', 'POST', 'POST']);
            assert.equal(gw.requests[0].path, SIGNING_KEYS);
            assert.ok(gw.requests.every(request => request.headers['x-api-keypair-sign']));
        });
    });

    it('a refused signed read is a settled origin; a read lost on the network leaves it open and the write goes ahead', async () => {
        await withGateway({}, async ({ gw, client }) => {
            transferRoute(gw);
            gw.route('GET', /^\/api-keys\/current\/signing-keys$/, () => ({ status: 403, body: { requestId: 'r', error: { code: 'endpoint_not_allowed_for_api_key', message: 'no' } } }));
            await transfer(client);
            await transfer(client);
            assert.deepEqual(gw.requests.map(request => request.method), ['GET', 'POST', 'POST']);
        });
        // Every attempt of the read is refused on the network until the first write is done.
        let down = true;
        const fetch = failingFetch(Array.from({ length: 50 }, refused), init => init.method === 'GET' && down);
        await withGateway({ client: { unsupported: { fetch } } }, async ({ gw, client, events }) => {
            transferRoute(gw);
            await transfer(client);
            down = false;
            await transfer(client);
            // The read never reached the gateway, the write went ahead, and its own signed answer latched the origin:
            // no read before the second write.
            assert.ok(fetch.calls.filter(call => call.method === 'GET').length > 1);
            assert.deepEqual(gw.requests.map(request => request.method), ['POST', 'POST']);
            assert.ok(events.some(event => event.type === 'response_signature_latched'));
        });
    });

    it('a release candidate that embeds the roots bridges: unsigned answers until the first signed one, which latches with its root', async () => {
        await withGateway({ signing: false, roots: 'embedded' }, async ({ gw, client, events }) => {
            transferRoute(gw);
            assert.equal(client.responseSignature, 'when-present');
            assert.equal((await call(client)).meta.signature, 'absent');
            // Not configured roots (a release candidate): no signed read before a write.
            await transfer(client);
            assert.deepEqual(gw.requests.map(request => request.method), ['GET', 'POST']);
            gw.signing = { root: 'current' };
            assert.equal((await call(client)).meta.signature, 'verified');
            const latch = events.find(event => event.type === 'response_signature_latched');
            assert.equal(latch.rootId, require('../../../../conformance/mock-gateway').ROOT_IDS.current);
            gw.signing = false;
            await assert.rejects(call(client), rejectsWith('missing'));
        });
        // The same build as a stable release is strict from the first answer.
        await withGateway({ signing: false, roots: 'none', client: { unsupported: { embeddedRoots: ROOTS, sdkVersion: '1.0.0' } } }, async ({ client }) => {
            assert.equal(client.responseSignature, 'required');
            await assert.rejects(call(client), rejectsWith('missing'));
        });
    });

    it('a strict client latches too, so a release candidate sharing its store is strict', async () => {
        const store = new MemoryVaultKeyStore();
        await withGateway({ client: { vaultKeyStore: store } }, async ({ gw, clock, client }) => {
            await call(client);
            assert.ok(await store.getResponseSignatureLatch(client.origin));
            gw.signing = false;
            const candidate = make(gw, clock, { vaultKeyStore: store });
            assert.equal(candidate.responseSignature, 'when-present');
            await assert.rejects(call(candidate), rejectsWith('missing'));
        });
    });
});

describe('test-vectors/v1.json through the verification stage', () => {
    const roots = VECTORS.keys.roots;
    const pem = name => require('node:crypto').createPublicKey({ key: Buffer.from(roots[name].publicKeySpkiDerBase64, 'base64'), format: 'der', type: 'spki' }).export({ format: 'pem', type: 'spki' });

    for (const vector of VECTORS.cases) {
        for (const mode of ['required', 'when-present']) {
            it(`${vector.name} (${mode})`, async () => {
                const verifier = new ResponseVerifier({
                    origin: 'https://rest.vaultody.com',
                    mode,
                    roots: vector.verify.pinnedRoots.map(pem),
                    store: new MemoryVaultKeyStore(),
                    securityEvent: () => {},
                    warn: () => {},
                });
                const { request, response, now } = vector.verify;
                const sent = {
                    method: request.method,
                    target: request.query === '' ? request.path : `${request.path}?${request.query}`,
                    body: Buffer.from(request.bodyBase64, 'base64'),
                    apiSign: request.apiSign,
                    keypairSign: request.keypairSign,
                };
                const received = { status: response.status, headers: response.headers, body: Buffer.from(response.bodyBase64, 'base64') };
                const run = verifier.verify(sent, received, { nowSeconds: now, operationId: 'vector' });
                if (vector.expected.valid) {
                    assert.equal((await run).signature, 'verified');
                } else if (vector.name === 'missing_all' && mode === 'when-present') {
                    // No signature header at all: accepted as unsigned until the latch.
                    assert.equal((await run).signature, 'absent');
                } else {
                    await assert.rejects(run, rejectsWith(vector.expected.reason));
                }
            });
        }
    }
});
