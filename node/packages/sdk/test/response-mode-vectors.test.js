'use strict';

// test-vectors/response-mode-v1.json: the response-signature mode in force for each configuration (the pure rule and
// real clients), and what one answer (a v1.json case) does in each mode: accepted, refused, the latch after, the
// security events in order.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { Vaultody, MemoryVaultKeyStore, ResponseVerificationError, ConfigurationError } = require('../src');
const { readResponseSignatureConfig, ResponseVerifier, DEFAULT_RESPONSE_SIGNATURE, IGNORED_WARNING } = require('../src/responseVerification');
const { CREDENTIALS } = require('./helpers');
const { load } = require('./vectors');

const VECTORS = load('response-mode-v1.json');
const RESPONSES = load('v1.json');
const ORIGIN = 'https://rest.vaultody.com';

const rootPem = name => crypto.createPublicKey({ key: Buffer.from(RESPONSES.keys.roots[name].publicKeySpkiDerBase64, 'base64'), format: 'der', type: 'spki' })
    .export({ format: 'pem', type: 'spki' });
const TEST_ROOTS = [rootPem('current'), rootPem('next')];

describe('test-vectors/response-mode-v1.json: the mode in force', () => {
    for (const c of VECTORS.config) {
        it(c.name, () => {
            assert.deepEqual(
                (({ mode, ignored }) => ({ mode, warning: ignored }))(readResponseSignatureConfig({
                    option: c.option, env: {}, rootsOption: c.rootsOption, embeddedRoots: c.embeddedRoots, version: c.version, buildDefault: c.buildDefault,
                })),
                c.expected,
            );

            // A real client uses its build's default; the cases written for another default are the rule's alone.
            if (c.buildDefault !== DEFAULT_RESPONSE_SIGNATURE) {
                return;
            }
            const warnings = [];
            const saved = process.env.VAULTODY_RESPONSE_SIGNATURE;
            delete process.env.VAULTODY_RESPONSE_SIGNATURE;
            try {
                const client = new Vaultody({
                    apiKey: CREDENTIALS.apiKey,
                    apiSecret: CREDENTIALS.apiSecret,
                    passphrase: CREDENTIALS.passphrase,
                    vaultKeyStore: new MemoryVaultKeyStore(),
                    logger: { warn: message => warnings.push(message) },
                    ...(c.rootsOption ? { roots: TEST_ROOTS } : {}),
                    ...(c.option === null ? {} : { responseSignature: c.option }),
                    unsupported: { sdkVersion: c.version, ...(c.embeddedRoots ? { embeddedRoots: TEST_ROOTS } : { embeddedRoots: [] }) },
                });
                assert.equal(client.responseSignature, c.expected.mode);
                assert.equal(client.toJSON().responseSignature, c.expected.mode);
                assert.deepEqual(warnings, c.expected.warning ? [IGNORED_WARNING] : []);
            } finally {
                if (saved !== undefined) {
                    process.env.VAULTODY_RESPONSE_SIGNATURE = saved;
                }
            }
        });
    }

    it('VAULTODY_RESPONSE_SIGNATURE counts as given: when-present from it is ignored with roots, with the same warning', () => {
        const saved = process.env.VAULTODY_RESPONSE_SIGNATURE;
        process.env.VAULTODY_RESPONSE_SIGNATURE = 'when-present';
        try {
            const warnings = [];
            const client = new Vaultody({
                apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, roots: TEST_ROOTS,
                vaultKeyStore: new MemoryVaultKeyStore(), logger: { warn: message => warnings.push(message) },
            });
            assert.equal(client.responseSignature, 'required');
            assert.deepEqual(warnings, [IGNORED_WARNING]);
        } finally {
            if (saved === undefined) {
                delete process.env.VAULTODY_RESPONSE_SIGNATURE;
            } else {
                process.env.VAULTODY_RESPONSE_SIGNATURE = saved;
            }
        }
    });
});

describe('test-vectors/response-mode-v1.json: one answer', () => {
    for (const c of VECTORS.answers) {
        it(c.name, async () => {
            const vector = RESPONSES.cases.find(item => item.name === (c.answer === 'unsigned' ? 'missing_all' : c.answer));
            const store = new MemoryVaultKeyStore();
            if (c.latchedBefore) {
                await store.latchResponseSignature(ORIGIN, VECTORS.previousLatch);
            }
            const events = [];
            const verifier = new ResponseVerifier({
                origin: ORIGIN,
                mode: c.mode,
                // Without roots the build's embedded ones are used: none in this repository.
                roots: c.roots ? vector.verify.pinnedRoots.map(rootPem) : undefined,
                store,
                securityEvent: event => events.push(event),
                warn: () => {},
            });
            const { request, response, now } = vector.verify;
            const run = verifier.verify({
                method: request.method,
                target: request.query === '' ? request.path : `${request.path}?${request.query}`,
                body: Buffer.from(request.bodyBase64, 'base64'),
                apiSign: request.apiSign,
                keypairSign: request.keypairSign,
            }, { status: response.status, headers: new Headers(response.headers), body: Buffer.from(response.bodyBase64, 'base64') }, { nowSeconds: now, operationId: 'vector' });

            const { result } = c.expected;
            if (typeof result === 'string') {
                assert.equal((await run).signature, result);
            } else if (result.error) {
                await assert.rejects(run, error => error instanceof ResponseVerificationError && error.reason === result.error);
            } else {
                await assert.rejects(run, error => error instanceof ConfigurationError && error.code === 'no_root_keys');
            }
            assert.deepEqual(await store.getResponseSignatureLatch(ORIGIN), c.expected.latch);
            assert.deepEqual(events.map(event => event.type), c.expected.events);
            const latched = events.find(event => event.type === 'response_signature_latched');
            if (latched) {
                assert.deepEqual({ rootId: latched.rootId, latchedAt: latched.latchedAt }, c.expected.latch);
            }
        });
    }
});
