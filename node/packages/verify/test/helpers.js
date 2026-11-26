'use strict';

// Shared test helpers. node --test also loads this file, finds no tests in it and moves on.

const crypto = require('node:crypto');

const VECTORS = require('../../../../test-vectors/v1.json');
const { ResponseSignatureError } = require('../src/errors');

const SIGN_HEADERS = ['x-api-response-sign', 'x-api-response-timestamp', 'x-api-response-sign-version', 'x-api-response-cert'];

function caseNamed(name) {
    const vector = VECTORS.cases.find(candidate => candidate.name === name);
    if (!vector) {
        throw new Error(`no vector named ${name}`);
    }

    return vector;
}

const rootSpkiDer = name => Buffer.from(VECTORS.keys.roots[name].publicKeySpkiDerBase64, 'base64');

const rootPem = name => crypto.createPublicKey({ key: rootSpkiDer(name), format: 'der', type: 'spki' })
    .export({ format: 'pem', type: 'spki' });

// The vectors keep path and query apart; the helper takes them as one request-line target.
const urlOf = request => (request.query === '' ? request.path : `${request.path}?${request.query}`);

function exchangeOf(vector, headers = vector.verify.response.headers) {
    const { request, response } = vector.verify;

    return {
        request: {
            method: request.method,
            url: urlOf(request),
            body: Buffer.from(request.bodyBase64, 'base64'),
            apiSign: request.apiSign,
            keypairSign: request.keypairSign,
        },
        response: {
            status: response.status,
            headers,
            body: Buffer.from(response.bodyBase64, 'base64'),
        },
    };
}

const optionsOf = (vector, extra = {}) => ({
    roots: vector.verify.pinnedRoots.map(rootPem),
    now: vector.verify.now,
    maxClockSkewSeconds: VECTORS.verifier.skewSeconds,
    ...extra,
});

/**
 * Runs a verification and reports it in the vectors' own { valid, reason } shape. Only a
 * ResponseSignatureError counts as a verdict; any other error is a bug and is rethrown.
 */
function verdictOf(run) {
    try {
        const result = run();

        return result.verified ? { valid: true } : { valid: false, reason: result.reason, returned: true };
    } catch (e) {
        if (e instanceof ResponseSignatureError) {
            return { valid: false, reason: e.reason };
        }
        throw e;
    }
}

const withoutSignHeaders = headers => Object.fromEntries(
    Object.entries(headers).filter(([name]) => !SIGN_HEADERS.includes(name.toLowerCase())),
);

// A stand-in for the gateway, for tests that need a response signed over a request no vector covers. It
// reuses the certificate of a valid vector (pod key 1 under the current root) and signs with that pod's
// published, test-only private key.
const FRESH_BASE = caseNamed('valid_current_root');
const FRESH_POD_KEY = crypto.createPrivateKey(VECTORS.keys.podKeys[FRESH_BASE.signed.signingPod].privateKeyPkcs8Pem);
const FRESH_OPTIONS = Object.freeze({ roots: [rootPem('current')], now: FRESH_BASE.verify.now });

function signFresh({ method, url, requestBody = Buffer.alloc(0), apiSign = '', keypairSign = '', status = 200, body = Buffer.alloc(0), bodyHash }) {
    const queryAt = url.indexOf('?');
    const path = queryAt === -1 ? url : url.slice(0, queryAt);
    const query = queryAt === -1 ? '' : url.slice(queryAt + 1);
    const hash = bodyHash || crypto.createHash('sha256').update(requestBody).digest('hex');
    const head = ['vaultody-response-v1', String(FRESH_BASE.signed.ts), String(status), method, path, query, hash, apiSign, keypairSign].join('\n');
    const message = Buffer.concat([Buffer.from(`${head}\n`, 'latin1'), Buffer.from(body)]);

    return {
        'x-api-response-sign': crypto.sign(null, message, FRESH_POD_KEY).toString('base64'),
        'x-api-response-timestamp': String(FRESH_BASE.signed.ts),
        'x-api-response-sign-version': '1',
        'x-api-response-cert': FRESH_BASE.signed.headers['x-api-response-cert'],
    };
}

module.exports = {
    VECTORS,
    SIGN_HEADERS,
    caseNamed,
    rootSpkiDer,
    rootPem,
    urlOf,
    exchangeOf,
    optionsOf,
    verdictOf,
    withoutSignHeaders,
    signFresh,
    FRESH_BASE,
    FRESH_OPTIONS,
};
