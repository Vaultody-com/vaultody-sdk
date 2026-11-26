#!/usr/bin/env node
'use strict';

/**
 * Writes the vector sets whose bytes come from the API gateway's own code, and the error catalogue:
 *
 *   request-hmac-v2.json   x-api-sign version 2: the signed string and the HMAC (the gateway's signing helpers)
 *   request-full-v1.json   credentials, key pair, clock and nonce in; every authentication header out,
 *                          each checked with the gateway's own request checks
 *   signing-keys-v1.json   signed answers of GET /api-keys/current/signing-keys (its response-signing helpers)
 *   vault-key-pins-v1.json sequences of signed and unsigned GET /vaults/{networkType} answers and what
 *                          they do to the vault xpub pins (its response-signing helpers)
 *   ../contract/errors.json the error codes: the documented ones (contract/openapi.json) and the gateway's
 *                          own error responses
 *
 *   node test-vectors/tools/generate-gateway-vectors.js --gateway <API gateway checkout> [--check]
 *
 * The API gateway is Vaultody's own, not public: only Vaultody can run this. The checkout is only read.
 * Its commit is recorded in every file. --check compares with the files in the repository instead of
 * writing them.
 *
 * Keys and certificates are TEST-ONLY and come from the gateway's own vector files already copied here:
 * the client key pairs from request-keypair-v1.json, the response-signing roots, pod keys and the two
 * root certificates from v1.json. ECDSA certificate signatures are random, so the certificates are reused
 * from v1.json rather than made again; with them, a rerun writes every file byte for byte the same,
 * except the P-256 request signatures in request-full-v1.json, which are random and are therefore only
 * verified, never compared.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const VECTORS_DIR = path.join(ROOT, 'test-vectors');

function parseArgs(argv) {
    const args = { gateway: null, check: false };
    for (let i = 0; i < argv.length; i += 1) {
        if (argv[i] === '--gateway') {
            args.gateway = path.resolve(argv[i + 1]);
            i += 1;
        } else if (argv[i] === '--check') {
            args.check = true;
        } else {
            throw new Error(`unknown argument ${argv[i]}`);
        }
    }
    if (!args.gateway) {
        throw new Error('usage: generate-gateway-vectors.js --gateway <API gateway checkout> [--check]');
    }

    return args;
}

const ARGS = parseArgs(process.argv.slice(2));
const git = (...args) => execFileSync('git', ['-C', ARGS.gateway, ...args], { encoding: 'utf8' }).trim();

const GATEWAY_FILES = [
    'src/helpers/apiSign.js',
    'src/helpers/requestKeypair.js',
    'src/helpers/responseSigning.js',
    'src/tests/helpers/verifyResponse.js',
    'src/responses/customErrorResponses.js',
];
if (git('status', '--porcelain', '--', ...GATEWAY_FILES) !== '') {
    throw new Error('the gateway checkout has uncommitted changes in the files read here; commit or stash them first');
}
const GATEWAY = Object.freeze({
    commit: git('rev-parse', 'HEAD'),
});

const gatewayModule = file => require(path.join(ARGS.gateway, file));
const apiSign = gatewayModule('src/helpers/apiSign.js');
const { RequestKeypair } = gatewayModule('src/helpers/requestKeypair.js');
const rs = gatewayModule('src/helpers/responseSigning.js');
const reference = gatewayModule('src/tests/helpers/verifyResponse.js');
const customErrorResponses = gatewayModule('src/responses/customErrorResponses.js');

const readVectors = name => JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, name), 'utf8'));
const RESPONSE_VECTORS = readVectors('v1.json');
const KEYPAIR_VECTORS = readVectors('request-keypair-v1.json');

const b64 = bytes => Buffer.from(bytes).toString('base64');
const utf8 = text => Buffer.from(text, 'utf8');
const json = value => utf8(JSON.stringify(value));
const label = text => crypto.createHash('sha256').update(`vaultody sdk vectors TEST-ONLY ${text}`).digest();

const WARNING = 'TEST-ONLY KEYS AND SECRETS. Every secret and private key in this file is public. Never use them outside tests.';
const sourceOf = (generator, extra = {}) => ({ generator: `test-vectors/tools/${generator}`, gateway: GATEWAY, ...extra });

// ---------------------------------------------------------------------------------------------------
// Request signing: HMAC v2
// ---------------------------------------------------------------------------------------------------

/** An API secret as Vaultody issues one: 10 random bytes, standard base64 with padding (16 characters). */
const secretOf = (text, bytes = 10) => b64(label(`api secret ${text}`).subarray(0, bytes));
const SECRET = secretOf('A');
const SECRET_LONG = secretOf('B', 32);

const VAULT_A = '6630f1c2a9e4b5d7c8e9f0a1';
const VAULT_B = '6630f1c2a9e4b5d7c8e9f0c3';
const VAULT_SMART = '6630f1c2a9e4b5d7c8e9f0d7';
const TIMESTAMP = '1794201000';
const PASSPHRASE = 'TEST-ONLY passphrase 7';
const API_VERSION = '2026-03-20';

const CREATE_ADDRESS = Object.freeze({
    timestamp: TIMESTAMP,
    method: 'POST',
    path: `/vaults/${VAULT_A}/bitcoin/mainnet/addresses`,
    apiVersion: API_VERSION,
    passphrase: PASSPHRASE,
    nonce: '6f1c2a9e0b5d47c8a9e4f0a1c2b3d4e5',
    query: '',
    body: '{"context":"yes","data":{"item":{"label":"deposit-7"}}}',
});

const LIST_VAULTS = Object.freeze({
    timestamp: TIMESTAMP,
    method: 'GET',
    path: '/vaults/main',
    apiVersion: API_VERSION,
    passphrase: PASSPHRASE,
    nonce: '0c9b8a7f6e5d4c3b2a1908f7e6d5c4b3',
    query: 'limit=50',
    body: '',
});

/** apiSign's names for the request fields */
const signParams = request => ({
    timestamp: request.timestamp,
    method: request.method,
    path: request.path,
    rawQuery: request.query,
    apiVersionHeader: request.apiVersion,
    passphrase: request.passphrase,
    nonce: request.nonce,
    rawBody: request.body,
});

const SECRET_SHAPE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?$/;

/** The SDK's rule for an API secret: standard base64, padding optional, at least one byte. */
const sdkAcceptsSecret = secret => typeof secret === 'string' && secret !== '' && SECRET_SHAPE.test(secret)
    && Buffer.from(secret, 'base64').length > 0;

function hmacCase(spec) {
    const request = { ...CREATE_ADDRESS, ...spec.request };
    const secret = spec.secret === undefined ? SECRET : spec.secret;
    const base = { name: spec.name, description: spec.description, secret, request };
    if (spec.error) {
        if (spec.error === 'invalid_api_secret' && sdkAcceptsSecret(secret)) {
            throw new Error(`${spec.name}: the SDK rule accepts this secret`);
        }

        return { ...base, expected: { error: spec.error } };
    }
    if (!sdkAcceptsSecret(secret) || !apiSign.isUsableSecret(secret)) {
        throw new Error(`${spec.name}: the secret is not usable`);
    }

    const signedString = apiSign.v2Message(signParams(request));
    const signature = apiSign.signV2({ ...signParams(request), secret });
    // The same HMAC, computed here from the string and the decoded secret, so the file can't hold a
    // signature the gateway's two functions disagree on.
    const recomputed = crypto.createHmac('sha256', Buffer.from(secret, 'base64')).update(utf8(signedString)).digest('base64');
    if (recomputed !== signature) {
        throw new Error(`${spec.name}: signV2 and v2Message disagree`);
    }
    if (spec.sameSignatureAs && spec.sameSignatureAs !== signature) {
        throw new Error(`${spec.name}: expected the same signature as the padded secret`);
    }

    return { ...base, expected: { signedString, signedStringBase64: b64(utf8(signedString)), signature } };
}

function buildHmacV2() {
    const padded = apiSign.signV2({ ...signParams(CREATE_ADDRESS), secret: SECRET });
    const specs = [
        { name: 'post_all_fields', description: 'POST with x-api-version, a nonce, a query string and a body.', request: { query: 'context=yes' } },
        { name: 'get_empty_fields', description: 'GET without x-api-version, nonce, query string or body: those four are empty lines.', request: { ...LIST_VAULTS, apiVersion: '', nonce: '', query: '' } },
        { name: 'get_list_vaults', description: 'GET /vaults/main?limit=50 with x-api-version and a nonce, as the SDK sends it.', request: LIST_VAULTS },
        { name: 'no_api_version', description: 'x-api-version not sent: an empty line.', request: { apiVersion: '' } },
        { name: 'no_nonce', description: 'x-api-nonce not sent: an empty line. The SDK always sends one; the gateway accepts v2 without it for an API key without a key pair.', request: { nonce: '' } },
        {
            name: 'raw_query_as_sent',
            description: 'The query string is signed exactly as sent: unsorted, a repeated name, percent-encoding untouched.',
            request: { ...LIST_VAULTS, query: 'offset=0&limit=10&label=deposit%20%E2%9C%93&label=a%2Bb' },
        },
        { name: 'query_with_question_mark', description: 'Everything after the first "?" is the query, a later "?" included.', request: { ...LIST_VAULTS, query: 'label=a?b' } },
        {
            name: 'unicode_body',
            description: 'The body is signed exactly as sent, as UTF-8: whitespace, newlines, key order and non-ASCII kept.',
            request: { body: '{\n  "data": { "item": { "label": "Сметка ✓ 東京", "amount": "0.10" } },\n  "context": "yes"\n}' },
        },
        { name: 'body_trailing_newline', description: 'A body ending in a newline keeps it: the body is the last field and nothing follows it.', request: { body: `${CREATE_ADDRESS.body}\n` } },
        { name: 'v2_path_prefix', description: 'The path is signed as sent, with the /v2 prefix when the client calls through it.', request: { path: `/v2/vaults/${VAULT_A}/bitcoin/mainnet/addresses` } },
        {
            name: 'put_update_vault_account',
            description: 'PUT with a body.',
            request: { method: 'PUT', path: `/vaults/${VAULT_A}/vault-accounts/6630f1c2a9e4b5d7c8e9f0e2/edit`, body: '{"data":{"item":{"name":"Treasury","isFavoriteInDashboard":true}}}' },
        },
        {
            name: 'percent_encoded_path',
            description: 'A path parameter percent-encoded on the request line is signed in that form, not decoded.',
            request: { ...LIST_VAULTS, path: `/vaults/${VAULT_A}/addresses/r%20Test%2Fx/balance`, query: 'limit=1' },
        },
        { name: 'secret_without_padding', description: 'The same secret without its "==" padding gives the same signature: the padding is optional.', secret: SECRET.replace(/=+$/, ''), sameSignatureAs: padded },
        { name: 'secret_32_bytes', description: 'A longer secret (32 bytes).', secret: SECRET_LONG },

        // Secrets the SDK refuses before it signs anything. Vaultody issues secrets as canonical base64
        // (clients EncryptionHelper.generateSecret), so a real secret never meets these.
        { name: 'secret_empty', description: 'An empty secret would be an HMAC key anyone can sign with.', secret: '', error: 'invalid_api_secret' },
        { name: 'secret_only_padding', description: '"====" decodes to zero bytes.', secret: '====', error: 'invalid_api_secret' },
        { name: 'secret_not_base64', description: 'Characters outside the base64 alphabet. (The gateway\'s lenient decoder would skip them; the SDK refuses rather than guess.)', secret: 'not base64!', error: 'invalid_api_secret' },
        { name: 'secret_url_safe_alphabet', description: 'The URL-safe alphabet ("-", "_") is not the one Vaultody issues secrets in.', secret: 'ab-_cd-_ef-_gh==', error: 'invalid_api_secret' },
        { name: 'secret_with_newline', description: 'A trailing newline, as from a file read whole: refused, never trimmed.', secret: `${SECRET}\n`, error: 'invalid_api_secret' },
    ];

    return {
        format: 'vaultody request signature x-api-sign, version 2',
        warning: WARNING,
        source: sourceOf('generate-gateway-vectors.js'),
        wire: {
            signedString: '"v2\\n" timestamp "\\n" method "\\n" path "\\n" apiVersion "\\n" passphrase "\\n" nonce "\\n" query "\\n" body, as UTF-8, no trailing newline (as the gateway builds it)',
            fields: 'timestamp = x-api-timestamp; method as sent; path as sent, without the query (with the /v2 prefix if used); apiVersion = x-api-version, empty if not sent; passphrase = x-api-passphrase; nonce = x-api-nonce, empty if not sent; query = the raw query string after the first "?", empty if none; body = the raw body as sent, empty if none',
            signature: 'x-api-sign = standard base64 (with padding) of HMAC-SHA256 keyed with the base64-decoded API secret over the signed string; sent with x-api-sign-version: 2',
            secret: 'The SDK accepts an API secret in standard base64, padding optional, decoding to at least one byte, and refuses anything else with invalid_api_secret before signing.',
        },
        caseFormat: {
            secret: 'the API secret as configured',
            request: 'the request fields as sent',
            expected: '{ signedString, signedStringBase64, signature } or { error }',
        },
        cases: specs.map(hmacCase),
    };
}

// ---------------------------------------------------------------------------------------------------
// Request signing: the whole header set
// ---------------------------------------------------------------------------------------------------

const CLIENT_KEYS = Object.fromEntries(['ed25519', 'p256'].map(name => {
    const record = KEYPAIR_VECTORS.keys[name];

    return [name, { ...record, privateKey: crypto.createPrivateKey(record.privateKeyPkcs8Pem) }];
}));

const CREDENTIALS = Object.freeze({
    apiKey: label('api key A').toString('hex').slice(0, 40),
    apiSecret: SECRET,
    passphrase: PASSPHRASE,
});

const HEADER_ORDER = ['x-api-key', 'x-api-passphrase', 'x-api-timestamp', 'x-api-sign', 'x-api-sign-version', 'x-api-nonce', 'x-api-version', 'x-api-keypair-sign', 'x-api-keypair-id'];

/** Every authentication header of one request, as the SDK must send them. */
function authenticationHeaders(request, keyName) {
    const params = signParams(request);
    const headers = {
        'x-api-key': CREDENTIALS.apiKey,
        'x-api-passphrase': CREDENTIALS.passphrase,
        'x-api-timestamp': request.timestamp,
        'x-api-sign': apiSign.signV2({ ...params, secret: CREDENTIALS.apiSecret }),
        'x-api-sign-version': '2',
        'x-api-nonce': request.nonce,
    };
    if (request.apiVersion !== '') {
        headers['x-api-version'] = request.apiVersion;
    }
    if (keyName) {
        const key = CLIENT_KEYS[keyName];
        const message = utf8(apiSign.keypairMessage({ ...params, apiKey: CREDENTIALS.apiKey }));
        const signature = key.algorithm === 'ed25519'
            ? crypto.sign(null, message, key.privateKey)
            : crypto.sign('sha256', message, { key: key.privateKey, dsaEncoding: 'der' });
        headers['x-api-keypair-sign'] = b64(signature);
        headers['x-api-keypair-id'] = key.fingerprint;
    }

    return headers;
}

/** The gateway's own checks of a request: the HMAC v2 and, with a key pair, RequestKeypair.verify. */
function gatewayAccepts(request, headers, keyName) {
    const params = signParams(request);
    if (!apiSign.signaturesMatch(headers['x-api-sign'], apiSign.signV2({ ...params, secret: CREDENTIALS.apiSecret }))) {
        return false;
    }
    if (!keyName) {
        return headers['x-api-keypair-sign'] === undefined;
    }
    const key = CLIENT_KEYS[keyName];
    const verdict = new RequestKeypair().verify({
        publicKeys: [{ fingerprint: key.fingerprint, algorithm: key.algorithm, publicKey: key.publicKeySpkiPem, status: 'active' }],
        keypairSign: headers['x-api-keypair-sign'],
        keypairId: headers['x-api-keypair-id'],
        signVersion: 2,
        nonce: headers['x-api-nonce'],
        message: () => apiSign.keypairMessage({ ...params, apiKey: CREDENTIALS.apiKey }),
    });

    return verdict.ok === true;
}

const ordered = headers => Object.fromEntries(HEADER_ORDER.filter(name => name in headers).map(name => [name, headers[name]]));

function fullCase(spec) {
    const request = { ...CREATE_ADDRESS, ...spec.request };
    const headers = authenticationHeaders(request, spec.key);
    if (!gatewayAccepts(request, headers, spec.key)) {
        throw new Error(`${spec.name}: the gateway's own checks refuse the headers`);
    }
    const randomSignature = spec.key && CLIENT_KEYS[spec.key].algorithm === 'p-256';
    const expectedHeaders = ordered(headers);
    if (randomSignature) {
        expectedHeaders['x-api-keypair-sign'] = null;
    }

    return {
        name: spec.name,
        description: spec.description,
        key: spec.key || null,
        request,
        expected: {
            headers: expectedHeaders,
            keypairSignedStringBase64: spec.key ? b64(utf8(apiSign.keypairMessage({ ...signParams(request), apiKey: CREDENTIALS.apiKey }))) : null,
            keypairSignature: !spec.key ? 'none' : randomSignature ? 'verify' : 'exact',
        },
    };
}

function buildFull() {
    const specs = [
        { name: 'legacy_get_list_vaults', description: 'An API key without a key pair: HMAC v2 with a nonce, no key-pair headers.', request: LIST_VAULTS },
        { name: 'legacy_post_create_address', description: 'POST with a body, no key pair.', request: {} },
        { name: 'legacy_without_api_version', description: 'No x-api-version: the header is left out and its line in the signed string is empty.', request: { ...LIST_VAULTS, apiVersion: '' } },
        { name: 'ed25519_get_signing_keys', description: 'The signing-keys check, signed with an Ed25519 key pair.', key: 'ed25519', request: { ...LIST_VAULTS, path: '/api-keys/current/signing-keys', query: '' } },
        { name: 'ed25519_post_create_address', description: 'POST with a body, signed with an Ed25519 key pair. Ed25519 is deterministic, so the signature is exact.', key: 'ed25519', request: {} },
        {
            name: 'ed25519_unicode_body',
            description: 'A non-ASCII body: both signatures cover its UTF-8 bytes.',
            key: 'ed25519',
            request: { body: '{"data":{"item":{"label":"Сметка ✓ 東京","vaultAccountId":"6630f1c2a9e4b5d7c8e9f0e2"}}}' },
        },
        { name: 'p256_post_create_address', description: 'POST signed with a P-256 key pair: ECDSA is random, so the runner signs and then verifies (DER, SHA-256) instead of comparing.', key: 'p256', request: {} },
        { name: 'p256_get_list_vaults', description: 'GET signed with a P-256 key pair.', key: 'p256', request: LIST_VAULTS },
    ];

    return {
        format: 'vaultody request authentication headers, v1',
        warning: WARNING,
        source: sourceOf('generate-gateway-vectors.js'),
        wire: {
            headers: 'x-api-key, x-api-passphrase, x-api-timestamp, x-api-sign (HMAC v2, see request-hmac-v2.json), x-api-sign-version: 2, x-api-nonce, x-api-version when not empty, and with a key pair x-api-keypair-sign (base64 of the signature over the key-pair string: Ed25519 the raw 64 bytes, P-256 ECDSA SHA-256 in DER) and x-api-keypair-id (the key\'s fingerprint, see request-keypair-v1.json)',
            keypairSignedString: 'the tag "vaultody-request-keypair-v1", the x-api-key, then the HMAC v2 fields in the same order, one per line (as the gateway builds it)',
            checks: 'every case was accepted by the gateway\'s own HMAC and key-pair checks before it was written',
        },
        caseFormat: {
            credentials: 'the API key, secret and passphrase every case signs with',
            keys: 'the key pairs, as in request-keypair-v1.json',
            key: 'the key pair the request is signed with, or null for an API key without one',
            request: 'the fixed clock (timestamp) and nonce and the request fields',
            expected: 'headers: every authentication header, in this order; x-api-keypair-sign is null when keypairSignature is "verify" (P-256): sign, then verify it over keypairSignedStringBase64 with the key',
        },
        credentials: CREDENTIALS,
        keys: Object.fromEntries(Object.entries(CLIENT_KEYS).map(([name, { privateKey, ...record }]) => [name, record])),
        cases: specs.map(fullCase),
    };
}

// ---------------------------------------------------------------------------------------------------
// Signed responses
// ---------------------------------------------------------------------------------------------------

const RESPONSE_CASES = Object.fromEntries(RESPONSE_VECTORS.cases.map(vector => [vector.name, vector]));
const CERTS = {
    current: RESPONSE_CASES.valid_current_root.signed.headers['x-api-response-cert'],
    next: RESPONSE_CASES.valid_next_root.signed.headers['x-api-response-cert'],
};
const ROOT_IDS = { current: RESPONSE_VECTORS.keys.roots.current.rootId, next: RESPONSE_VECTORS.keys.roots.next.rootId };
const POD_KEY = crypto.createPrivateKey(RESPONSE_VECTORS.keys.podKeys.pod1.privateKeyPkcs8Pem);
const SIGNED_AT = RESPONSE_CASES.valid_current_root.signed.ts;
const NOW = RESPONSE_CASES.valid_current_root.verify.now;
const PINNED_ROOTS = ['current', 'next'];
const ROOT_DER = name => Buffer.from(RESPONSE_VECTORS.keys.roots[name].publicKeySpkiDerBase64, 'base64');

for (const [root, header] of Object.entries(CERTS)) {
    const cert = Buffer.from(header.split('.')[0], 'base64').toString('ascii');
    if (cert.split('\n')[1] !== ROOT_IDS[root] || cert.split('\n')[2] !== RESPONSE_VECTORS.keys.podKeys.pod1.publicKeyBase64) {
        throw new Error(`the ${root} certificate in v1.json is not pod key 1 under that root`);
    }
}

/**
 * The four response-signing headers the gateway would send for this response, made with its own
 * responseSigning helpers and the test pod key, under a certificate from v1.json.
 */
function signResponse({ request, status, body, root = 'current', ts = SIGNED_AT }) {
    const message = rs.buildMessage({
        ts,
        status,
        method: request.method,
        path: request.path,
        query: request.query,
        bodyHash: rs.hashRequestBody(Buffer.from(request.bodyBase64, 'base64')),
        requestSign: request.apiSign,
        keypairSign: request.keypairSign,
        body,
    });

    return rs.responseHeaders({ ts, signature: rs.signMessage(POD_KEY, message), certHeader: CERTS[root] });
}

/** The gateway's reference verifier on what the client receives, so no vector disagrees with it. */
function referenceVerdict(request, response, now) {
    return reference.verifyResponse({
        request: { ...request, body: Buffer.from(request.bodyBase64, 'base64') },
        response: { status: response.status, headers: response.headers, body: Buffer.from(response.bodyBase64, 'base64') },
        roots: PINNED_ROOTS.map(ROOT_DER),
        now,
        skewSeconds: RESPONSE_VECTORS.verifier.skewSeconds,
    });
}

const SIGN_HEADERS = Object.values(rs.HEADER);
const signatureVerdict = (headers, verdict) => {
    if (SIGN_HEADERS.every(name => headers[name] === undefined)) {
        return 'absent';
    }

    return verdict.ok ? 'verified' : { error: verdict.reason };
};

/** A request record as the response vectors hold it. */
function requestRecord(request, headers) {
    return {
        method: request.method,
        path: request.path,
        query: request.query,
        bodyBase64: b64(utf8(request.body)),
        apiSign: headers['x-api-sign'],
        keypairSign: headers['x-api-keypair-sign'] || '',
    };
}

// ---------------------------------------------------------------------------------------------------
// GET /api-keys/current/signing-keys
// ---------------------------------------------------------------------------------------------------

const SIGNING_KEYS_REQUEST = { ...LIST_VAULTS, path: '/api-keys/current/signing-keys', query: '' };
const SIGNING_KEYS_HEADERS = authenticationHeaders(SIGNING_KEYS_REQUEST, 'ed25519');
const OUR_FINGERPRINT = CLIENT_KEYS.ed25519.fingerprint;
const OTHER_ED25519 = KEYPAIR_VECTORS.keys.ed25519_other;

const keyItem = (record, status = 'active') => ({
    fingerprint: record.fingerprint,
    algorithm: record.algorithm,
    status,
    createdTimestamp: 1795000000,
    approvedTimestamp: 1795000300,
});

const signingKeysBody = items => json({
    apiVersion: API_VERSION,
    requestId: '6630f1c2a9e4b5d7c8e9f0e1',
    data: { limit: 2, offset: 0, total: items.length, items },
});

function signingKeysCase(spec) {
    const request = requestRecord(SIGNING_KEYS_REQUEST, SIGNING_KEYS_HEADERS);
    const status = spec.status || 200;
    const signedBody = spec.body || signingKeysBody(spec.items || []);
    const signedRequest = spec.signedRequest ? spec.signedRequest(request) : request;
    let headers = spec.unsigned ? {} : signResponse({ request: signedRequest, status, body: signedBody, root: spec.root });
    if (spec.headers) {
        headers = spec.headers(headers);
    }
    const response = { status, headers, bodyBase64: b64(spec.receivedBody || signedBody) };
    const verdict = referenceVerdict(request, response, NOW);
    const signature = signatureVerdict(headers, verdict);
    if (JSON.stringify(signature) !== JSON.stringify(spec.signature || 'verified')) {
        throw new Error(`${spec.name}: the reference verifier says ${JSON.stringify(signature)}`);
    }

    return {
        name: spec.name,
        description: spec.description,
        fingerprint: OUR_FINGERPRINT,
        request,
        response,
        now: NOW,
        expected: { signature, ...spec.expected },
    };
}

function buildSigningKeys() {
    const p256 = KEYPAIR_VECTORS.keys.p256;
    const specs = [
        { name: 'active', description: 'The key that signed the request is listed and active.', items: [keyItem(CLIENT_KEYS.ed25519)], expected: { outcome: 'active' } },
        {
            name: 'active_second_of_two',
            description: 'Two keys during a rotation; ours is the second.',
            items: [keyItem(p256), keyItem(CLIENT_KEYS.ed25519)],
            expected: { outcome: 'active' },
        },
        { name: 'next_root', description: 'The answer is certified by the next root (after a root rotation).', root: 'next', items: [keyItem(CLIENT_KEYS.ed25519)], expected: { outcome: 'active' } },
        { name: 'not_listed_empty', description: 'The API key has no signing key.', items: [], expected: { outcome: 'not_listed' } },
        {
            name: 'not_listed_other_keys',
            description: 'The API key holds keys, none of them ours: the registered key was replaced on its way to Vaultody.',
            items: [keyItem(p256), keyItem(OTHER_ED25519)],
            expected: { outcome: 'not_listed' },
        },
        { name: 'inactive', description: 'Ours is listed with a status other than active.', items: [keyItem(CLIENT_KEYS.ed25519, 'revoked')], expected: { outcome: 'inactive' } },
        {
            name: 'refused',
            description: 'A 401 (no apiVersion in a 401 body): the outcome is refused, with the error code.',
            status: 401,
            body: json({ requestId: '6630f1c2a9e4b5d7c8e9f0e3', error: { code: 'invalid_api_sign', message: 'The provided API sign is invalid, please check our Authorization section in our Documentation.' } }),
            expected: { outcome: 'refused', code: 'invalid_api_sign' },
        },
        {
            name: 'unsigned_active',
            description: 'No signature headers at all (response signing not switched on): verified only when the caller accepts unsigned answers, and then reported as unsigned.',
            unsigned: true,
            items: [keyItem(CLIENT_KEYS.ed25519)],
            signature: 'absent',
            expected: { outcome: 'active' },
        },
        {
            name: 'tampered_list',
            description: 'The answer listed another key and was changed on the way to list ours: refused before it is read.',
            items: [keyItem(OTHER_ED25519)],
            receivedBody: signingKeysBody([keyItem(CLIENT_KEYS.ed25519)]),
            signature: { error: 'invalid' },
            expected: {},
        },
        {
            name: 'keypair_sign_stripped',
            description: 'The gateway received the request without x-api-keypair-sign (stripped on the way) and signed its answer over that: the answer does not match the request the client sent.',
            items: [keyItem(CLIENT_KEYS.ed25519)],
            signedRequest: request => ({ ...request, keypairSign: '' }),
            signature: { error: 'invalid' },
            expected: {},
        },
        {
            name: 'partly_stripped',
            description: 'One of the four signature headers removed: never treated as unsigned.',
            items: [keyItem(CLIENT_KEYS.ed25519)],
            headers: headers => {
                const copy = { ...headers };
                delete copy['x-api-response-cert'];

                return copy;
            },
            signature: { error: 'missing' },
            expected: {},
        },
    ];

    return {
        format: 'vaultody signed answers of GET /api-keys/current/signing-keys, v1',
        warning: WARNING,
        source: sourceOf('generate-gateway-vectors.js', { responses: 'signed with the gateway\'s response-signing helpers, pod key 1 and the certificates of v1.json; every verdict checked with its reference verifier' }),
        rules: {
            order: 'Verify the response first, over the request as sent (x-api-sign and x-api-keypair-sign included), with unsigned answers accepted (requireResponseSignature false). Only a response that passes is read.',
            outcome: '401 or 403: refused, with error.code. 200: data.items is the list; active when an item has our fingerprint and status "active", inactive when it has our fingerprint and another status, not_listed otherwise. Any other status or shape is an unexpected answer.',
        },
        caseFormat: {
            fingerprint: 'the fingerprint of the key the client signed with',
            request: 'the request as sent (as in v1.json)',
            response: 'the response as received',
            now: 'Unix seconds',
            expected: 'signature: verified | absent | { error: reason }; outcome (and code) only when the signature check passed',
            roots: 'the roots to pin are v1.json keys.roots current and next',
        },
        pinnedRoots: PINNED_ROOTS,
        cases: specs.map(signingKeysCase),
    };
}

// ---------------------------------------------------------------------------------------------------
// GET /vaults/{networkType} and the vault xpub pins
// ---------------------------------------------------------------------------------------------------

// TEST-ONLY xpubs: BIP32 test vector 1 and synthetic EdDSA keys, as in the address vectors
// (address-v1.json).
const XPUBS = Object.freeze({
    ecdsa1: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
    ecdsa2: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
    eddsa1: 'xpub661MyMwAqRbcF7h9JXx6VX3d8mX4C8QH6cefjAYGCRSHMYwa9YgFeobgfZ93e4dCrsQTxU2dAn4KBPxaNjRvT4UswSmSkWpBP9gn6LSzRGH',
    eddsa2: 'xpub69Rk31mwbQ17xYsnUdygwUpojVEsaDxi7RPQWZcgib6NTNTZSTQHCsMabp5KQQZZ2kP2kpVEt6DPMJ2LLTBJbSCuQv9DZ8bJj4qSvScffQF',
});

const shortHash = xpub => crypto.createHash('sha256').update(xpub, 'utf8').digest('hex').slice(0, 16);

const vaultItem = (id, mpcKeys, extra = {}) => ({
    backuped: true,
    changeAddressesCount: 0,
    color: '#2684FF',
    createdTimestamp: 1725458109,
    depositAddressesCount: 3,
    id,
    name: `Vault ${id.slice(-2)}`,
    type: 'main',
    ...(mpcKeys === undefined ? {} : { mpcKeys }),
    ...extra,
});
const keysOf = (ecdsa, eddsa) => [
    ...(ecdsa ? [{ algorithm: 'ECDSA', xpub: XPUBS[ecdsa] }] : []),
    ...(eddsa ? [{ algorithm: 'EDDSA', xpub: XPUBS[eddsa] }] : []),
];

const LIST_VAULTS_HEADERS = authenticationHeaders(LIST_VAULTS, null);
const listVaultsBody = (items, requestId = '6630f1c2a9e4b5d7c8e9f0f1') => json({ apiVersion: API_VERSION, requestId, data: { limit: 50, hasMore: false, items } });

/**
 * A pin as stored: the xpub of each algorithm, verified when a signed answer showed it (with the root
 * and the response time as evidence), unverified when only an unsigned one did (trust on first use).
 */
const pin = (vaultId, ecdsa, eddsa, { status = 'verified', firstSeenAt = NOW, verifiedAt, root = 'current', ts = SIGNED_AT, type = 'main' } = {}) => ({
    vaultId,
    type,
    keys: { ECDSA: ecdsa ? XPUBS[ecdsa] : null, EDDSA: eddsa ? XPUBS[eddsa] : null },
    status,
    firstSeenAt,
    verifiedAt: status === 'verified' ? (verifiedAt === undefined ? firstSeenAt : verifiedAt) : null,
    verification: status === 'verified' ? { rootId: ROOT_IDS[root], timestamp: ts } : null,
});

/**
 * A pin given in the client's configuration: the vault, its type and its xpubs, nothing else. It counts as
 * verified and is never written to the store.
 */
const configured = (vaultId, ecdsa, eddsa, { type = 'main' } = {}) => ({
    vaultId,
    type,
    keys: { ECDSA: ecdsa ? XPUBS[ecdsa] : null, EDDSA: eddsa ? XPUBS[eddsa] : null },
});

function pinsStep(spec, index, caseName) {
    const request = requestRecord(LIST_VAULTS, LIST_VAULTS_HEADERS);
    const signedBody = listVaultsBody(spec.items, `6630f1c2a9e4b5d7c8e9f${String(index).padStart(3, '0')}`);
    const ts = spec.ts || SIGNED_AT;
    let headers = spec.unsigned ? {} : signResponse({ request, status: 200, body: signedBody, root: spec.root, ts });
    if (spec.headers) {
        headers = spec.headers(headers);
    }
    const response = { status: 200, headers, bodyBase64: b64(spec.receivedBody ? listVaultsBody(spec.receivedBody, `6630f1c2a9e4b5d7c8e9f${String(index).padStart(3, '0')}`) : signedBody) };
    const now = spec.now || NOW;
    const signature = signatureVerdict(headers, referenceVerdict(request, response, now));
    if (JSON.stringify(signature) !== JSON.stringify(spec.signature || (spec.unsigned ? 'absent' : 'verified'))) {
        throw new Error(`${caseName} step ${index}: the reference verifier says ${JSON.stringify(signature)}`);
    }

    return { request, response, now, expected: { signature, ...spec.expected } };
}

function pinsCase(spec) {
    return {
        name: spec.name,
        description: spec.description,
        initialPins: spec.initialPins || [],
        configuredPins: spec.configuredPins || [],
        steps: spec.steps.map((step, index) => pinsStep(step, index + 1, spec.name)),
    };
}

function buildVaultKeyPins() {
    const A = VAULT_A;
    const B = VAULT_B;
    const alarm = (vaultId, algorithm, pinned, seen) => ({
        vaultId,
        algorithm,
        reason: seen ? 'xpub_changed' : 'xpub_missing',
        pinned: shortHash(XPUBS[pinned]),
        seen: seen ? shortHash(XPUBS[seen]) : null,
    });
    const specs = [
        {
            name: 'first_sight_signed',
            description: 'A vault seen for the first time in a signed answer is pinned as verified, with the root and the response time as evidence.',
            steps: [{ items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'pinned' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] } }],
        },
        {
            name: 'first_sight_unsigned',
            description: 'A vault seen for the first time in an unsigned answer (prod does not sign yet) is pinned as unverified: trust on first use.',
            steps: [{
                unsigned: true,
                items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))],
                expected: { outcomes: [{ vaultId: A, outcome: 'pinned' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1', { status: 'unverified' })] },
            }],
        },
        {
            name: 'unverified_confirmed_by_signed',
            description: 'An unverified pin is confirmed by a later signed answer with the same xpubs: it becomes verified, and keeps the time it was first seen.',
            steps: [
                { unsigned: true, now: NOW - 60, items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'pinned' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1', { status: 'unverified', firstSeenAt: NOW - 60 })] } },
                { items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'upgraded' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1', { firstSeenAt: NOW - 60, verifiedAt: NOW })] } },
            ],
        },
        {
            name: 'unverified_contradicted_by_signed',
            description: 'A signed answer shows another xpub than the unverified pin: the alarm. The pin stays as it was and the answer is refused.',
            steps: [
                { unsigned: true, items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'pinned' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1', { status: 'unverified' })] } },
                { items: [vaultItem(A, keysOf('ecdsa2', 'eddsa1'))], expected: { alarms: [alarm(A, 'ECDSA', 'ecdsa1', 'ecdsa2')], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1', { status: 'unverified' })] } },
            ],
        },
        {
            name: 'verified_then_unsigned_same',
            description: 'An unsigned answer with the same xpubs leaves a verified pin verified.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1')],
            steps: [{ unsigned: true, items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'unchanged' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] } }],
        },
        {
            name: 'verified_then_changed_unsigned',
            description: 'An unsigned answer with another ECDSA xpub: the alarm.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1')],
            steps: [{ unsigned: true, items: [vaultItem(A, keysOf('ecdsa2', 'eddsa1'))], expected: { alarms: [alarm(A, 'ECDSA', 'ecdsa1', 'ecdsa2')], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] } }],
        },
        {
            name: 'verified_then_changed_signed',
            description: 'Even a signed answer never re-pins a changed xpub: the alarm, and only an explicit replace (support, CLI) changes a pin.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1')],
            steps: [{ items: [vaultItem(A, keysOf('ecdsa1', 'eddsa2'))], expected: { alarms: [alarm(A, 'EDDSA', 'eddsa1', 'eddsa2')], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] } }],
        },
        {
            name: 'pinned_algorithm_disappears',
            description: 'A pinned algorithm missing from the answer is the alarm too.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1')],
            steps: [{ items: [vaultItem(A, keysOf('ecdsa1', null))], expected: { alarms: [alarm(A, 'EDDSA', 'eddsa1', null)], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] } }],
        },
        {
            name: 'two_algorithms_changed',
            description: 'Both xpubs changed: one alarm entry per algorithm, ECDSA first.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1')],
            steps: [{ items: [vaultItem(A, keysOf('ecdsa2', 'eddsa2'))], expected: { alarms: [alarm(A, 'ECDSA', 'ecdsa1', 'ecdsa2'), alarm(A, 'EDDSA', 'eddsa1', 'eddsa2')], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] } }],
        },
        {
            name: 'alarm_refuses_whole_answer',
            description: 'One vault alarms and another is new: the whole answer is refused, so the new vault is not pinned either.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1')],
            steps: [{
                items: [vaultItem(A, keysOf('ecdsa2', 'eddsa1')), vaultItem(B, keysOf('ecdsa1', null))],
                expected: { alarms: [alarm(A, 'ECDSA', 'ecdsa1', 'ecdsa2')], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] },
            }],
        },
        {
            name: 'smart_vault_not_verifiable',
            description: 'A vault without MPC keys (SMART or AUTOMATION) has nothing to pin: not verifiable, never verified.',
            steps: [{ items: [vaultItem(VAULT_SMART, [])], expected: { outcomes: [{ vaultId: VAULT_SMART, outcome: 'not_verifiable' }], pinsAfter: [] } }],
        },
        {
            name: 'smart_vault_without_mpc_keys_field',
            description: 'mpcKeys absent altogether (the field is hidden until the SDK ships): not verifiable as well.',
            steps: [{ items: [vaultItem(VAULT_SMART, undefined)], expected: { outcomes: [{ vaultId: VAULT_SMART, outcome: 'not_verifiable' }], pinsAfter: [] } }],
        },
        {
            name: 'other_vaults_untouched',
            description: 'A page that does not list a pinned vault leaves its pin as it is: lists are paged.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1'), pin(B, 'ecdsa2', null)],
            steps: [{ items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'unchanged' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1'), pin(B, 'ecdsa2', null)] } }],
        },
        {
            name: 'several_vaults_first_sight',
            description: 'Several new vaults in one signed answer are all pinned, in the order of the answer.',
            steps: [{
                items: [vaultItem(B, keysOf('ecdsa2', null)), vaultItem(A, keysOf('ecdsa1', 'eddsa1')), vaultItem(VAULT_SMART, [])],
                expected: {
                    outcomes: [{ vaultId: B, outcome: 'pinned' }, { vaultId: A, outcome: 'pinned' }, { vaultId: VAULT_SMART, outcome: 'not_verifiable' }],
                    pinsAfter: [pin(A, 'ecdsa1', 'eddsa1'), pin(B, 'ecdsa2', null)],
                },
            }],
        },
        {
            name: 'next_root',
            description: 'A signed answer certified by the next root pins as verified, with that root as evidence.',
            steps: [{ root: 'next', items: [vaultItem(A, keysOf('ecdsa1', null))], expected: { outcomes: [{ vaultId: A, outcome: 'pinned' }], pinsAfter: [pin(A, 'ecdsa1', null, { root: 'next' })] } }],
        },
        {
            name: 'algorithm_names_case_insensitive',
            description: 'mpcKeys algorithm names are read in uppercase, as the API compares them.',
            steps: [{
                items: [vaultItem(A, [{ algorithm: 'ecdsa', xpub: XPUBS.ecdsa1 }, { algorithm: 'EdDSA', xpub: XPUBS.eddsa1 }])],
                expected: { outcomes: [{ vaultId: A, outcome: 'pinned' }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1')] },
            }],
        },
        {
            name: 'first_key_of_an_algorithm_wins',
            description: 'Two entries for one algorithm: the first counts, as on the server (mpcKeys.find); unknown algorithms are ignored.',
            steps: [{
                items: [vaultItem(A, [{ algorithm: 'ECDSA', xpub: XPUBS.ecdsa1 }, { algorithm: 'ECDSA', xpub: XPUBS.ecdsa2 }, { algorithm: 'SCHNORR', xpub: XPUBS.eddsa2 }])],
                expected: { outcomes: [{ vaultId: A, outcome: 'pinned' }], pinsAfter: [pin(A, 'ecdsa1', null)] },
            }],
        },
        {
            name: 'tampered_signed_answer',
            description: 'A signed answer changed on the way (another xpub): refused by the signature check before any pin is looked at.',
            steps: [{ items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], receivedBody: [vaultItem(A, keysOf('ecdsa2', 'eddsa1'))], signature: { error: 'invalid' }, expected: { pinsAfter: [] } }],
        },
        {
            name: 'signature_partly_stripped',
            description: 'A signed answer with one signature header removed is never treated as unsigned: refused, no pin.',
            steps: [{
                items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))],
                headers: headers => {
                    const copy = { ...headers };
                    delete copy['x-api-response-sign'];

                    return copy;
                },
                signature: { error: 'missing' },
                expected: { pinsAfter: [] },
            }],
        },
        {
            name: 'pinned_vault_gains_algorithm',
            description: 'A pinned vault that gains an algorithm it did not have: refused (xpub_added), fail closed. A legitimate change is confirmed by the client and re-pinned (the command line, or the store\'s replace).',
            initialPins: [pin(A, 'ecdsa1', null)],
            steps: [{
                items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))],
                expected: { alarms: [{ vaultId: A, algorithm: 'EDDSA', reason: 'xpub_added', pinned: null, seen: shortHash(XPUBS.eddsa1) }], pinsAfter: [pin(A, 'ecdsa1', null)] },
            }],
        },
        {
            name: 'vault_type_changed',
            description: 'A vault pinned as a test vault is listed as a main vault: refused (type_changed), fail closed, until the client re-pins it.',
            initialPins: [pin(A, 'ecdsa1', 'eddsa1', { type: 'test' })],
            steps: [{
                items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))],
                expected: { alarms: [{ vaultId: A, algorithm: null, reason: 'type_changed', pinned: null, seen: null }], pinsAfter: [pin(A, 'ecdsa1', 'eddsa1', { type: 'test' })] },
            }],
        },
        {
            name: 'configured_pin_counts_as_verified',
            description: 'A pin given in configuration counts as verified, whether the answer is signed or not: unchanged, and never written to the store.',
            configuredPins: [configured(A, 'ecdsa1', 'eddsa1')],
            steps: [
                { unsigned: true, items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'unchanged' }], pinsAfter: [] } },
                { items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'unchanged' }], pinsAfter: [] } },
            ],
        },
        {
            name: 'configured_pin_changed_signed',
            description: 'A signed answer with another xpub than the configured pin: the alarm, exactly as for a stored pin.',
            configuredPins: [configured(A, 'ecdsa1', 'eddsa1')],
            steps: [{ items: [vaultItem(A, keysOf('ecdsa2', 'eddsa1'))], expected: { alarms: [alarm(A, 'ECDSA', 'ecdsa1', 'ecdsa2')], pinsAfter: [] } }],
        },
        {
            name: 'configured_pin_changed_unsigned',
            description: 'An unsigned answer with another xpub than the configured pin: the alarm as well.',
            configuredPins: [configured(A, 'ecdsa1', 'eddsa1')],
            steps: [{ unsigned: true, items: [vaultItem(A, keysOf('ecdsa1', 'eddsa2'))], expected: { alarms: [alarm(A, 'EDDSA', 'eddsa1', 'eddsa2')], pinsAfter: [] } }],
        },
        {
            name: 'configured_pin_gains_algorithm',
            description: 'A configured vault that gains an algorithm: refused (xpub_added), as for a stored pin.',
            configuredPins: [configured(A, 'ecdsa1', null)],
            steps: [{
                items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))],
                expected: { alarms: [{ vaultId: A, algorithm: 'EDDSA', reason: 'xpub_added', pinned: null, seen: shortHash(XPUBS.eddsa1) }], pinsAfter: [] },
            }],
        },
        {
            name: 'configured_pin_replaces_stored_pin',
            description: 'The configured pin takes the place of the stored pin of the same vault: the answer is compared with the configured xpubs only, and the stored pin is neither read nor changed.',
            initialPins: [pin(A, 'ecdsa2', 'eddsa1', { status: 'unverified' })],
            configuredPins: [configured(A, 'ecdsa1', 'eddsa1')],
            steps: [
                { items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1'))], expected: { outcomes: [{ vaultId: A, outcome: 'unchanged' }], pinsAfter: [pin(A, 'ecdsa2', 'eddsa1', { status: 'unverified' })] } },
                { unsigned: true, items: [vaultItem(A, keysOf('ecdsa2', 'eddsa1'))], expected: { alarms: [alarm(A, 'ECDSA', 'ecdsa1', 'ecdsa2')], pinsAfter: [pin(A, 'ecdsa2', 'eddsa1', { status: 'unverified' })] } },
            ],
        },
        {
            name: 'configured_and_stored_pins_together',
            description: 'Vaults not in the configuration are pinned in the store as usual, next to the configured ones.',
            configuredPins: [configured(A, 'ecdsa1', 'eddsa1')],
            steps: [{
                items: [vaultItem(A, keysOf('ecdsa1', 'eddsa1')), vaultItem(B, keysOf('ecdsa2', null))],
                expected: { outcomes: [{ vaultId: A, outcome: 'unchanged' }, { vaultId: B, outcome: 'pinned' }], pinsAfter: [pin(B, 'ecdsa2', null)] },
            }],
        },
        {
            name: 'configured_pin_alarm_refuses_whole_answer',
            description: 'A configured vault alarms and another is new: the whole answer is refused, so the new vault is not pinned either.',
            configuredPins: [configured(A, 'ecdsa1', 'eddsa1')],
            steps: [{
                items: [vaultItem(A, keysOf('ecdsa2', 'eddsa1')), vaultItem(B, keysOf('ecdsa2', null))],
                expected: { alarms: [alarm(A, 'ECDSA', 'ecdsa1', 'ecdsa2')], pinsAfter: [] },
            }],
        },
    ];

    const addressChecks = [
        { name: 'verified_pin_match', description: 'The address derives from a verified pin.', pin: 'verified', vaultHasKeys: true, pathFields: true, derivation: 'match', expected: { status: 'verified' } },
        { name: 'unverified_pin_match', description: 'The address derives from an unverified (trust on first use) pin: reported as unverified, never verified.', pin: 'unverified', vaultHasKeys: true, pathFields: true, derivation: 'match', expected: { status: 'unverified' } },
        { name: 'smart_vault', description: 'A vault without MPC keys: not verifiable.', pin: null, vaultHasKeys: false, pathFields: false, derivation: null, expected: { status: 'not_verifiable' } },
        { name: 'no_path_fields', description: 'An address without accountIndex, isChange and addressIndex (an old row): not verifiable.', pin: 'verified', vaultHasKeys: true, pathFields: false, derivation: null, expected: { status: 'not_verifiable' } },
        { name: 'mismatch_verified', description: 'The address does not derive from the verified pin: refused.', pin: 'verified', vaultHasKeys: true, pathFields: true, derivation: 'mismatch', expected: { error: 'mismatch' } },
        { name: 'mismatch_unverified', description: 'Not deriving from an unverified pin is refused just the same.', pin: 'unverified', vaultHasKeys: true, pathFields: true, derivation: 'mismatch', expected: { error: 'mismatch' } },
        { name: 'configured_pin_match', description: 'The address derives from a pin given in configuration: verified.', pin: 'configured', vaultHasKeys: true, pathFields: true, derivation: 'match', expected: { status: 'verified' } },
        { name: 'configured_pin_mismatch', description: 'Not deriving from a configured pin is refused.', pin: 'configured', vaultHasKeys: true, pathFields: true, derivation: 'mismatch', expected: { error: 'mismatch' } },
        // requireAddressPaths: once the derivation paths are public, generateDepositAddress must carry one.
        { name: 'generate_no_path_required', description: 'requireAddressPaths on: generateDepositAddress answers an address without its path for a vault with MPC keys, on a chain the SDK can derive: refused.', pin: 'verified', vaultHasKeys: true, pathFields: false, derivation: null, pathRequired: { requireAddressPaths: true, operationId: 'generateDepositAddress', chainKnown: true }, expected: { error: 'path_missing' } },
        { name: 'generate_no_path_unverified_pin', description: 'The same with an unverified pin: refused just the same.', pin: 'unverified', vaultHasKeys: true, pathFields: false, derivation: null, pathRequired: { requireAddressPaths: true, operationId: 'generateDepositAddress', chainKnown: true }, expected: { error: 'path_missing' } },
        { name: 'generate_no_path_smart_vault', description: 'requireAddressPaths on, a vault without MPC keys (SMART): nothing to derive, not verifiable.', pin: null, vaultHasKeys: false, pathFields: false, derivation: null, pathRequired: { requireAddressPaths: true, operationId: 'generateDepositAddress', chainKnown: true }, expected: { status: 'not_verifiable' } },
        { name: 'generate_no_path_unknown_chain', description: 'requireAddressPaths on, a chain the SDK can\'t derive: not verifiable.', pin: 'verified', vaultHasKeys: true, pathFields: false, derivation: null, pathRequired: { requireAddressPaths: true, operationId: 'generateDepositAddress', chainKnown: false }, expected: { status: 'not_verifiable' } },
        { name: 'list_no_path_required', description: 'requireAddressPaths on, an address list: its older rows may have no path, so not verifiable.', pin: 'verified', vaultHasKeys: true, pathFields: false, derivation: null, pathRequired: { requireAddressPaths: true, operationId: 'listAddressesByVaultAccountId', chainKnown: true }, expected: { status: 'not_verifiable' } },
        { name: 'add_asset_no_path_required', description: 'requireAddressPaths on, addAssetToVaultAccount: it may answer an older address, so not verifiable.', pin: 'verified', vaultHasKeys: true, pathFields: false, derivation: null, pathRequired: { requireAddressPaths: true, operationId: 'addAssetToVaultAccount', chainKnown: true }, expected: { status: 'not_verifiable' } },
        { name: 'generate_no_path_not_required', description: 'requireAddressPaths off (the default while the paths are hidden): not verifiable.', pin: 'verified', vaultHasKeys: true, pathFields: false, derivation: null, pathRequired: { requireAddressPaths: false, operationId: 'generateDepositAddress', chainKnown: true }, expected: { status: 'not_verifiable' } },
        { name: 'generate_with_path_required', description: 'requireAddressPaths on and the path given: checked as always.', pin: 'verified', vaultHasKeys: true, pathFields: true, derivation: 'match', pathRequired: { requireAddressPaths: true, operationId: 'generateDepositAddress', chainKnown: true }, expected: { status: 'verified' } },
    ];

    return {
        format: 'vaultody vault xpub pins, v1',
        warning: WARNING,
        source: sourceOf('generate-gateway-vectors.js', { responses: 'signed with the gateway\'s response-signing helpers, pod key 1 and the certificates of v1.json; every signature verdict checked with its reference verifier' }),
        model: {
            pin: '{ vaultId, type: "main"|"test", keys: { ECDSA: xpub|null, EDDSA: xpub|null }, status: "verified"|"unverified", firstSeenAt: Unix seconds, verifiedAt: Unix seconds|null, verification: { rootId, timestamp }|null }',
            configuredPin: '{ vaultId, type: "main"|"test", keys: { ECDSA: xpub|null, EDDSA: xpub|null } }, at least one xpub, no other field: a pin given in the client configuration (Node pinnedVaultKeys, Python pinned_vault_keys, PHP pinnedVaultKeys), for the client\'s API origin',
            status: 'verified: a signed answer (checked against a pinned root) showed these xpubs, or the pin was given in configuration. unverified: only an unsigned answer did, trust on first use; allowed for release candidates while prod does not sign, never reported as verified, and confirmed by the first signed answer that shows the same xpubs.',
            addressCheck: 'verified (derives from a verified or configured pin) | unverified (derives from an unverified pin) | not_verifiable (a vault without MPC keys, such as SMART, or an address without its derivation path) | mismatch or path_missing, which are errors',
            pathRequired: 'An address without its derivation path is path_missing, an error, only when all hold: the client\'s requireAddressPaths is on (Python require_address_paths; its default is the build constant ADDRESS_PATHS_PUBLIC, false while the paths are hidden), the operation is generateDepositAddress, its vault has MPC keys (pinned, or pinned now from the vault lists), and its chain is one the SDK can derive. Lists and addAssetToVaultAccount may answer older rows without a path: not_verifiable.',
            scope: 'pins are kept per API origin, so test and production pins never mix; these cases are all one origin',
        },
        rules: {
            order: 'Verify the answer first (requireResponseSignature false: signed answers must verify, unsigned ones are accepted as unsigned). A refused answer touches no pin.',
            vaults: 'Each item of data.items: id, type and the xpub of each algorithm in mpcKeys (algorithm read in uppercase; the first entry of an algorithm counts; algorithms other than ECDSA and EDDSA are ignored). An item without any such key has nothing to pin and is not_verifiable.',
            outcomes: 'No pin yet: pinned, verified if the answer was signed, else unverified. Same xpubs as the pin: unchanged, except an unverified pin and a signed answer, which is upgraded to verified. A pinned xpub that differs or is missing: an alarm.',
            alarm: 'Any alarm refuses the whole answer: no pin is written or changed, not even for other vaults in it. Each alarm names the vault, the algorithm, the reason (xpub_changed, xpub_missing, xpub_added, type_changed) and the first 16 hex characters of SHA-256 of each xpub (never the xpub itself; null where there is none), ECDSA before EDDSA, then the type, in the order of the answer.',
            refused: 'A pinned vault that gains an algorithm it did not have (xpub_added: pinned null, seen the hash of the new xpub) and a vault whose type changes (type_changed: algorithm, pinned and seen null) are alarms like any other: refused, fail closed. The client confirms a legitimate change out of band and re-pins the vault: the command line (npx @vaultody/sdk vault-keys accept) or the store\'s replace.',
            configured: 'A configured pin counts as verified: its vault\'s status is verified, and an address that derives from it is verified. It is compared with every answer, signed or not, exactly as a stored pin, and any difference is the alarm. It is never written to the store, and the stored pin of the same vault, if any, is neither read nor changed: the configured pin takes its place. Vaults not configured are pinned in the store as usual.',
        },
        caseFormat: {
            initialPins: 'the pins in the store before the first step',
            configuredPins: 'the pins given in configuration for the whole case (configuredPin); pinsAfter never holds them, and the status of a configured vault is verified',
            steps: 'each: the request as sent, the response as received, now, and expected: signature (verified | absent | { error }), outcomes per vault in the order of the answer, or alarms; pinsAfter is every pin after the step, sorted by vaultId',
            addressChecks: 'pin status (verified, unverified, configured, or null), whether the vault has MPC keys, whether the address carries its derivation path, the derivation result, and pathRequired when the case is about it ({ requireAddressPaths, operationId, chainKnown }; absent: requireAddressPaths off) → expected status or error',
            roots: 'the roots to pin are v1.json keys.roots current and next',
        },
        pinnedRoots: PINNED_ROOTS,
        cases: specs.map(spec => {
            const built = pinsCase(spec);
            for (const step of built.steps) {
                step.expected.pinsAfter = [...step.expected.pinsAfter].sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1));
            }

            return built;
        }),
        addressChecks,
    };
}

// ---------------------------------------------------------------------------------------------------
// The error catalogue
// ---------------------------------------------------------------------------------------------------

function buildErrorCatalogue() {
    const openapi = JSON.parse(fs.readFileSync(path.join(ROOT, 'contract', 'openapi.json'), 'utf8'));
    const documented = new Map();
    for (const item of Object.values(openapi.paths)) {
        for (const op of Object.values(item)) {
            if (!op || !op.responses) {
                continue;
            }
            for (const [status, response] of Object.entries(op.responses)) {
                const content = response.content && response.content['application/json'];
                for (const example of Object.values((content && content.examples) || {})) {
                    const code = example.value && example.value.error && example.value.error.code;
                    if (!code) {
                        continue;
                    }
                    const entry = documented.get(code) || { code, status: Number(status), operations: new Set() };
                    if (entry.status !== Number(status)) {
                        throw new Error(`${code} is documented with two statuses`);
                    }
                    entry.operations.add(op.operationId);
                    documented.set(code, entry);
                }
            }
        }
    }

    const codes = new Map([...documented.values()].map(entry => [entry.code, {
        code: entry.code, status: entry.status, documented: true, gateway: false, operations: entry.operations.size,
    }]));
    for (const { key, httpCode } of customErrorResponses) {
        const entry = codes.get(key);
        if (entry) {
            if (entry.status !== httpCode) {
                throw new Error(`${key}: documented as ${entry.status}, the gateway answers ${httpCode}`);
            }
            entry.gateway = true;
        } else {
            codes.set(key, { code: key, status: httpCode, documented: false, gateway: true, operations: 0 });
        }
    }

    return {
        about: 'Every error code an SDK can be expected to map: the ones documented in contract/openapi.json (examples of each operation\'s error responses) and the gateway\'s own error responses, with the HTTP status each comes with. Generated by test-vectors/tools/generate-gateway-vectors.js; test-vectors/envelope-errors-v1.json is built from it.',
        source: { openapi: 'contract/openapi.json', gateway: GATEWAY },
        fields: { documented: 'in the published docs', gateway: 'answered by the gateway itself', operations: 'how many documented operations list it' },
        codes: [...codes.values()].sort((a, b) => a.status - b.status || (a.code < b.code ? -1 : 1)),
    };
}

// ---------------------------------------------------------------------------------------------------

const OUTPUTS = [
    [path.join(VECTORS_DIR, 'request-hmac-v2.json'), buildHmacV2],
    [path.join(VECTORS_DIR, 'request-full-v1.json'), buildFull],
    [path.join(VECTORS_DIR, 'signing-keys-v1.json'), buildSigningKeys],
    [path.join(VECTORS_DIR, 'vault-key-pins-v1.json'), buildVaultKeyPins],
    [path.join(ROOT, 'contract', 'errors.json'), buildErrorCatalogue],
];

let differ = 0;
for (const [file, build] of OUTPUTS) {
    const text = `${JSON.stringify(build(), null, 2)}\n`;
    const relative = path.relative(ROOT, file);
    if (ARGS.check) {
        const current = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
        if (current !== text) {
            differ += 1;
            process.stdout.write(`${relative}: differs\n`);
        } else {
            process.stdout.write(`${relative}: same\n`);
        }
    } else {
        fs.writeFileSync(file, text);
        process.stdout.write(`${relative}: written\n`);
    }
}
process.exitCode = differ === 0 ? 0 : 1;
