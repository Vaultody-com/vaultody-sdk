#!/usr/bin/env node
'use strict';

/**
 * Writes the vector sets that pin SDK behaviour no server code decides, so every language does exactly
 * the same thing:
 *
 *   path-encoding-v1.json     path and query parameters → the exact request target
 *   p1363-der-v1.json         a P-256 signature as IEEE P1363 r||s → DER, as the gateway requires
 *   envelope-errors-v1.json   status, headers and raw body → result kind or typed error (from contract/errors.json)
 *   pagination-v1.json        sequences of pages → the requests made, the items yielded, why it stopped
 *   retry-v1.json             one finished attempt → retry (re-signed or resent), return, fail, or outcome unknown
 *   transport-errors-v1.json  a client library's error → whether the request may have been sent
 *   webhook-v1.json           raw body, headers and secrets → X-Signature verdict
 *   vault-keys-file-v1.json   the pin file: valid and refused files, file modes, the canonical bytes a writer writes
 *   security-events-v1.json   the security events' names and fields, and the entries of the per-answer results
 *   response-mode-v1.json     the client's configuration → the response-signature mode in force; one answer, the
 *                             mode and the latch → accepted, refused, and the latch after
 *
 *   node test-vectors/tools/generate-sdk-vectors.js [--check]
 *
 * Every expected value here is written by hand from the rules recorded in each file (the approved SDK
 * design); nothing is computed by the SDK code it tests. Two inputs are cross-checked against independent
 * implementations: every real P-256 DER signature verifies with node:crypto and, when an openssl binary is
 * on PATH, with openssl; every request target is what a WHATWG URL (fetch) keeps unchanged.
 *
 * ECDSA signatures are random, so a real P-256 case already in p1363-der-v1.json is kept while it still
 * verifies and still has its property; a rerun therefore writes every file byte for byte the same.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const VECTORS_DIR = path.join(ROOT, 'test-vectors');
const CHECK = process.argv.includes('--check');

const b64 = bytes => Buffer.from(bytes).toString('base64');
const utf8 = text => Buffer.from(text, 'utf8');
const hex = bytes => Buffer.from(bytes).toString('hex');
const label = text => crypto.createHash('sha256').update(`vaultody sdk vectors TEST-ONLY ${text}`).digest();
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const previous = name => {
    const file = path.join(VECTORS_DIR, name);

    return fs.existsSync(file) ? readJson(file) : null;
};
const SOURCE = { generator: 'test-vectors/tools/generate-sdk-vectors.js' };

// ---------------------------------------------------------------------------------------------------
// Path and query encoding
// ---------------------------------------------------------------------------------------------------

/** RFC 3986 unreserved characters stay; every other UTF-8 byte becomes %XX with uppercase hex. */
function percentEncode(text) {
    let out = '';
    for (const byte of utf8(text)) {
        const char = String.fromCharCode(byte);
        out += /[A-Za-z0-9\-._~]/.test(char) ? char : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    }

    return out;
}

function pathCase(spec) {
    const base = { name: spec.name, description: spec.description, template: spec.template, pathParams: spec.pathParams, query: spec.query || [] };
    if (spec.error) {
        return { ...base, expected: { error: spec.error } };
    }

    const target = spec.template.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name) => percentEncode(String(spec.pathParams[name])));
    const pairs = base.query.filter(([, value]) => value !== null).map(([name, value]) => `${percentEncode(name)}=${percentEncode(String(value))}`);
    const full = pairs.length === 0 ? target : `${target}?${pairs.join('&')}`;

    // A WHATWG URL (what fetch sends) must leave the target exactly as it is.
    const url = new URL(`https://rest.vaultody.com${full}`);
    if (url.pathname + url.search !== full) {
        throw new Error(`${spec.name}: a URL changes ${full} into ${url.pathname + url.search}`);
    }
    if (spec.target && spec.target !== full) {
        throw new Error(`${spec.name}: expected ${spec.target}, the encoder gives ${full}`);
    }

    return { ...base, expected: { target: full } };
}

function buildPathEncoding() {
    const VAULT = '6630f1c2a9e4b5d7c8e9f0a1';
    const ACCOUNT = '6630f1c2a9e4b5d7c8e9f0e2';
    const specs = [
        {
            name: 'plain_ids',
            description: 'Ids and names made only of unreserved characters are sent as they are.',
            template: '/vaults/{vaultId}/{blockchain}/{network}/addresses',
            pathParams: { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet' },
            target: `/vaults/${VAULT}/bitcoin/mainnet/addresses`,
        },
        {
            name: 'query_in_given_order',
            description: 'Query parameters go in the order given (the operation table\'s), never sorted.',
            template: '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses',
            pathParams: { vaultId: VAULT, vaultAccountId: ACCOUNT },
            query: [['startingAfter', '6630f1c2a9e4b5d7c8e9f0f9'], ['limit', 50], ['blockchain', 'ethereum']],
            target: `/vaults/${VAULT}/vault-accounts/${ACCOUNT}/list-addresses?startingAfter=6630f1c2a9e4b5d7c8e9f0f9&limit=50&blockchain=ethereum`,
        },
        {
            name: 'boolean_and_integer_query',
            description: 'Booleans are "true" and "false", integers plain decimals.',
            template: '/vaults/{vaultId}/utxos',
            pathParams: { vaultId: VAULT },
            query: [['isSpent', false], ['limit', 10]],
            target: `/vaults/${VAULT}/utxos?isSpent=false&limit=10`,
        },
        {
            name: 'null_query_left_out',
            description: 'A parameter given as null (or not given) is not sent at all.',
            template: '/vaults/{vaultId}/utxos',
            pathParams: { vaultId: VAULT },
            query: [['address', null], ['limit', 10], ['assetId', null]],
            target: `/vaults/${VAULT}/utxos?limit=10`,
        },
        {
            name: 'empty_string_query_sent',
            description: 'An empty string is a value: sent as "name=".',
            template: '/supported-assets',
            pathParams: {},
            query: [['assetUnit', '']],
            target: '/supported-assets?assetUnit=',
        },
        {
            name: 'no_query',
            description: 'No query parameters: no "?" at all.',
            template: '/supported-assets',
            pathParams: {},
            query: [],
            target: '/supported-assets',
        },
        {
            name: 'reserved_characters_in_path',
            description: 'Every reserved character in a path parameter is percent-encoded, "/" included, so it can never add a path segment.',
            template: '/vaults/{vaultId}/addresses/{address}/balance',
            pathParams: { vaultId: VAULT, address: 'a/b?c#d%e&f=g+h i:j@k!l$m\'n(o)p*q,r;s' },
            target: `/vaults/${VAULT}/addresses/a%2Fb%3Fc%23d%25e%26f%3Dg%2Bh%20i%3Aj%40k%21l%24m%27n%28o%29p%2Aq%2Cr%3Bs/balance`,
        },
        {
            name: 'unreserved_kept',
            description: 'Letters, digits, "-", ".", "_" and "~" stay as they are.',
            template: '/vaults/{vaultId}/addresses/{address}/balance',
            pathParams: { vaultId: VAULT, address: 'Az09-._~' },
            target: `/vaults/${VAULT}/addresses/Az09-._~/balance`,
        },
        {
            name: 'utf8_in_path_and_query',
            description: 'Non-ASCII is encoded as its UTF-8 bytes, uppercase hex.',
            template: '/vaults/{vaultId}/addresses/{address}/balance',
            pathParams: { vaultId: VAULT, address: 'Сметка✓' },
            query: [['assetUnit', '東京']],
            target: `/vaults/${VAULT}/addresses/%D0%A1%D0%BC%D0%B5%D1%82%D0%BA%D0%B0%E2%9C%93/balance?assetUnit=%E6%9D%B1%E4%BA%AC`,
        },
        {
            name: 'reserved_characters_in_query',
            description: 'Query names and values are encoded the same way, so "&", "=" and "+" in a value stay inside it.',
            template: '/supported-assets',
            pathParams: {},
            query: [['assetUnit', 'a&b=c+d e']],
            target: '/supported-assets?assetUnit=a%26b%3Dc%2Bd%20e',
        },
        {
            name: 'integer_path_parameter',
            description: 'An integer path parameter (encodeXrpAddress addressTag) is its decimal.',
            template: '/utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}',
            pathParams: { network: 'testnet', classicAddress: 'rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY', addressTag: 12345 },
            target: '/utils/xrp/testnet/addresses/encode/rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY/12345',
        },
        {
            name: 'dot_segment_with_text',
            description: 'Dots inside a value are fine; only a whole "." or ".." segment is refused.',
            template: '/vaults/{vaultId}/addresses/{address}/balance',
            pathParams: { vaultId: VAULT, address: '..x' },
            target: `/vaults/${VAULT}/addresses/..x/balance`,
        },
        // Refused before anything is signed or sent
        { name: 'missing_path_parameter', description: 'A path parameter not given.', template: '/vaults/{vaultId}/utxos', pathParams: {}, error: 'missing_path_param' },
        { name: 'empty_path_parameter', description: 'An empty path parameter would leave an empty segment.', template: '/vaults/{vaultId}/utxos', pathParams: { vaultId: '' }, error: 'invalid_path_param' },
        { name: 'dot_path_parameter', description: '"." is a dot segment a URL removes, which would change the path signed.', template: '/vaults/{vaultId}/utxos', pathParams: { vaultId: '.' }, error: 'invalid_path_param' },
        { name: 'dot_dot_path_parameter', description: '".." would climb one segment up.', template: '/vaults/{vaultId}/utxos', pathParams: { vaultId: '..' }, error: 'invalid_path_param' },
        { name: 'boolean_path_parameter', description: 'Path parameters are strings or integers.', template: '/vaults/{vaultId}/utxos', pathParams: { vaultId: true }, error: 'invalid_path_param' },
        { name: 'fractional_query_value', description: 'Query values are strings, integers or booleans; no documented parameter is fractional.', template: '/supported-assets', pathParams: {}, query: [['limit', 1.5]], error: 'invalid_query_param' },
    ];

    return {
        format: 'vaultody request target encoding, v1',
        source: SOURCE,
        rules: {
            path: 'Each {name} in the template is replaced by its parameter: a string, or an integer as its decimal. Every UTF-8 byte outside the RFC 3986 unreserved set (A-Z a-z 0-9 - . _ ~) becomes %XX in uppercase hex, "/" included. Refused (invalid_path_param): an empty value, "." or "..", a value of another type, text with no UTF-8 form (a lone UTF-16 surrogate; tested per language, since JSON does not carry one portably). A parameter not given: missing_path_param.',
            query: 'name=value pairs joined by "&" in the order given, both encoded as the path is. A value is a string, an integer (decimal) or a boolean ("true"/"false"); null leaves the pair out; anything else is invalid_query_param. No pairs: no "?".',
            fetch: 'Every target is one a WHATWG URL (and so fetch) sends unchanged, so the path and query signed are the ones on the request line.',
        },
        caseFormat: { template: 'the operation path', pathParams: 'name → value', query: '[[name, value], ...] in order', expected: '{ target } or { error }' },
        cases: specs.map(pathCase),
    };
}

// ---------------------------------------------------------------------------------------------------
// P-256 signatures: IEEE P1363 → DER
// ---------------------------------------------------------------------------------------------------

function derInteger(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
        start += 1;
    }
    let body = bytes.subarray(start);
    if (body[0] & 0x80) {
        body = Buffer.concat([Buffer.from([0]), body]);
    }

    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}

function p1363ToDer(p1363) {
    const r = derInteger(p1363.subarray(0, 32));
    const s = derInteger(p1363.subarray(32));

    return Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
}

const P256_KEY = (() => {
    const scalar = label('p1363 key p-256');
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(scalar);
    const point = ecdh.getPublicKey();
    const privateKey = crypto.createPrivateKey({
        key: { kty: 'EC', crv: 'P-256', d: scalar.toString('base64url'), x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') },
        format: 'jwk',
    });

    return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
})();
const P256_SPKI = P256_KEY.publicKey.export({ format: 'der', type: 'spki' });

const OPENSSL = (() => {
    try {
        execFileSync('openssl', ['version'], { stdio: 'ignore' });

        return true;
    } catch (e) {
        return false;
    }
})();

function opensslVerifies(message, der) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-p1363-'));
    try {
        fs.writeFileSync(path.join(dir, 'key.pem'), P256_KEY.publicKey.export({ format: 'pem', type: 'spki' }));
        fs.writeFileSync(path.join(dir, 'message'), message);
        fs.writeFileSync(path.join(dir, 'signature.der'), der);
        const out = execFileSync('openssl', ['dgst', '-sha256', '-verify', path.join(dir, 'key.pem'), '-signature', path.join(dir, 'signature.der'), path.join(dir, 'message')], { encoding: 'utf8' });

        return /Verified OK/.test(out);
    } catch (e) {
        return false;
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

const REAL_SIGNATURES = [
    { name: 'neither_high_bit', description: 'r and s both start below 0x80: two 32-byte INTEGERs.', property: (r, s) => r[0] > 0 && r[0] < 0x80 && s[0] > 0 && s[0] < 0x80 },
    { name: 'r_high_bit', description: 'r starts at 0x80 or above: its INTEGER gets a leading 0x00 (33 bytes).', property: (r, s) => r[0] >= 0x80 && s[0] > 0 && s[0] < 0x80 },
    { name: 's_high_bit', description: 's starts at 0x80 or above: its INTEGER gets a leading 0x00.', property: (r, s) => s[0] >= 0x80 && r[0] > 0 && r[0] < 0x80 },
    { name: 'both_high_bits', description: 'Both get a leading 0x00: the longest DER, 72 bytes.', property: (r, s) => r[0] >= 0x80 && s[0] >= 0x80 },
    { name: 'r_leading_zero_byte', description: 'r has a leading zero byte: DER drops it (31 bytes).', property: (r, s) => r[0] === 0 && r[1] > 0 && r[1] < 0x80 && s[0] > 0 },
    { name: 'r_leading_zero_then_high_bit', description: 'r = 0x00 then a byte at 0x80 or above: the zero stays, as the sign byte (32 bytes).', property: (r, s) => r[0] === 0 && r[1] >= 0x80 && s[0] > 0 },
    { name: 's_leading_zero_byte', description: 's has a leading zero byte: DER drops it.', property: (r, s) => s[0] === 0 && s[1] > 0 && s[1] < 0x80 && r[0] > 0 },
    // 0x30 then 62 (= 64 - 2) is what a DER SEQUENCE of 64 bytes starts with: about 1 signature in 65,536.
    { name: 'p1363_starts_like_der', description: 'r starts with 0x30 0x3E, the first two bytes of a 64-byte DER SEQUENCE: still P1363, converted like any other 64-byte P-256 signature.', property: r => r[0] === 0x30 && r[1] === 0x3e, tries: 2000000 },
];

function realSignatureCase(spec, old) {
    const message = utf8(`vaultody sdk p1363 vector ${spec.name}`);
    const usable = p1363 => p1363.length === 64 && spec.property(p1363.subarray(0, 32), p1363.subarray(32))
        && crypto.verify('sha256', message, { key: P256_KEY.publicKey, dsaEncoding: 'ieee-p1363' }, p1363);

    let p1363 = old ? Buffer.from(old.p1363Hex, 'hex') : null;
    if (!p1363 || !usable(p1363)) {
        p1363 = null;
        for (let i = 0; i < (spec.tries || 200000) && !p1363; i += 1) {
            const candidate = crypto.sign('sha256', message, { key: P256_KEY.privateKey, dsaEncoding: 'ieee-p1363' });
            if (usable(candidate)) {
                p1363 = candidate;
            }
        }
        if (!p1363) {
            throw new Error(`${spec.name}: no signature with this property found`);
        }
    }

    const der = p1363ToDer(p1363);
    if (!crypto.verify('sha256', message, { key: P256_KEY.publicKey, dsaEncoding: 'der' }, der)) {
        throw new Error(`${spec.name}: node:crypto refuses the DER`);
    }
    if (OPENSSL && !opensslVerifies(message, der)) {
        throw new Error(`${spec.name}: openssl refuses the DER`);
    }

    return { name: spec.name, description: spec.description, p1363Hex: hex(p1363), messageBase64: b64(message), expected: { derHex: hex(der) } };
}

function syntheticCase(name, description, p1363HexText, expected) {
    const p1363 = Buffer.from(p1363HexText, 'hex');
    if (expected.derHex && hex(p1363ToDer(p1363)) !== expected.derHex) {
        throw new Error(`${name}: the encoder gives ${hex(p1363ToDer(p1363))}`);
    }

    return { name, description, p1363Hex: p1363HexText, messageBase64: null, expected };
}

function buildP1363() {
    const old = previous('p1363-der-v1.json');
    const oldCase = name => (old ? old.cases.find(c => c.name === name) : undefined);
    const zeros = n => '00'.repeat(n);
    const ff = n => 'ff'.repeat(n);

    return {
        format: 'vaultody P-256 signature encoding, IEEE P1363 to DER, v1',
        warning: 'TEST-ONLY key. Its private half is derived from a fixed label and is public.',
        source: { ...SOURCE, crossChecks: 'every real signature verified as DER by node:crypto, and by openssl whenever an openssl binary is on PATH (the generator and --check)' },
        rules: {
            input: 'exactly 64 bytes: r then s, each 32 bytes big-endian (Web Crypto, Azure Key Vault, some KMS APIs); any other length is invalid_length',
            output: 'DER SEQUENCE { INTEGER r, INTEGER s }: each INTEGER without leading zero bytes, then with one 0x00 added when its first byte is 0x80 or above; the sequence length always fits one byte',
            zero: 'r or s equal to zero is not a signature: zero_integer',
            signer: 'A signer\'s P-256 output of exactly 64 bytes is P1363 and is converted, even when it starts like DER (0x30 then 62, as p1363_starts_like_der does): a DER signature is 70 to 72 bytes for every signature a P-256 key makes in practice. Each SDK runs that case through its signer path (a signer callback returning those 64 bytes for the case\'s message), not only through its converter.',
        },
        caseFormat: { p1363Hex: 'the r||s input', messageBase64: 'for a real signature, the message the TEST-ONLY key signed (SHA-256), so a runner can also verify the DER; null for a synthetic case', expected: '{ derHex } or { error }' },
        publicKeySpkiDerBase64: b64(P256_SPKI),
        cases: [
            ...REAL_SIGNATURES.map(spec => realSignatureCase(spec, oldCase(spec.name))),
            syntheticCase('smallest_integers', 'r = s = 1: one-byte INTEGERs.', `${zeros(31)}01${zeros(31)}01`, { derHex: '3006020101020101' }),
            syntheticCase('small_integer_high_bit', 'r = 0x80 alone: 0x00 0x80.', `${zeros(31)}80${zeros(31)}01`, { derHex: '300702020080020101' }),
            syntheticCase('two_leading_zero_bytes', 'r with two leading zero bytes: both dropped.', `0000${'7f'.repeat(30)}${'11'.repeat(32)}`, { derHex: `3042021e${'7f'.repeat(30)}0220${'11'.repeat(32)}` }),
            syntheticCase('all_ones', 'r = s = 2^256 - 1: the longest form.', `${ff(32)}${ff(32)}`, { derHex: `30460221${'00'}${ff(32)}0221${'00'}${ff(32)}` }),
            syntheticCase('length_63', '63 bytes.', `${'11'.repeat(63)}`, { error: 'invalid_length' }),
            syntheticCase('length_65', '65 bytes.', `${'11'.repeat(65)}`, { error: 'invalid_length' }),
            syntheticCase('der_given', 'Already DER (70 bytes): not P1363.', `30440220${'11'.repeat(32)}0220${'22'.repeat(32)}`, { error: 'invalid_length' }),
            syntheticCase('empty', 'No bytes.', '', { error: 'invalid_length' }),
            syntheticCase('r_zero', 'r = 0.', `${zeros(32)}${'11'.repeat(32)}`, { error: 'zero_integer' }),
            syntheticCase('s_zero', 's = 0.', `${'11'.repeat(32)}${zeros(32)}`, { error: 'zero_integer' }),
        ],
    };
}

// ---------------------------------------------------------------------------------------------------
// Response envelope and typed errors
// ---------------------------------------------------------------------------------------------------

/** The error class of a code, which comes before the class of its status. */
const CLASS_OF_CODE = Object.freeze({
    api_keypair_required: 'RequestSigningError',
    missing_api_keypair_sign: 'RequestSigningError',
    missing_api_nonce: 'RequestSigningError',
    // the gateway's idempotency per API key and nonce; not in the gateway's catalogue yet
    api_nonce_reused: 'RequestSigningError',
    unknown_api_keypair_id: 'RequestSigningError',
    invalid_api_keypair_sign: 'RequestSigningError',
    invalid_api_key: 'AuthenticationError',
    invalid_api_sign: 'AuthenticationError',
    invalid_api_timestamp: 'AuthenticationError',
    missing_authorization_header: 'AuthenticationError',
    invalid_data: 'InvalidRequestError',
    missing_required_attributes: 'InvalidRequestError',
    extra_body_attributes: 'InvalidRequestError',
    extra_query_attributes: 'InvalidRequestError',
    invalid_api_version: 'InvalidRequestError',
    double_spending: 'DuplicateTransferError',
});
const RETRYABLE_CODES = new Set(['address_derivation_conflict', 'vault_accounts_creation_failed']);

function classOfStatus(status) {
    if (status >= 500 && status <= 599) {
        return 'ServerError';
    }

    return ({ 400: 'InvalidRequestError', 401: 'AuthenticationError', 403: 'PermissionDeniedError', 404: 'NotFoundError', 409: 'ConflictError', 415: 'InvalidRequestError', 422: 'InvalidRequestError', 429: 'RateLimitError' })[status] || 'ApiError';
}

const errorClass = (status, code) => (code && CLASS_OF_CODE[code]) || classOfStatus(status);

function errorBody({ code, message, requestId = '6630f1c2a9e4b5d7c8e9f1a1', apiVersion, details }) {
    const body = {};
    if (apiVersion) {
        body.apiVersion = apiVersion;
    }
    body.requestId = requestId;
    body.error = { code, message };
    if (details !== undefined) {
        body.error.details = details;
    }

    return JSON.stringify(body);
}

function envelopeErrorCase({ name, description, status, headers = {}, body, code, message = null, requestId = null, apiVersion = null, details, className }) {
    return {
        name,
        description,
        status,
        headers,
        body,
        expected: {
            kind: 'error',
            class: className || errorClass(status, code),
            code: code === undefined ? null : code,
            message,
            requestId,
            apiVersion,
            ...(details === undefined ? {} : { details }),
            replayed: headers['x-api-replayed'] === 'true',
            retryable: Boolean(code && RETRYABLE_CODES.has(code)),
        },
    };
}

function buildEnvelopeErrors() {
    const catalogue = readJson(path.join(ROOT, 'contract', 'errors.json'));
    const cases = [];

    const item = JSON.stringify({ apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b1', context: 'order-1842', data: { item: { address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', label: 'deposit-7' } } });
    cases.push({ name: 'item', description: 'A single item: { apiVersion, requestId, context, data: { item } }.', status: 201, headers: {}, body: item, expected: { kind: 'item', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b1', context: 'order-1842', replayed: false } });
    cases.push({ name: 'item_without_context', description: 'No context sent: context is null.', status: 200, headers: {}, body: JSON.stringify({ apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b2', data: { item: { isValid: true } } }), expected: { kind: 'item', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b2', context: null, replayed: false } });
    cases.push({ name: 'item_replayed', description: 'The first answer to a request sent again: x-api-replayed: true.', status: 201, headers: { 'x-api-replayed': 'true' }, body: item, expected: { kind: 'item', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b1', context: 'order-1842', replayed: true } });
    cases.push({ name: 'item_replayed_header_case', description: 'Header names match case-insensitively.', status: 201, headers: { 'X-Api-Replayed': 'true' }, body: item, expected: { kind: 'item', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b1', context: 'order-1842', replayed: true } });
    cases.push({ name: 'item_replayed_other_value', description: 'Only the exact value "true" means replayed.', status: 201, headers: { 'x-api-replayed': 'yes' }, body: item, expected: { kind: 'item', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b1', context: 'order-1842', replayed: false } });
    cases.push({
        name: 'item_unknown_fields_kept',
        description: 'Fields the SDK does not know (added by a later API change) are no error.',
        status: 200,
        headers: {},
        body: JSON.stringify({ apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b3', newTopLevel: 1, data: { item: { id: 'x', newField: { a: 1 } } } }),
        expected: { kind: 'item', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1b3', context: null, replayed: false },
    });
    cases.push({
        name: 'cursor_page',
        description: 'A cursor page: { limit, startingAfter, hasMore, items }.',
        status: 200,
        headers: {},
        body: JSON.stringify({ apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1c1', data: { limit: 2, startingAfter: '6630f1c2a9e4b5d7c8e9f0a2', hasMore: true, items: [{ id: '6630f1c2a9e4b5d7c8e9f0a1' }, { id: '6630f1c2a9e4b5d7c8e9f0a2' }] } }),
        expected: { kind: 'page', paging: 'cursor', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1c1', context: null, replayed: false, limit: 2, hasMore: true, startingAfter: '6630f1c2a9e4b5d7c8e9f0a2', count: 2 },
    });
    cases.push({
        name: 'cursor_page_last',
        description: 'The last page: hasMore false, no startingAfter.',
        status: 200,
        headers: {},
        body: JSON.stringify({ apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1c2', data: { limit: 50, hasMore: false, items: [] } }),
        expected: { kind: 'page', paging: 'cursor', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1c2', context: null, replayed: false, limit: 50, hasMore: false, startingAfter: null, count: 0 },
    });
    cases.push({
        name: 'offset_page',
        description: 'An offset page: { limit, offset, total, items } (listApiKeySigningKeys).',
        status: 200,
        headers: {},
        body: JSON.stringify({ apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1c3', data: { limit: 2, offset: 0, total: 1, items: [{ fingerprint: 'SHA256:1K9sRW4V/tM+To9K/9728DyV3Qg2kE7x/9UELb/Nixg' }] } }),
        expected: { kind: 'page', paging: 'offset', apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1c3', context: null, replayed: false, limit: 2, offset: 0, total: 1, count: 1 },
    });

    // One case per catalogued code, with the status it comes with
    for (const entry of catalogue.codes) {
        const withApiVersion = entry.status !== 401;
        cases.push(envelopeErrorCase({
            name: `code_${entry.code}`,
            description: `${entry.status} ${entry.code}${entry.documented ? '' : ' (the gateway\'s own)'}${withApiVersion ? '' : '; a 401 body has no apiVersion'}.`,
            status: entry.status,
            body: errorBody({ code: entry.code, message: `TEST message for ${entry.code}.`, apiVersion: withApiVersion ? '2026-03-20' : undefined }),
            code: entry.code,
            message: `TEST message for ${entry.code}.`,
            requestId: '6630f1c2a9e4b5d7c8e9f1a1',
            apiVersion: withApiVersion ? '2026-03-20' : null,
        }));
    }

    // The gateway's idempotency, not in its catalogue yet: a nonce used before for a different
    // request is a signing error, never retried (duplicate_api_request_in_progress, catalogued above, is a
    // ConflictError here; a write that meets it ends as RequestOutcomeUnknownError with inProgress, retry-v1.json).
    cases.push(envelopeErrorCase({
        name: 'code_api_nonce_reused',
        description: '409 api_nonce_reused: the nonce was used before for a different request; RequestSigningError, not retryable.',
        status: 409,
        body: errorBody({ code: 'api_nonce_reused', message: 'TEST message for api_nonce_reused.', apiVersion: '2026-03-20' }),
        code: 'api_nonce_reused',
        message: 'TEST message for api_nonce_reused.',
        requestId: '6630f1c2a9e4b5d7c8e9f1a1',
        apiVersion: '2026-03-20',
    }));

    // Codes the SDK does not know: the class of the status, the code kept
    for (const status of [400, 401, 403, 404, 409, 415, 422, 429, 500, 502, 503, 405, 413]) {
        cases.push(envelopeErrorCase({
            name: `unknown_code_${status}`,
            description: `An unknown code with ${status}: the class of the status, the code kept as it is.`,
            status,
            body: errorBody({ code: `some_future_code_${status}`, message: 'TEST message.', apiVersion: '2026-03-20' }),
            code: `some_future_code_${status}`,
            message: 'TEST message.',
            requestId: '6630f1c2a9e4b5d7c8e9f1a1',
            apiVersion: '2026-03-20',
        }));
    }

    cases.push(envelopeErrorCase({
        name: 'error_with_details',
        description: 'error.details is passed on as it is.',
        status: 409,
        body: errorBody({ code: 'invalid_data', message: 'TEST message.', apiVersion: '2026-03-20', details: [{ attribute: 'amount', message: 'must be a string' }] }),
        code: 'invalid_data',
        message: 'TEST message.',
        requestId: '6630f1c2a9e4b5d7c8e9f1a1',
        apiVersion: '2026-03-20',
        details: [{ attribute: 'amount', message: 'must be a string' }],
    }));
    cases.push(envelopeErrorCase({
        name: 'error_replayed',
        description: 'A replayed error answer is still that error, marked replayed.',
        status: 403,
        headers: { 'x-api-replayed': 'true' },
        body: errorBody({ code: 'wallet_as_a_service_provided_network_is_not_suitable_for_this_wallet_type', message: 'TEST message.', apiVersion: '2026-03-20' }),
        code: 'wallet_as_a_service_provided_network_is_not_suitable_for_this_wallet_type',
        message: 'TEST message.',
        requestId: '6630f1c2a9e4b5d7c8e9f1a1',
        apiVersion: '2026-03-20',
    }));
    cases.push(envelopeErrorCase({ name: 'html_502', description: 'A 502 from a proxy with an HTML body: the class of the status, no code.', status: 502, body: '<html><body>Bad Gateway</body></html>' }));
    cases.push(envelopeErrorCase({ name: 'empty_503', description: 'A 503 with no body.', status: 503, body: '' }));
    cases.push(envelopeErrorCase({ name: 'json_without_error_object', description: 'A 400 whose JSON has no error object.', status: 400, body: '{"requestId":"6630f1c2a9e4b5d7c8e9f1a2"}', requestId: '6630f1c2a9e4b5d7c8e9f1a2' }));
    cases.push(envelopeErrorCase({ name: 'error_code_not_a_string', description: 'error.code that is not a string is no code.', status: 409, body: '{"requestId":"6630f1c2a9e4b5d7c8e9f1a3","error":{"code":42,"message":"TEST message."}}', message: 'TEST message.', requestId: '6630f1c2a9e4b5d7c8e9f1a3' }));
    cases.push(envelopeErrorCase({ name: 'success_not_json', description: 'A 200 that is not JSON is not an answer the SDK can return: ApiError, no code.', status: 200, body: 'OK', className: 'ApiError' }));
    cases.push(envelopeErrorCase({ name: 'success_without_data', description: 'A 200 JSON without data.item or data.items.', status: 200, body: '{"apiVersion":"2026-03-20","requestId":"6630f1c2a9e4b5d7c8e9f1a4","data":{}}', className: 'ApiError', requestId: '6630f1c2a9e4b5d7c8e9f1a4', apiVersion: '2026-03-20' }));
    cases.push(envelopeErrorCase({ name: 'success_json_array', description: 'A 200 whose JSON is not an object.', status: 200, body: '[]', className: 'ApiError' }));

    return {
        format: 'vaultody response envelope and typed errors, v1',
        source: { ...SOURCE, catalogue: 'contract/errors.json' },
        hierarchy: {
            VaultodyError: 'the base of every error the SDK raises on purpose',
            ApiError: 'VaultodyError; an answer the SDK can\'t return as a result: status, code, message, details, requestId, apiVersion, replayed, retryable',
            AuthenticationError: 'ApiError', RequestSigningError: 'ApiError', PermissionDeniedError: 'ApiError', NotFoundError: 'ApiError',
            InvalidRequestError: 'ApiError', ConflictError: 'ApiError', DuplicateTransferError: 'ApiError', RateLimitError: 'ApiError', ServerError: 'ApiError',
        },
        rules: {
            success: 'A 2xx JSON object with data.item is an item; with data.items an array, a page: offset-paged when data has offset or total, else cursor-paged. Unknown fields are ignored. Anything else on a 2xx is an ApiError without a code.',
            error: 'Any other status is an error. code is error.code when it is a string, else null; message likewise; requestId and apiVersion from the top level when strings, else null; details passed on as given (only when present).',
            class: 'The class of the code (RequestSigningError for the key-pair and nonce codes, api_nonce_reused included, AuthenticationError for the four documented 401 codes, InvalidRequestError for the 409 validation codes, DuplicateTransferError for double_spending), else the class of the status: 400, 415, 422 InvalidRequestError; 401 AuthenticationError; 403 PermissionDeniedError; 404 NotFoundError; 409 ConflictError; 429 RateLimitError; 5xx ServerError; anything else ApiError.',
            replayed: 'x-api-replayed exactly "true" (header name in any case)',
            retryable: 'true only for address_derivation_conflict and vault_accounts_creation_failed, which the docs say to retry at once',
            branchOnCode: 'Callers branch on code, never on message.',
        },
        caseFormat: { status: 'HTTP status', headers: 'response headers', body: 'the raw body as text', expected: '{ kind: item|page, ... } or { kind: error, class, code, message, requestId, apiVersion, replayed, retryable, details? }' },
        cases,
        sdkErrors: buildSdkErrors(),
    };
}

/**
 * The errors the SDK raises with no answer of the API: their names, and the fields the three SDKs fill the same
 * way, raised for real by the param checks of a method and by webhooks.verify.
 */
function buildSdkErrors() {
    const valid = {
        vaultId: '6630f1c2a9e4b5d7c8e9f0a1',
        assetId: '6630f1c2a9e4b5d7c8e9f0b7',
        feePriority: 'standard',
        note: 'TEST note',
        prepareStrategy: 'minimize-dust',
        recipients: [{ address: '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', amount: '0.1' }],
        vaultAccountId: '6630f1c2a9e4b5d7c8e9f0e2',
    };
    const withoutNote = { ...valid };
    delete withoutNote.note;
    const recipient = valid.recipients[0];
    const call = (name, description, params, code, param) => ({
        name,
        description,
        call: { group: 'transactions', operationId: 'createMultipleTransfer', params },
        expected: { class: 'ParameterError', fields: { code, param } },
    });

    const SECRET = 'TEST-ONLY webhook signing secret A';
    const signed = text => ({ 'X-Signature': webhookSignature(text, SECRET) });
    const event = JSON.stringify({ webhookId: '68516e9c6620b0a4790ed541', data: { event: 'TRANSACTION_REQUEST', item: { requestId: '686cd2860ca2f4fd25f77099' } } });
    const webhook = (name, description, bodyText, headers, expected) => ({
        name, description, webhook: { bodyBase64: b64(utf8(bodyText)), headers, secrets: [SECRET] }, expected,
    });

    return {
        rule: 'Errors the SDK raises with no answer of the API. Each class extends VaultodyError and is exported where ApiError is: the Node package root, the vaultody_sdk package root, PHP\'s Vaultody\\Sdk\\Exception namespace. Each case raises one for real and names the class and the fields it must carry (Python names them in snake_case; these are one word). Nothing is sent: the params are checked before.',
        classes: [
            'RequestOutcomeUnknownError', 'TransportError', 'ParameterError', 'PaginationError', 'VaultKeyChangedError', 'AddressVerificationError',
            'ResponseVerificationError', 'ConfigurationError', 'WebhookSignatureError', 'WebhookPayloadError', 'VaultKeyStoreError',
        ],
        caseFormat: {
            call: 'a method of the client: its group, operationId (Python: snake_case) and params, as the application passes them',
            webhook: 'webhooks.verify(raw body, headers, secrets)',
            expected: '{ class, fields }: the class raised and the value of each field named',
        },
        cases: [
            call('param_unknown', 'A param the operation does not document: param names it.', { ...valid, fooBar: 'x' }, 'unknown_param', 'fooBar'),
            call('param_missing', 'A required param left out.', withoutNote, 'missing_param', 'note'),
            call('param_not_documented_value', 'A value outside the documented list (case included).', { ...valid, feePriority: 'FAST' }, 'invalid_param', 'feePriority'),
            call('param_nested_wrong_type', 'A nested field of the wrong type: param is its path.', { ...valid, recipients: [{ ...recipient, amount: 5 }] }, 'invalid_param', 'recipients[0].amount'),
            call('param_nested_unknown', 'A nested field the API does not document.', { ...valid, recipients: [{ ...recipient, memo: 'x' }] }, 'unknown_param', 'recipients[0].memo'),
            call('param_nested_missing', 'A required nested field left out.', { ...valid, recipients: [{ address: recipient.address }] }, 'missing_param', 'recipients[0].amount'),
            webhook('webhook_mismatch', 'A delivery whose body changed after signing.', `${event} `, signed(event), { class: 'WebhookSignatureError', fields: { reason: 'mismatch' } }),
            webhook('webhook_missing', 'A delivery without X-Signature.', event, {}, { class: 'WebhookSignatureError', fields: { reason: 'missing' } }),
            webhook('webhook_not_json', 'Signed, but not JSON.', 'not json', signed('not json'), { class: 'WebhookPayloadError', fields: {} }),
            webhook('webhook_no_event', 'Signed JSON without data.event.', '{"data":{}}', signed('{"data":{}}'), { class: 'WebhookPayloadError', fields: {} }),
        ],
    };
}

// ---------------------------------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------------------------------

function buildPagination() {
    const overlay = readJson(path.join(ROOT, 'contract', 'overlay.json')).operations;
    const id = n => `6630f1c2a9e4b5d7c8e9${String(n).padStart(4, '0')}`;
    const itemsOf = (field, from, count) => Array.from({ length: count }, (_, i) => ({ [field]: id(from + i), extra: `item ${from + i}` }));
    const cursorPages = (field, sizes, limit) => {
        let next = 1;

        return sizes.map((size, index) => {
            const items = itemsOf(field, next, size);
            const hasMore = index < sizes.length - 1;
            const page = { limit, hasMore, items };
            if (hasMore) {
                page.startingAfter = items[items.length - 1][field];
            }
            next += size;

            return page;
        });
    };
    const ids = (field, pages) => pages.flatMap(page => page.items.map(itemRecord => itemRecord[field]));
    const requestsFor = (field, pages, limit) => pages.map((page, index) => ({ startingAfter: index === 0 ? null : pages[index - 1].items[pages[index - 1].items.length - 1][field], limit }));

    // The operation's largest page: limit's maximum in the published document; the pending
    // listApiKeySigningKeys holds at most two keys.
    const openapi = readJson(path.join(ROOT, 'contract', 'openapi.json'));
    const maxLimitOf = {};
    for (const item of Object.values(openapi.paths)) {
        for (const op of Object.values(item)) {
            const limitParam = (op.parameters || []).find(param => param.name === 'limit');
            if (limitParam) {
                maxLimitOf[op.operationId] = limitParam.schema.maximum;
            }
        }
    }
    maxLimitOf.listApiKeySigningKeys = 2;

    const cases = [];
    for (const [operationId, entry] of Object.entries(overlay)) {
        if (!entry.cursorField) {
            continue;
        }
        const field = entry.cursorField;
        const pages = cursorPages(field, [2, 2, 1], 2);
        cases.push({
            name: `${operationId}_three_pages`,
            description: `${operationId}: the cursor is the ${field} of the last item.`,
            operationId,
            paging: 'cursor',
            cursorField: field,
            limit: 2,
            pages: pages.map((page, index) => ({ request: requestsFor(field, pages, 2)[index], response: page })),
            expected: { items: ids(field, pages), stop: 'end' },
        });
    }

    const field = 'id';
    const defaultLimit = cursorPages(field, [1], 50);
    cases.push({ name: 'default_limit', description: 'No limit given: the operation\'s maximum, 50.', operationId: 'listVaults', paging: 'cursor', cursorField: field, limit: null, pages: [{ request: { startingAfter: null, limit: 50 }, response: defaultLimit[0] }], expected: { items: ids(field, defaultLimit), stop: 'end' } });
    cases.push({ name: 'empty_first_page', description: 'Nothing at all.', operationId: 'listVaults', paging: 'cursor', cursorField: field, limit: 2, pages: [{ request: { startingAfter: null, limit: 2 }, response: { limit: 2, hasMore: false, items: [] } }], expected: { items: [], stop: 'end' } });
    const emptyPage = cursorPages(field, [2], 2);
    cases.push({
        name: 'empty_page_with_has_more',
        description: 'An empty page that says more follow: stop, there is no cursor to go on with.',
        operationId: 'listVaults',
        paging: 'cursor',
        cursorField: field,
        limit: 2,
        pages: [
            { request: { startingAfter: null, limit: 2 }, response: { ...emptyPage[0], hasMore: true, startingAfter: id(2) } },
            { request: { startingAfter: id(2), limit: 2 }, response: { limit: 2, hasMore: true, items: [] } },
        ],
        expected: { items: [id(1), id(2)], stop: 'empty_page' },
    });
    const loop = cursorPages(field, [2], 2)[0];
    cases.push({
        name: 'same_cursor_twice',
        description: 'A page whose last item is the cursor already used: a loop, refused.',
        operationId: 'listVaults',
        paging: 'cursor',
        cursorField: field,
        limit: 2,
        pages: [
            { request: { startingAfter: null, limit: 2 }, response: { ...loop, hasMore: true, startingAfter: id(2) } },
            { request: { startingAfter: id(2), limit: 2 }, response: { limit: 2, hasMore: true, startingAfter: id(2), items: [{ id: id(3) }, { id: id(2) }] } },
        ],
        expected: { items: [id(1), id(2), id(3), id(2)], error: 'pagination_loop' },
    });
    cases.push({
        name: 'cursor_field_missing',
        description: 'The last item has no cursor field: refused rather than guessed.',
        operationId: 'listVaults',
        paging: 'cursor',
        cursorField: field,
        limit: 2,
        pages: [{ request: { startingAfter: null, limit: 2 }, response: { limit: 2, hasMore: true, items: [{ id: id(1) }, { name: 'no id' }] } }],
        expected: { items: [id(1), null], error: 'missing_cursor' },
    });
    const max = cursorPages(field, [2, 2, 2], 2);
    cases.push({
        name: 'max_items_mid_page',
        description: 'maxItems 3: stop after the third item, without asking for the third page.',
        operationId: 'listVaults',
        paging: 'cursor',
        cursorField: field,
        limit: 2,
        maxItems: 3,
        pages: max.slice(0, 2).map((page, index) => ({ request: requestsFor(field, max, 2)[index], response: page })),
        expected: { items: [id(1), id(2), id(3)], stop: 'max_items' },
    });
    const exact = cursorPages(field, [2, 2], 2);
    cases.push({
        name: 'max_items_at_page_end',
        description: 'maxItems 2 with a full first page: stop there, though more follow.',
        operationId: 'listVaults',
        paging: 'cursor',
        cursorField: field,
        limit: 2,
        maxItems: 2,
        pages: [{ request: requestsFor(field, exact, 2)[0], response: exact[0] }],
        expected: { items: [id(1), id(2)], stop: 'max_items' },
    });

    const fingerprints = ['SHA256:1K9sRW4V/tM+To9K/9728DyV3Qg2kE7x/9UELb/Nixg', 'SHA256:NC4XT6Zk48B1y5dLbXZWM+WGfRk7NI+3YinOrusjMgw'];
    cases.push({
        name: 'offset_two_pages',
        description: 'Offset paging (listApiKeySigningKeys): the next offset is the offset plus the items received, until total is reached.',
        operationId: 'listApiKeySigningKeys',
        paging: 'offset',
        cursorField: null,
        limit: 1,
        pages: [
            { request: { offset: 0, limit: 1 }, response: { limit: 1, offset: 0, total: 2, items: [{ fingerprint: fingerprints[0] }] } },
            { request: { offset: 1, limit: 1 }, response: { limit: 1, offset: 1, total: 2, items: [{ fingerprint: fingerprints[1] }] } },
        ],
        itemField: 'fingerprint',
        expected: { items: fingerprints, stop: 'end' },
    });
    cases.push({
        name: 'offset_empty_page_before_total',
        description: 'An empty offset page before total is reached: stop.',
        operationId: 'listApiKeySigningKeys',
        paging: 'offset',
        cursorField: null,
        limit: 2,
        pages: [{ request: { offset: 0, limit: 2 }, response: { limit: 2, offset: 0, total: 3, items: [] } }],
        itemField: 'fingerprint',
        expected: { items: [], stop: 'empty_page' },
    });

    for (const vector of cases) {
        vector.maxLimit = maxLimitOf[vector.operationId];
        if (typeof vector.maxLimit !== 'number') {
            throw new Error(`${vector.name}: no maximum limit for ${vector.operationId}`);
        }
    }

    return {
        format: 'vaultody pagination, v1',
        source: { ...SOURCE, overlay: 'contract/overlay.json (cursorField per operation)' },
        rules: {
            first: 'The first request has no startingAfter (offset paging: offset 0) and the limit given, or the operation\'s maximum (50; listApiKeySigningKeys 2) when none is.',
            cursor: 'After a page: stop with "end" when hasMore is false; stop with "empty_page" when it has no items; else the next startingAfter is the value of the operation\'s cursor field on the last item (missing or not a non-empty string: error missing_cursor). A cursor used before: error pagination_loop.',
            offset: 'After a page: the next offset is offset + the number of items; stop with "end" when that reaches total, else with "empty_page" when the page had no items.',
            maxItems: 'With maxItems, stop with "max_items" as soon as that many items were yielded, without fetching further.',
            pages: 'Each page is fetched like any other call: signed, verified, checked.',
        },
        caseFormat: {
            maxLimit: 'the operation\'s largest page, the limit used when none is given',
            pages: 'in order, the request the SDK must make (startingAfter and limit, or offset and limit) and the data the answer holds',
            expected: 'items: the cursor field (offset paging: itemField) of every item yielded, in order, null where it is missing; stop: why it ended, or error',
        },
        cases,
    };
}

// ---------------------------------------------------------------------------------------------------
// Retries
// ---------------------------------------------------------------------------------------------------

const RETRY = Object.freeze({ maxAttempts: 5, baseDelayMs: 1000, maxDelayMs: 8000, deadlineMs: 30000, resendWindowMs: 2500, signatureMaxAgeMs: 25000 });
const ceiling = attempt => Math.min(RETRY.maxDelayMs, RETRY.baseDelayMs * (2 ** (attempt - 1)));
const jitter = (attempt, random) => Math.floor(random * ceiling(attempt));

function retryCase(spec) {
    const input = {
        operation: spec.operation,
        keyMode: spec.keyMode || 'legacy',
        attempt: spec.attempt || 1,
        elapsedMs: spec.elapsedMs || 0,
        signedAgeMs: spec.signedAgeMs || 0,
        sinceFirstSendMs: spec.sinceFirstSendMs || 0,
        resends: spec.resends || 0,
        mayHaveRun: spec.mayHaveRun || false,
        conflictRetried: spec.conflictRetried || false,
        random: spec.random === undefined ? 0.5 : spec.random,
        outcome: spec.outcome,
    };
    if (spec.expected.action === 'retry' && spec.expected.delayMs === undefined) {
        throw new Error(`${spec.name}: a retry needs its delay`);
    }
    // A retry of a write keeps the call's nonce (the gateway's idempotency); a read re-signed gets a new one,
    // and so does the one retry after address_derivation_conflict or vault_accounts_creation_failed, where nothing ran.
    const conflictRetry = spec.outcome.type === 'response' && RETRYABLE_CODES.has(spec.outcome.code);
    const expected = spec.expected.action === 'retry'
        ? { action: 'retry', mode: spec.expected.mode, nonce: spec.operation === 'write' && !conflictRetry ? 'same' : 'new', delayMs: spec.expected.delayMs }
        : spec.expected;

    return { name: spec.name, description: spec.description, input, expected };
}

const ok = status => ({ type: 'response', status, code: null, replayed: false, retryAfterSeconds: null });
const err = (status, code, extra = {}) => ({ type: 'response', status, code, replayed: false, retryAfterSeconds: null, ...extra });
const NOT_SENT = { type: 'not_sent' };
const SENT_UNKNOWN = { type: 'sent_unknown' };
const VERIFICATION_FAILED = { type: 'verification_failed' };

function buildRetry() {
    const R = (action, extra = {}) => ({ action, ...extra });
    const specs = [
        // Reads: GET and the POSTs that change nothing
        { name: 'read_ok', description: 'A 2xx is returned.', operation: 'read', outcome: ok(200), expected: R('return') },
        { name: 'read_not_found', description: 'A 4xx is returned to the caller as its typed error, never retried.', operation: 'read', outcome: err(404, 'resource_not_found'), expected: R('return') },
        { name: 'read_auth_error', description: 'Neither is a 401.', operation: 'read', outcome: err(401, 'invalid_api_sign'), expected: R('return') },
        { name: 'read_bad_request', description: 'Nor a 400.', operation: 'read', outcome: err(400, 'invalid_pagination'), expected: R('return') },
        { name: 'read_not_sent', description: 'Connection failed before sending: re-signed and retried after a full-jitter backoff (attempt 1: up to 1 s).', operation: 'read', attempt: 1, random: 0.5, outcome: NOT_SENT, expected: R('retry', { mode: 'resign', delayMs: 500 }) },
        { name: 'read_sent_unknown', description: 'A timeout after sending: a read is retried all the same (attempt 2: up to 2 s).', operation: 'read', attempt: 2, random: 0.5, outcome: SENT_UNKNOWN, expected: R('retry', { mode: 'resign', delayMs: 1000 }) },
        { name: 'read_429', description: 'Rate limited: re-signed, backoff (attempt 3: up to 4 s).', operation: 'read', attempt: 3, random: 0.25, outcome: err(429, 'request_limit_reached'), expected: R('retry', { mode: 'resign', delayMs: 1000 }) },
        { name: 'read_503_backoff_cap', description: 'Backoff is capped at 8 s (attempt 4).', operation: 'read', attempt: 4, random: 0.999, outcome: err(503, null), expected: R('retry', { mode: 'resign', delayMs: 7992 }) },
        { name: 'read_500_last_attempt', description: 'The fifth attempt is the last: the error is returned.', operation: 'read', attempt: 5, outcome: err(500, 'unexpected_server_error'), expected: R('return') },
        { name: 'read_not_sent_last_attempt', description: 'The fifth attempt failing to connect: the transport error is raised.', operation: 'read', attempt: 5, outcome: NOT_SENT, expected: R('fail') },
        { name: 'read_retry_after', description: 'A Retry-After header is honoured when it asks for longer than the backoff.', operation: 'read', attempt: 1, random: 0.1, outcome: err(429, 'request_limit_reached', { retryAfterSeconds: 3 }), expected: R('retry', { mode: 'resign', delayMs: 3000 }) },
        { name: 'read_retry_after_shorter', description: 'A Retry-After shorter than the backoff changes nothing.', operation: 'read', attempt: 2, random: 0.9, outcome: err(429, 'request_limit_reached', { retryAfterSeconds: 1 }), expected: R('retry', { mode: 'resign', delayMs: 1800 }) },
        { name: 'read_deadline', description: 'A retry that would end past the 30 s deadline is not made.', operation: 'read', attempt: 1, elapsedMs: 29500, random: 0.9, outcome: err(502, null), expected: R('return') },
        { name: 'read_verification_failed', description: 'A response that fails its signature check is never retried.', operation: 'read', outcome: VERIFICATION_FAILED, expected: R('fail') },

        // Writes with a confirmed key pair: replay protection always enforced
        { name: 'write_created', description: 'A 2xx is returned.', operation: 'write', keyMode: 'keypair', outcome: ok(201), expected: R('return') },
        { name: 'write_replayed_created', description: 'The replayed first answer to a resend is the outcome.', operation: 'write', keyMode: 'keypair', resends: 1, outcome: { ...ok(201), replayed: true }, expected: R('return') },
        { name: 'write_sent_unknown_resend', description: 'A timeout after sending: the same signed request is sent again at once, within the gateway\'s 3 s replay-response window, to get the first answer.', operation: 'write', keyMode: 'keypair', sinceFirstSendMs: 800, outcome: SENT_UNKNOWN, expected: R('retry', { mode: 'resend', delayMs: 0 }) },
        { name: 'write_sent_unknown_too_late', description: 'Too late for the replay-response window (2.5 s with a margin): the outcome is unknown.', operation: 'write', keyMode: 'keypair', sinceFirstSendMs: 2600, outcome: SENT_UNKNOWN, expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_sent_unknown_twice', description: 'The resend timed out too: only one resend, then unknown.', operation: 'write', keyMode: 'keypair', attempt: 2, resends: 1, sinceFirstSendMs: 1500, outcome: SENT_UNKNOWN, expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_500_resend', description: 'A 5xx may have run: one immediate resend of the same request gets the first answer.', operation: 'write', keyMode: 'keypair', sinceFirstSendMs: 300, outcome: err(500, 'unexpected_server_error'), expected: R('retry', { mode: 'resend', delayMs: 0 }) },
        { name: 'write_500_too_late', description: 'A 5xx after the window: unknown.', operation: 'write', keyMode: 'keypair', sinceFirstSendMs: 2700, outcome: err(500, 'unexpected_server_error'), expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_replayed_500', description: 'The replayed first answer is itself a 5xx: unknown.', operation: 'write', keyMode: 'keypair', resends: 1, outcome: { ...err(500, 'unexpected_server_error'), replayed: true }, expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_in_progress', description: '409 duplicate_api_request_in_progress: the first request is still running; unknown, in progress.', operation: 'write', keyMode: 'keypair', resends: 1, outcome: err(409, 'duplicate_api_request_in_progress'), expected: R('outcome_unknown', { inProgress: true }) },
        { name: 'write_duplicate_after_resend', description: '401 duplicate_api_request to a resend: the first request was received, but its answer is gone (past the 3 s window); unknown.', operation: 'write', keyMode: 'keypair', resends: 1, outcome: err(401, 'duplicate_api_request'), expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_duplicate_first_send', description: 'duplicate_api_request to a first send is an ordinary error.', operation: 'write', keyMode: 'keypair', outcome: err(401, 'duplicate_api_request'), expected: R('return') },
        { name: 'write_not_sent_resend', description: 'Not sent: the same signed request again, after a backoff.', operation: 'write', keyMode: 'keypair', attempt: 1, signedAgeMs: 100, random: 0.5, outcome: NOT_SENT, expected: R('retry', { mode: 'resend', delayMs: 500 }) },
        { name: 'write_not_sent_signature_too_old', description: 'Not sent, and the signature would be older than 25 s when resent: re-signed, since nothing of this call ever reached the gateway.', operation: 'write', keyMode: 'keypair', attempt: 1, signedAgeMs: 24800, random: 0.5, outcome: NOT_SENT, expected: R('retry', { mode: 'resign', delayMs: 500 }) },
        { name: 'write_not_sent_signature_too_old_after_send', description: 'The same, but an earlier attempt may have run: never re-signed; unknown.', operation: 'write', keyMode: 'keypair', attempt: 2, signedAgeMs: 24800, mayHaveRun: true, outcome: NOT_SENT, expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_429_resend', description: 'A 429 is refused before the route, so the request never ran: the same request again after a backoff.', operation: 'write', keyMode: 'keypair', attempt: 2, signedAgeMs: 3000, random: 0.5, outcome: err(429, 'request_limit_reached'), expected: R('retry', { mode: 'resend', delayMs: 1000 }) },
        { name: 'write_429_signature_too_old', description: 'After a 429, with the signature too old to resend: re-signed.', operation: 'write', keyMode: 'keypair', attempt: 2, signedAgeMs: 24500, random: 0.5, outcome: err(429, 'request_limit_reached'), expected: R('retry', { mode: 'resign', delayMs: 1000 }) },
        { name: 'write_429_after_possible_run', description: 'A 429 to a resend of a request that may have run: resent while the signature is fresh enough.', operation: 'write', keyMode: 'keypair', attempt: 2, signedAgeMs: 1000, random: 0.5, resends: 1, mayHaveRun: true, outcome: err(429, 'request_limit_reached'), expected: R('retry', { mode: 'resend', delayMs: 1000 }) },
        { name: 'write_429_after_possible_run_too_old', description: '... and unknown once it is not.', operation: 'write', keyMode: 'keypair', attempt: 2, signedAgeMs: 24500, random: 0.5, resends: 1, mayHaveRun: true, outcome: err(429, 'request_limit_reached'), expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_address_conflict', description: 'address_derivation_conflict is a collision with no side effect: one retry at once, as the docs say, signed again with a new nonce: nothing was executed, and with the same nonce the gateway would only replay the 409.', operation: 'write', keyMode: 'keypair', outcome: err(409, 'address_derivation_conflict'), expected: R('retry', { mode: 'resign', delayMs: 0 }) },
        { name: 'write_address_conflict_twice', description: 'Only one such retry.', operation: 'write', keyMode: 'keypair', attempt: 2, conflictRetried: true, outcome: err(409, 'address_derivation_conflict'), expected: R('return') },
        { name: 'write_vault_accounts_conflict', description: 'vault_accounts_creation_failed likewise: nothing was executed, so the one retry gets a new nonce.', operation: 'write', keyMode: 'keypair', outcome: err(409, 'vault_accounts_creation_failed'), expected: R('retry', { mode: 'resign', delayMs: 0 }) },
        { name: 'write_conflict_after_possible_run', description: 'Not re-signed when an earlier attempt may have run: the error is returned.', operation: 'write', keyMode: 'keypair', attempt: 2, resends: 1, mayHaveRun: true, outcome: err(409, 'address_derivation_conflict'), expected: R('return') },
        { name: 'write_double_spending', description: 'A business 409 is returned.', operation: 'write', keyMode: 'keypair', outcome: err(409, 'double_spending'), expected: R('return') },
        { name: 'write_nonce_reused', description: '409 api_nonce_reused: the nonce was used before for a different request; returned (a RequestSigningError), never retried.', operation: 'write', keyMode: 'keypair', outcome: err(409, 'api_nonce_reused'), expected: R('return') },
        { name: 'write_in_progress_first_send', description: '409 duplicate_api_request_in_progress to a first send (an earlier request with this nonce is still running): unknown, in progress.', operation: 'write', keyMode: 'keypair', outcome: err(409, 'duplicate_api_request_in_progress'), expected: R('outcome_unknown', { inProgress: true }) },
        { name: 'write_forbidden', description: 'A 403 is returned.', operation: 'write', keyMode: 'keypair', outcome: err(403, 'wallet_as_a_service_wallet_balance_not_enough'), expected: R('return') },
        { name: 'write_verification_failed', description: 'Never retried.', operation: 'write', keyMode: 'keypair', outcome: VERIFICATION_FAILED, expected: R('fail') },
        { name: 'write_not_sent_last_attempt', description: 'Out of attempts, nothing ever sent: the transport error.', operation: 'write', keyMode: 'keypair', attempt: 5, outcome: NOT_SENT, expected: R('fail') },
        { name: 'write_not_sent_last_attempt_after_possible_run', description: 'Out of attempts after an attempt that may have run: unknown.', operation: 'write', keyMode: 'keypair', attempt: 5, mayHaveRun: true, outcome: NOT_SENT, expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_429_last_attempt', description: 'Out of attempts on a 429 that never ran: the RateLimitError.', operation: 'write', keyMode: 'keypair', attempt: 5, outcome: err(429, 'request_limit_reached'), expected: R('return') },
        { name: 'write_500_last_attempt', description: 'Out of attempts on a 5xx: unknown.', operation: 'write', keyMode: 'keypair', attempt: 5, sinceFirstSendMs: 300, outcome: err(503, null), expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'write_not_sent_deadline', description: 'A backoff past the 30 s deadline: no retry; nothing was sent.', operation: 'write', keyMode: 'keypair', attempt: 3, elapsedMs: 28000, signedAgeMs: 100, random: 0.9, outcome: NOT_SENT, expected: R('fail') },

        // Writes with a legacy key, or a key pair not confirmed active: replay protection may only report
        { name: 'legacy_sent_unknown', description: 'A timeout after sending: never resent, since the gateway may not refuse a duplicate; unknown.', operation: 'write', keyMode: 'legacy', sinceFirstSendMs: 300, outcome: SENT_UNKNOWN, expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'legacy_500', description: 'A 5xx: unknown.', operation: 'write', keyMode: 'legacy', sinceFirstSendMs: 300, outcome: err(500, 'unexpected_server_error'), expected: R('outcome_unknown', { inProgress: false }) },
        { name: 'legacy_not_sent', description: 'Certainly not sent, so it cannot have run: resent after a backoff.', operation: 'write', keyMode: 'legacy', attempt: 1, signedAgeMs: 50, random: 0.5, outcome: NOT_SENT, expected: R('retry', { mode: 'resend', delayMs: 500 }) },
        { name: 'legacy_429', description: 'A 429 never ran: resent after a backoff.', operation: 'write', keyMode: 'legacy', attempt: 1, signedAgeMs: 200, random: 0.5, outcome: err(429, 'request_limit_reached'), expected: R('retry', { mode: 'resend', delayMs: 500 }) },
        { name: 'legacy_429_signature_too_old', description: 'Re-signed when the signature would be too old.', operation: 'write', keyMode: 'legacy', attempt: 1, signedAgeMs: 24900, random: 0.5, outcome: err(429, 'request_limit_reached'), expected: R('retry', { mode: 'resign', delayMs: 500 }) },
        { name: 'legacy_429_retry_after', description: 'Retry-After honoured.', operation: 'write', keyMode: 'legacy', attempt: 1, signedAgeMs: 100, random: 0.1, outcome: err(429, 'request_limit_reached', { retryAfterSeconds: 2 }), expected: R('retry', { mode: 'resend', delayMs: 2000 }) },
        { name: 'legacy_created', description: 'A 2xx is returned.', operation: 'write', keyMode: 'legacy', outcome: ok(201), expected: R('return') },
        { name: 'legacy_in_progress', description: 'duplicate_api_request_in_progress: unknown, in progress.', operation: 'write', keyMode: 'legacy', outcome: err(409, 'duplicate_api_request_in_progress'), expected: R('outcome_unknown', { inProgress: true }) },
        { name: 'legacy_address_conflict', description: 'The conflict retry, with its new nonce, does not depend on the key.', operation: 'write', keyMode: 'legacy', outcome: err(409, 'address_derivation_conflict'), expected: R('retry', { mode: 'resign', delayMs: 0 }) },
    ];

    // The delays above are written by hand; they must be the full-jitter values of the rules.
    for (const spec of specs) {
        if (spec.expected.action === 'retry' && spec.expected.delayMs > 0) {
            const backoff = jitter(spec.attempt || 1, spec.random === undefined ? 0.5 : spec.random);
            const after = spec.outcome.retryAfterSeconds ? spec.outcome.retryAfterSeconds * 1000 : 0;
            if (spec.expected.delayMs !== Math.max(backoff, after)) {
                throw new Error(`${spec.name}: delay ${spec.expected.delayMs}, the rules give ${Math.max(backoff, after)}`);
            }
        }
    }

    return {
        format: 'vaultody retry decisions, v1',
        source: SOURCE,
        constants: RETRY,
        rules: {
            classes: 'read: GET and validateAddress, estimateTransactionFeeByAssetId, validateUtxoTransfer (contract/overlay.json retry). write: every other POST and PUT. keyMode keypair: the key pair was confirmed active through listApiKeySigningKeys, so replay protection always refuses a duplicate; legacy: no key pair, or one not confirmed, where prod replay protection may only report.',
            order: [
                'verification_failed: fail (never retried).',
                '2xx: return.',
                'write, 409 duplicate_api_request_in_progress: outcome_unknown, inProgress.',
                'write, 401 duplicate_api_request when resends > 0: outcome_unknown.',
                'write, a replayed 5xx: outcome_unknown.',
                'address_derivation_conflict or vault_accounts_creation_failed, not retried yet and (for a write) mayHaveRun false: retry, resign with a new nonce, no delay; otherwise return.',
                'read: not_sent, sent_unknown, 429 and 5xx retry, re-signed, after the backoff; any other status returns.',
                'write, sent_unknown or a 5xx: keypair, resends 0 and sinceFirstSendMs < resendWindowMs: retry, resend, no delay; otherwise outcome_unknown.',
                'write, not_sent or 429 (neither ran): after the backoff, resend while signedAgeMs + delay < signatureMaxAgeMs; else resign if mayHaveRun is false; else outcome_unknown.',
                'write, any other status: return.',
            ],
            backoff: 'full jitter: floor(random × min(maxDelayMs, baseDelayMs × 2^(attempt − 1))), raised to Retry-After seconds × 1000 when the response carries a longer one',
            budget: 'No retry when attempt >= maxAttempts or elapsedMs + delay > deadlineMs. Then: a read returns the response or fails with the transport error; a write is outcome_unknown when this attempt or an earlier one may have run (sent_unknown, 5xx, mayHaveRun), else returns or fails the same way.',
            mayHaveRun: 'Whether an earlier attempt of the same call may have been carried out: sent_unknown and 5xx may have; not_sent and 429 did not.',
            nonce: 'Every retry of a write keeps the call\'s x-api-nonce and its body (nonce: same): resend sends the same signed request again; resign signs it again with a fresh x-api-timestamp and fresh signatures over the same nonce, so the gateway\'s idempotency (per API key and nonce) sees one operation. One exception: the one immediate retry after address_derivation_conflict or vault_accounts_creation_failed, which say that nothing was executed, is signed again with a new nonce and the same body (nonce: new); with the same nonce the gateway would only replay the 409. Later retries of that call keep the new nonce. A read re-signed gets a new nonce (nonce: new). A new call always gets a new nonce.',
        },
        caseFormat: {
            input: 'operation, keyMode, attempt (attempts made, this one included), elapsedMs (since the call started), signedAgeMs (age of the current signature), sinceFirstSendMs (since the current signed request was first sent), resends (of the current signed request before this attempt), mayHaveRun, conflictRetried, random (the jitter draw in [0, 1)), outcome',
            outcome: '{ type: not_sent | sent_unknown | verification_failed } or { type: response, status, code, replayed, retryAfterSeconds }',
            expected: '{ action: return | fail } | { action: retry, mode: resign | resend, nonce: same | new, delayMs } | { action: outcome_unknown, inProgress }',
        },
        cases: specs.map(retryCase),
    };
}

// ---------------------------------------------------------------------------------------------------
// Transport errors: was the request sent?
// ---------------------------------------------------------------------------------------------------

function buildTransportErrors() {
    const fetchFailed = (code, extra = {}) => ({ name: 'TypeError', message: 'fetch failed', cause: { name: 'Error', code, ...extra } });
    const node = [
        ['connection_refused', 'ECONNREFUSED', false],
        ['dns_not_found', 'ENOTFOUND', false],
        ['dns_try_again', 'EAI_AGAIN', false],
        ['connect_timeout', 'UND_ERR_CONNECT_TIMEOUT', false],
        ['certificate_expired', 'CERT_HAS_EXPIRED', false],
        ['certificate_unverified', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', false],
        ['certificate_self_signed', 'DEPTH_ZERO_SELF_SIGNED_CERT', false],
        ['certificate_self_signed_chain', 'SELF_SIGNED_CERT_IN_CHAIN', false],
        ['certificate_issuer_unknown', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', false],
        ['certificate_not_yet_valid', 'CERT_NOT_YET_VALID', false],
        ['certificate_wrong_host', 'ERR_TLS_CERT_ALTNAME_INVALID', false],
        ['connection_reset', 'ECONNRESET', 'unknown'],
        ['os_timeout', 'ETIMEDOUT', 'unknown'],
        ['broken_pipe', 'EPIPE', 'unknown'],
        ['socket_closed', 'UND_ERR_SOCKET', 'unknown'],
        ['headers_timeout', 'UND_ERR_HEADERS_TIMEOUT', 'unknown'],
        ['body_timeout', 'UND_ERR_BODY_TIMEOUT', 'unknown'],
    ].map(([name, code, sent]) => ({ name, error: fetchFailed(code), expected: { sent } }));
    node.push(
        { name: 'all_addresses_refused', error: { name: 'TypeError', message: 'fetch failed', cause: { name: 'AggregateError', code: 'ECONNREFUSED', errors: [{ name: 'Error', code: 'ECONNREFUSED' }, { name: 'Error', code: 'ECONNREFUSED' }] } }, expected: { sent: false } },
        { name: 'addresses_mixed', error: { name: 'TypeError', message: 'fetch failed', cause: { name: 'AggregateError', errors: [{ name: 'Error', code: 'ECONNREFUSED' }, { name: 'Error', code: 'ETIMEDOUT' }] } }, expected: { sent: 'unknown' } },
        { name: 'nested_cause', error: { name: 'TypeError', message: 'fetch failed', cause: { name: 'Error', message: 'wrapped', cause: { name: 'Error', code: 'ENOTFOUND' } } }, expected: { sent: false } },
        { name: 'abort', error: { name: 'AbortError', message: 'This operation was aborted' }, expected: { sent: 'unknown' } },
        { name: 'timeout_signal', error: { name: 'TimeoutError', message: 'The operation was aborted due to timeout' }, expected: { sent: 'unknown' } },
        { name: 'no_code', error: { name: 'TypeError', message: 'fetch failed', cause: { name: 'Error', message: 'other side closed' } }, expected: { sent: 'unknown' } },
    );

    const python = [
        ['ConnectError', false], ['ConnectTimeout', false],
        ['ReadTimeout', 'unknown'], ['WriteTimeout', 'unknown'], ['PoolTimeout', 'unknown'], ['ReadError', 'unknown'], ['WriteError', 'unknown'],
        ['RemoteProtocolError', 'unknown'], ['LocalProtocolError', 'unknown'], ['ProxyError', 'unknown'], ['UnsupportedProtocol', 'unknown'],
        ['CloseError', 'unknown'], ['NetworkError', 'unknown'], ['TimeoutException', 'unknown'], ['TransportError', 'unknown'],
    ].map(([exception, sent]) => ({ name: exception, exception: `httpx.${exception}`, expected: { sent } }));

    const php = [
        [6, 'CURLE_COULDNT_RESOLVE_HOST', false], [7, 'CURLE_COULDNT_CONNECT', false], [35, 'CURLE_SSL_CONNECT_ERROR', false], [60, 'CURLE_PEER_FAILED_VERIFICATION', false],
        [28, 'CURLE_OPERATION_TIMEDOUT', 'unknown'], [52, 'CURLE_GOT_NOTHING', 'unknown'], [55, 'CURLE_SEND_ERROR', 'unknown'], [56, 'CURLE_RECV_ERROR', 'unknown'], [18, 'CURLE_PARTIAL_FILE', 'unknown'],
    ].map(([errno, constant, sent]) => ({ name: constant, curlErrno: errno, expected: { sent } }));

    return {
        format: 'vaultody transport error classification, v1',
        source: SOURCE,
        rules: {
            sent: 'false only when the client library proves the request never left: the name could not be resolved, the connection was refused or timed out while connecting, or the TLS handshake (certificate) failed. Everything else is "unknown": the request may have reached the gateway. A write whose sending is unknown is never treated as not sent (retry-v1.json).',
            node: 'fetch (undici) wraps the cause: walk error.cause; an AggregateError (one error per address tried) is not sent only when every error in it is. Codes that mean not sent: ECONNREFUSED, ENOTFOUND, EAI_AGAIN, UND_ERR_CONNECT_TIMEOUT and the certificate codes listed.',
            python: 'httpx: ConnectError and ConnectTimeout (and their subclasses) are not sent; every other httpx exception is unknown.',
            php: 'curl: errno 6, 7, 35 and 60 are not sent; anything else is unknown. Runner pending: the PHP transport comes later.',
        },
        caseFormat: { node: 'an error described by name, message, code, cause and errors, to rebuild as Error objects', python: 'an httpx exception class', php: 'a curl errno', expected: '{ sent: false | "unknown" }' },
        node,
        python,
        php,
    };
}

// ---------------------------------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------------------------------

/** What Vaultody sends with a webhook delivery: HMAC-SHA256 keyed with the secret (UTF-8) over JSON.stringify(body), lowercase hex. */
const webhookSignature = (bodyText, secret) => crypto.createHmac('sha256', secret).update(bodyText).digest('hex');

function buildWebhook() {
    const SECRET_A = 'TEST-ONLY webhook signing secret A';
    const SECRET_B = 'TEST-ONLY webhook signing secret B';
    const SECRET_UNICODE = 'TEST-ONLY тайна ✓ 秘密';
    const payload = {
        walletId: '685121237d7d1e0007ac1a1d',
        webhookId: '68516e9c6620b0a4790ed541',
        idempotencyKey: '1f232491a0f5b5e32165546e80c36c9f8046f6581eca26c62542dbc8ec4f0fa1',
        apiVersion: '2026-03-20',
        data: {
            event: 'TRANSACTION_REQUEST',
            item: { vaultAccountId: '69ba58c529eb49000746b311', assetId: '6913471c6b2794841dc8fb6f', unit: 'ETH', requestId: '686cd2860ca2f4fd25f77099', transactionType: 'COIN' },
        },
    };
    const body = JSON.stringify(payload);
    const unicodeBody = JSON.stringify({ ...payload, data: { ...payload.data, item: { ...payload.data.item, note: 'Сметка ✓ 東京' } } });
    const tampered = body.replace('"unit":"ETH"', '"unit":"BTC"');
    const pretty = JSON.stringify(payload, null, 2);
    const sig = webhookSignature(body, SECRET_A);

    const c = (name, description, { bodyText = body, headers, secrets = [SECRET_A], expected }) => ({ name, description, bodyBase64: b64(utf8(bodyText)), headers, secrets, expected });

    return {
        format: 'vaultody webhook signature X-Signature, v1',
        warning: 'TEST-ONLY secrets.',
        source: { ...SOURCE, signer: 'Vaultody\'s webhook delivery: HMAC-SHA256 keyed with the webhook\'s signing secret over JSON.stringify(body), hex, sent as X-Signature with JSON.stringify of the same body' },
        rules: {
            header: 'X-Signature, name matched case-insensitively. Absent or empty: missing. Anything but exactly 64 lowercase hex characters: malformed (no trimming, no case folding).',
            signature: 'lowercase hex of HMAC-SHA256 keyed with the secret\'s UTF-8 bytes over the raw body bytes as received; compared in constant time with each configured secret, in order',
            verdict: 'valid with the index of the first secret that matches (several secrets cover a rotation); otherwise mismatch. The body is parsed only after this.',
            replay: 'The scheme has no timestamp, so it does not protect against a delivery being sent again, and Vaultody may deliver the same event more than once. A receiver checks whether it already acted on an event, keyed on what the event is about, as the Webhook Notifications page of the docs says: outgoing transaction events data.item.requestId and data.event; incoming ones data.item.transactionId, data.item.address, data.event and data.item.currentConfirmations (an internal transfer: data.item.parentTransactionId and data.item.operationId in place of transactionId).',
        },
        caseFormat: { bodyBase64: 'the raw body as received', headers: 'the request headers', secrets: 'the signing secrets configured, in order', expected: '{ valid: true, secretIndex } or { valid: false, reason: missing | malformed | mismatch }' },
        cases: [
            c('valid', 'A delivery signed with the secret.', { headers: { 'X-Signature': sig }, expected: { valid: true, secretIndex: 0 } }),
            c('header_lowercase', 'The header name in lowercase, as most servers hand it over.', { headers: { 'x-signature': sig }, expected: { valid: true, secretIndex: 0 } }),
            c('header_uppercase', 'The header name in uppercase.', { headers: { 'X-SIGNATURE': sig }, expected: { valid: true, secretIndex: 0 } }),
            c('unicode_body', 'A body with non-ASCII text: the HMAC covers its UTF-8 bytes.', { bodyText: unicodeBody, headers: { 'X-Signature': webhookSignature(unicodeBody, SECRET_A) }, expected: { valid: true, secretIndex: 0 } }),
            c('unicode_secret', 'A secret with non-ASCII characters keys the HMAC with its UTF-8 bytes.', { headers: { 'X-Signature': webhookSignature(body, SECRET_UNICODE) }, secrets: [SECRET_UNICODE], expected: { valid: true, secretIndex: 0 } }),
            c('rotation_new_secret', 'During a rotation both secrets are configured; signed with the new one (second).', { headers: { 'X-Signature': webhookSignature(body, SECRET_B) }, secrets: [SECRET_A, SECRET_B], expected: { valid: true, secretIndex: 1 } }),
            c('rotation_old_secret', 'Signed with the old one (first).', { headers: { 'X-Signature': sig }, secrets: [SECRET_A, SECRET_B], expected: { valid: true, secretIndex: 0 } }),
            c('tampered_body', 'The body changed after signing.', { bodyText: tampered, headers: { 'X-Signature': sig }, expected: { valid: false, reason: 'mismatch' } }),
            c('reserialised_body', 'The same JSON re-serialised with spaces: the raw body is signed, not the parsed one.', { bodyText: pretty, headers: { 'X-Signature': sig }, expected: { valid: false, reason: 'mismatch' } }),
            c('trailing_newline', 'A newline added to the body.', { bodyText: `${body}\n`, headers: { 'X-Signature': sig }, expected: { valid: false, reason: 'mismatch' } }),
            c('wrong_secret', 'Signed with another secret.', { headers: { 'X-Signature': webhookSignature(body, SECRET_B) }, expected: { valid: false, reason: 'mismatch' } }),
            c('uppercase_hex', 'The right digest in uppercase hex.', { headers: { 'X-Signature': sig.toUpperCase() }, expected: { valid: false, reason: 'malformed' } }),
            c('missing_header', 'No X-Signature.', { headers: { 'Content-Type': 'application/json' }, expected: { valid: false, reason: 'missing' } }),
            c('empty_header', 'An empty X-Signature.', { headers: { 'X-Signature': '' }, expected: { valid: false, reason: 'missing' } }),
            c('short_signature', '63 hex characters.', { headers: { 'X-Signature': sig.slice(0, 63) }, expected: { valid: false, reason: 'malformed' } }),
            c('signature_with_space', 'A trailing space.', { headers: { 'X-Signature': `${sig} ` }, expected: { valid: false, reason: 'malformed' } }),
            c('base64_signature', 'The digest in base64 instead of hex.', { headers: { 'X-Signature': crypto.createHmac('sha256', SECRET_A).update(body).digest('base64') }, expected: { valid: false, reason: 'malformed' } }),
            c('prefixed_signature', 'A "sha256=" prefix, as other providers write it.', { headers: { 'X-Signature': `sha256=${sig}` }, expected: { valid: false, reason: 'malformed' } }),
        ],
    };
}

// ---------------------------------------------------------------------------------------------------
// The vault keys file (docs/vault-keys-file.md, docs/vault-keys-file-v1.schema.json)
// ---------------------------------------------------------------------------------------------------

/** The canonical bytes of a vault keys file: keys sorted at every level, two-space indent, a final newline. */
function canonicalJson(value) {
    const sorted = v => {
        if (Array.isArray(v)) {
            return v.map(sorted);
        }
        if (v !== null && typeof v === 'object') {
            return Object.fromEntries(Object.keys(v).sort().map(key => [key, sorted(v[key])]));
        }

        return v;
    };

    return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function buildVaultKeysFile() {
    const TAG = 'vaultody vault keys v1';
    const PROD = 'https://rest.vaultody.com';
    const TEST = 'https://rest.example.test';
    const LOOPBACK = 'http://127.0.0.1:8080';
    const IPV6 = 'http://[::1]:8080';
    // Public test xpubs (vault-key-pins-v1.json); the root id is the TEST-ONLY root of v1.json.
    const ECDSA = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
    const EDDSA = 'xpub661MyMwAqRbcF7h9JXx6VX3d8mX4C8QH6cefjAYGCRSHMYwa9YgFeobgfZ93e4dCrsQTxU2dAn4KBPxaNjRvT4UswSmSkWpBP9gn6LSzRGH';
    const ROOT_ID = 'b8db84bfef783441332173f1c099c89df45f4ef86258d1b582f43c501d62a9df';
    const VAULT_A = '6630f1c2a9e4b5d7c8e9f0a1';
    const VAULT_B = '6630f1c2a9e4b5d7c8e9f0b2';
    const VAULT_C = '6630f1c2a9e4b5d7c8e9f0c3';

    const unverified = (vaultId, keys = { ECDSA, EDDSA }, type = 'main') => ({
        vaultId, type, keys, status: 'unverified', firstSeenAt: 1794200000, verifiedAt: null, verification: null,
    });
    const verified = (vaultId, keys = { ECDSA, EDDSA }, type = 'main') => ({
        vaultId, type, keys, status: 'verified', firstSeenAt: 1794200000, verifiedAt: 1794201002, verification: { rootId: ROOT_ID, timestamp: 1794201000 },
    });
    const latch = { latchedAt: 1794201002, rootId: ROOT_ID };
    const entry = ({ responseSignature = null, vaults = [], audit = [] } = {}) => ({
        responseSignature, vaults: Object.fromEntries(vaults.map(pin => [pin.vaultId, pin])), audit,
    });
    const doc = origins => ({ format: TAG, origins });
    const pretty = value => `${JSON.stringify(value, null, 2)}\n`;

    const documents = {
        empty: doc({}),
        tofu_pin: doc({ [PROD]: entry({ vaults: [unverified(VAULT_A)] }) }),
        verified_pin_and_latch: doc({ [PROD]: entry({ responseSignature: latch, vaults: [verified(VAULT_A)] }) }),
        two_origins: doc({
            [PROD]: entry({ responseSignature: latch, vaults: [verified(VAULT_A), unverified(VAULT_B, { ECDSA, EDDSA: null }, 'test')] }),
            [LOOPBACK]: entry({ vaults: [unverified(VAULT_C, { ECDSA: null, EDDSA })] }),
        }),
        latch_only: doc({ [TEST]: entry({ responseSignature: latch }) }),
        latch_unverified: doc({ [PROD]: entry({ responseSignature: { latchedAt: 1794201002, rootId: null }, vaults: [unverified(VAULT_A)] }) }),
        audit_entries: doc({
            [PROD]: entry({
                vaults: [verified(VAULT_A)],
                audit: [
                    { vaultId: VAULT_A, at: 1794300000, reason: 'xpub confirmed with Vaultody support, ticket TEST-1', removed: false },
                    { vaultId: VAULT_B, at: 1794300100, reason: 'vault deleted', removed: true },
                ],
            }),
        }),
        unicode_reason: doc({ [PROD]: entry({ vaults: [unverified(VAULT_A)], audit: [{ vaultId: VAULT_A, at: 0, reason: 'потвърдено ✓ 確認', removed: false }] }) }),
        time_bounds: doc({ [PROD]: entry({ responseSignature: { latchedAt: 9007199254740991, rootId: ROOT_ID }, vaults: [{ ...unverified(VAULT_A), firstSeenAt: 0 }] }) }),
        ipv6_origin: doc({ [IPV6]: entry({ vaults: [unverified(VAULT_A, { ECDSA, EDDSA: null }, 'test')] }) }),
    };

    const valid = [
        ['empty', 'No origin yet: what a store that has pinned nothing would hold.', pretty(documents.empty)],
        ['tofu_pin', 'One vault pinned from an unsigned answer (trust on first use); no latch.', pretty(documents.tofu_pin)],
        ['verified_pin_and_latch', 'A verified pin and the latch, as after the first signed vault list.', pretty(documents.verified_pin_and_latch)],
        ['two_origins', 'Two origins: one signs (latch, a verified main pin, an unverified test pin with ECDSA only), one is a loopback test gateway (EDDSA only).', pretty(documents.two_origins)],
        ['latch_only', 'The latch set and no pin yet.', pretty(documents.latch_only)],
        ['latch_unverified', 'The latch set by a signed answer that did not verify (refused, or no root to check it with): rootId null.', pretty(documents.latch_unverified)],
        ['audit_entries', 'Two audit entries: a pin replaced after an out-of-band check, and one removed.', pretty(documents.audit_entries)],
        ['unicode_reason', 'An audit reason in UTF-8 that is not ASCII.', pretty(documents.unicode_reason)],
        ['time_bounds', 'Times at both bounds: 0 and 2^53 − 1.', pretty(documents.time_bounds)],
        ['ipv6_origin', 'A loopback IPv6 origin.', pretty(documents.ipv6_origin)],
        ['minified', 'The verified_pin_and_latch content minified and with its keys in another order: readers do not require the canonical form.',
            '{"origins":{"https://rest.vaultody.com":{"vaults":{"6630f1c2a9e4b5d7c8e9f0a1":{"verification":{"timestamp":1794201000,"rootId":"'
            + ROOT_ID + '"},"verifiedAt":1794201002,"vaultId":"6630f1c2a9e4b5d7c8e9f0a1","type":"main","status":"verified","keys":{"EDDSA":"' + EDDSA
            + '","ECDSA":"' + ECDSA + '"},"firstSeenAt":1794200000}},"responseSignature":{"rootId":"' + ROOT_ID
            + '","latchedAt":1794201002},"audit":[]}},"format":"vaultody vault keys v1"}'],
    ].map(([name, description, text]) => ({ name, description, text, expected: { origins: JSON.parse(text).origins } }));
    if (canonicalJson(JSON.parse(valid.find(c => c.name === 'minified').text)) !== canonicalJson(documents.verified_pin_and_latch)) {
        throw new Error('minified differs from verified_pin_and_latch');
    }

    // Invalid files: start from a valid document and change one thing.
    const base = () => JSON.parse(JSON.stringify(documents.two_origins));
    const change = fn => {
        const d = base();
        fn(d, d.origins[PROD], d.origins[PROD].vaults[VAULT_A]);

        return pretty(d);
    };
    const invalid = [
        // not_json
        ['empty_file', 'An empty file.', '', 'not_json'],
        ['syntax_error', 'Not JSON.', '{"format": "vaultody vault keys v1", "origins": {', 'not_json'],
        ['byte_order_mark', 'A UTF-8 byte-order mark before the JSON.', `﻿${pretty(documents.empty)}`, 'not_json'],
        ['invalid_utf8', 'Bytes that are not UTF-8 inside a string (base64: the text holds 0xC3 0x28).', { base64: Buffer.concat([utf8('{"format":"vaultody vault keys v1","origins":{"https://rest.vaultody.com":{"responseSignature":null,"vaults":{},"audit":[{"vaultId":"a","at":1,"reason":"'), Buffer.from([0xc3, 0x28]), utf8('","removed":false}]}}}\n')]).toString('base64') }, 'not_json'],
        // unknown_format
        ['top_level_array', 'The top level is an array.', '[]\n', 'unknown_format'],
        ['top_level_null', 'The top level is null.', 'null\n', 'unknown_format'],
        ['no_format', 'No format tag.', pretty({ origins: {} }), 'unknown_format'],
        ['format_v2', 'A version this SDK does not know.', pretty({ format: 'vaultody vault keys v2', origins: {} }), 'unknown_format'],
        ['format_case', 'The tag in another case.', pretty({ format: 'Vaultody vault keys v1', origins: {} }), 'unknown_format'],
        ['format_not_string', 'The tag is a number.', pretty({ format: 1, origins: {} }), 'unknown_format'],
        // malformed: the top level
        ['unknown_top_level_field', 'An extra field next to format and origins.', pretty({ ...documents.empty, version: 1 }), 'malformed'],
        ['no_origins', 'No origins.', pretty({ format: TAG }), 'malformed'],
        ['origins_array', 'origins is an array.', pretty({ format: TAG, origins: [] }), 'malformed'],
        ['origin_without_scheme', 'An origin key that is a host name.', pretty(doc({ 'rest.vaultody.com': entry() })), 'malformed'],
        ['origin_with_path', 'An origin key with a path.', pretty(doc({ 'https://rest.vaultody.com/v2': entry() })), 'malformed'],
        ['origin_trailing_slash', 'An origin key with a trailing slash.', pretty(doc({ 'https://rest.vaultody.com/': entry() })), 'malformed'],
        // malformed: an origin entry, including the earlier per-language layouts
        ['php_layout', 'The layout PHP wrote before v1 was unified: pins and signedResponses.', pretty(doc({ [PROD]: { signedResponses: true, pins: { [VAULT_A]: verified(VAULT_A) } } })), 'malformed'],
        ['python_latch_key', 'The latch under the key Python used before: strict.', pretty(doc({ [PROD]: { vaults: {}, strict: { since: 1, rootId: ROOT_ID }, audit: [] } })), 'malformed'],
        ['no_audit', 'An origin entry without audit (the layout Node wrote before).', pretty(doc({ [PROD]: { responseSignature: null, vaults: {} } })), 'malformed'],
        ['no_latch_key', 'An origin entry without responseSignature.', pretty(doc({ [PROD]: { vaults: {}, audit: [] } })), 'malformed'],
        ['unknown_origin_field', 'An extra field in an origin entry.', change((d, prod) => { prod.note = 'x'; }), 'malformed'],
        ['origin_entry_null', 'An origin entry that is null.', pretty(doc({ [PROD]: null })), 'malformed'],
        ['vaults_array', 'vaults is an empty array, not an object (what a JSON encoder that cannot tell them apart writes).', pretty(doc({ [PROD]: { responseSignature: null, vaults: [], audit: [] } })), 'malformed'],
        // malformed: the latch
        ['latch_true', 'The latch as a boolean.', change((d, prod) => { prod.responseSignature = true; }), 'malformed'],
        ['latch_no_root', 'The latch without rootId.', change((d, prod) => { prod.responseSignature = { latchedAt: 1794201002 }; }), 'malformed'],
        ['latch_empty_root', 'The latch with an empty rootId.', change((d, prod) => { prod.responseSignature = { latchedAt: 1794201002, rootId: '' }; }), 'malformed'],
        ['latch_root_number', 'The latch with a rootId that is neither text nor null.', change((d, prod) => { prod.responseSignature = { latchedAt: 1794201002, rootId: 1 }; }), 'malformed'],
        ['latch_extra_field', 'The latch with a field more (Python wrote responseTimestamp before).', change((d, prod) => { prod.responseSignature = { ...latch, responseTimestamp: 1794201000 }; }), 'malformed'],
        ['latch_time_string', 'latchedAt as a string.', change((d, prod) => { prod.responseSignature = { ...latch, latchedAt: '1794201002' }; }), 'malformed'],
        // malformed: a pin
        ['pin_under_other_id', 'A pin stored under another vault id.', change((d, prod) => { prod.vaults.other = prod.vaults[VAULT_A]; delete prod.vaults[VAULT_A]; }), 'malformed'],
        ['bad_status', 'A status that does not exist.', change((d, prod, pin) => { pin.status = 'trusted'; }), 'malformed'],
        ['verified_without_evidence', 'verified with verification null.', change((d, prod, pin) => { pin.verification = null; }), 'malformed'],
        ['verified_without_time', 'verified with verifiedAt null.', change((d, prod, pin) => { pin.verifiedAt = null; }), 'malformed'],
        ['unverified_with_evidence', 'unverified with verifiedAt and verification set.', change((d, prod) => { prod.vaults[VAULT_B].verifiedAt = 1; prod.vaults[VAULT_B].verification = { rootId: ROOT_ID, timestamp: 1 }; }), 'malformed'],
        ['type_uppercase', 'The vault type in uppercase.', change((d, prod, pin) => { pin.type = 'MAIN'; }), 'malformed'],
        ['type_unknown', 'A vault type that is not main or test.', change((d, prod, pin) => { pin.type = 'smart'; }), 'malformed'],
        ['keys_missing_eddsa', 'keys without EDDSA.', change((d, prod, pin) => { delete pin.keys.EDDSA; }), 'malformed'],
        ['keys_both_null', 'keys with no xpub.', change((d, prod, pin) => { pin.keys = { ECDSA: null, EDDSA: null }; }), 'malformed'],
        ['keys_extra_algorithm', 'keys with an algorithm the SDK does not pin.', change((d, prod, pin) => { pin.keys.SCHNORR = ECDSA; }), 'malformed'],
        ['xpub_empty', 'An empty xpub.', change((d, prod, pin) => { pin.keys.ECDSA = ''; }), 'malformed'],
        ['xpub_number', 'An xpub that is a number.', change((d, prod, pin) => { pin.keys.ECDSA = 1; }), 'malformed'],
        ['pin_unknown_field', 'A pin with a field more (Node wrote replaced on a pin before).', change((d, prod, pin) => { pin.replaced = { reason: 'x', previous: 'present' }; }), 'malformed'],
        ['pin_missing_field', 'A pin without firstSeenAt.', change((d, prod, pin) => { delete pin.firstSeenAt; }), 'malformed'],
        ['verification_extra_field', 'verification with a field more.', change((d, prod, pin) => { pin.verification.keyId = 'k'; }), 'malformed'],
        ['verification_no_timestamp', 'verification without timestamp.', change((d, prod, pin) => { delete pin.verification.timestamp; }), 'malformed'],
        // malformed: times
        ['time_fraction', 'firstSeenAt with a fraction.', change((d, prod, pin) => { pin.firstSeenAt = 1794200000.5; }), 'malformed'],
        ['time_integral_fraction', 'firstSeenAt written as 1794200000.0: an integer value, but not an integer token.', pretty(documents.tofu_pin).replace('"firstSeenAt": 1794200000', '"firstSeenAt": 1794200000.0'), 'malformed'],
        ['time_exponent', 'firstSeenAt written with an exponent.', pretty(documents.tofu_pin).replace('"firstSeenAt": 1794200000', '"firstSeenAt": 1.7942e9'), 'malformed'],
        ['time_negative', 'A negative firstSeenAt.', change((d, prod, pin) => { pin.firstSeenAt = -1; }), 'malformed'],
        ['time_too_large', 'A time above 2^53 − 1.', pretty(documents.tofu_pin).replace('"firstSeenAt": 1794200000', '"firstSeenAt": 9007199254740992'), 'malformed'],
        ['time_string', 'firstSeenAt as a string.', change((d, prod, pin) => { pin.firstSeenAt = '1794200000'; }), 'malformed'],
        // malformed: audit
        ['audit_object', 'audit is an object.', change((d, prod) => { prod.audit = {}; }), 'malformed'],
        ['audit_entry_extra_field', 'An audit entry with a field more.', change((d, prod) => { prod.audit = [{ vaultId: VAULT_A, at: 1, reason: 'r', removed: false, by: 'admin' }]; }), 'malformed'],
        ['audit_removed_not_boolean', 'removed is not a boolean.', change((d, prod) => { prod.audit = [{ vaultId: VAULT_A, at: 1, reason: 'r', removed: 0 }]; }), 'malformed'],
        ['audit_blank_reason', 'A reason of spaces only.', change((d, prod) => { prod.audit = [{ vaultId: VAULT_A, at: 1, reason: '   ', removed: false }]; }), 'malformed'],
    ].map(([name, description, text, error]) => ({ name, description, ...(typeof text === 'string' ? { text } : text), expected: { error } }));

    const files = [
        ['missing', 'No file at the path: an empty store.', { absent: true }, { origins: {} }],
        ['mode_0600', 'The mode every SDK writes.', { mode: '0600', content: 'two_origins' }, { origins: documents.two_origins.origins }],
        ['mode_0644', 'Readable by others but writable only by its owner: accepted (writers still use 0600).', { mode: '0644', content: 'two_origins' }, { origins: documents.two_origins.origins }],
        ['group_writable', 'Writable by the group (0620).', { mode: '0620', content: 'two_origins' }, { error: 'insecure_permissions' }],
        ['world_writable', 'Writable by others (0602).', { mode: '0602', content: 'two_origins' }, { error: 'insecure_permissions' }],
        ['world_writable_and_malformed', 'Both writable by others and malformed: the mode is checked first.', { mode: '0666', content: 'invalid:bad_status' }, { error: 'insecure_permissions' }],
        ['symlink', 'A symbolic link (mode 0777 itself) to a valid file with mode 0600.', { symlinkTo: 'two_origins' }, { error: 'not_regular_file' }],
        ['directory', 'A directory at the path.', { directory: true }, { error: 'not_regular_file' }],
    ].map(([name, description, setup, expected]) => ({ name, description, posixOnly: Boolean(setup.mode || setup.symlinkTo), ...setup, expected }));

    // The bytes a writer produces for a content: keys sorted at every level, two-space indent, a final newline.
    const canonical = [
        ['empty', 'No origin.', documents.empty],
        ['two_origins', 'Two origins, three pins, a latch.', documents.two_origins],
        ['audit_entries', 'Audit entries keep their order (a list is never sorted).', documents.audit_entries],
        ['unicode_and_slashes', 'Non-ASCII text and "/" are written as they are, not escaped.', documents.unicode_reason],
        ['ipv6_origin', 'An IPv6 origin.', documents.ipv6_origin],
        ['latch_unverified', 'A latch whose rootId is null.', documents.latch_unverified],
    ].map(([name, description, document]) => ({ name, description, document, text: canonicalJson(document) }));
    for (const c of canonical) {
        if (/\\u[0-9a-f]{4}|\\\//i.test(c.text)) {
            throw new Error(`${c.name}: canonical text escapes a character`);
        }
    }

    return {
        format: 'vaultody vault keys file, v1',
        warning: 'TEST-ONLY: the xpubs are public test values (vault-key-pins-v1.json); the root id is the TEST-ONLY root of v1.json.',
        source: { ...SOURCE, schema: 'docs/vault-keys-file-v1.schema.json', doc: 'docs/vault-keys-file.md' },
        rules: {
            tag: 'format is exactly "vaultody vault keys v1"; anything else (another version, another case, missing, not a string, a top level that is not an object) is unknown_format. No migration from earlier layouts.',
            layout: '{ format, origins: { origin: { responseSignature: null | { latchedAt, rootId: text | null }, vaults: { vaultId: pin }, audit: [ { vaultId, at, reason, removed } ] } } }; the latch\'s rootId is null when the signed answer that set it did not verify; pin = { vaultId, type: main|test, keys: { ECDSA: xpub|null, EDDSA: xpub|null } (at least one xpub), status: verified|unverified, firstSeenAt, verifiedAt, verification: null | { rootId, timestamp } }; verified ⇔ verifiedAt and verification set.',
            strict: 'Every field is required and no other is allowed, at any level; anything that differs is malformed. A refused file is never treated as empty.',
            origin: 'scheme://host[:port] (http or https), no path, no trailing slash: ^https?://[^/?#@\\s]+$',
            times: 'Unix seconds, a JSON integer token (no fraction, no exponent), 0 to 2^53 − 1.',
            errors: 'VaultKeyStoreError with code not_json (not strict UTF-8 JSON, a byte-order mark, empty), unknown_format, malformed, insecure_permissions (POSIX mode & 022), not_regular_file (a symbolic link, a directory), too_large (over 16 MiB). Checked in that order of the file first: regular file, mode, size, then the bytes.',
            canonical: 'A writer writes UTF-8 with object keys sorted at every level, a two-space indent, ": " after a key, "/" and non-ASCII characters unescaped, and a final newline: JSON.stringify(sorted, null, 2) + "\\n", Python json.dumps(indent=2, sort_keys=True, ensure_ascii=False) + "\\n".',
            storeErrors: 'Besides the file codes above, VaultKeyStoreError has, the same in every language: unreadable (an I/O error reading), unwritable (it can\'t be written), locked (the lock was held for 10 s), invalid_pin (a pin or latch handed to the store that the file can\'t hold), store_conflict (a pin changed in the store between the client\'s read and its write, by another writer; nothing is returned, calling again reads afresh).',
            files: 'A missing file is an empty store. Writes: directory 0700, a temporary file 0600 in it, synced, renamed over the file; a read-change-write holds <file>.lock, created exclusively (O_CREAT|O_EXCL, 0600) and removed afterwards; a lock older than 30 s is stale; a writer gives up after 10 s (locked). Readers take no lock.',
        },
        caseFormat: {
            valid: '{ name, text, expected: { origins } }: the text parses, and for each origin the store lists exactly its pins (sorted by vaultId) and returns its latch',
            invalid: '{ name, text | base64, expected: { error } }: refused with that code',
            files: '{ name, mode | symlinkTo | directory | absent, content: a valid case name or "invalid:<name>", posixOnly, expected: { origins } | { error } }: the file is set up so, then read through the file store',
            canonical: '{ name, document, text }: what every SDK writes for document, byte for byte',
        },
        valid,
        invalid,
        files,
        canonical,
    };
}

// ---------------------------------------------------------------------------------------------------
// Security events and the per-answer results: names and fields every SDK uses
// ---------------------------------------------------------------------------------------------------

function buildSecurityEvents() {
    const event = (type, fields, alarm, when) => ({ type, fields: ['type', ...fields], alarm, when });

    return {
        format: 'vaultody security events, v1',
        source: { ...SOURCE, doc: 'docs/vault-keys-file.md' },
        rules: {
            names: 'The security-event hook (Node onSecurityEvent, Python on_security_event, PHP onSecurityEvent) is called only with these types, and every event has exactly the fields listed: no other, none missing (a value can be null where it is unknown, such as operationId outside the API methods). An event never carries a secret, an xpub or an address.',
            order: 'The hook is called before the error is thrown; an exception from the hook is swallowed so it can never hide the error.',
            alarm: 'alarm: an error follows (the answer is refused). The others are information.',
            logging: 'With no hook, every event is logged once at warning level as "Vaultody security event: " followed by its JSON (compact, keys in the catalogue\'s order, "/" and non-ASCII unescaped); with a hook, the hook gets it and nothing is logged. A hook that raises is logged once at warning level as "the security event hook raised on <type>; the call still fails or continues as it would". unsigned_response_accepted also has its own warning, hook or not.',
            results: 'addressCheck and vaultKeyResult are the entries of the per-answer results (Node meta.addressChecks / meta.vaultKeys, Python meta.address_checks / meta.vault_keys, PHP meta->addressChecks / meta->vaultKeys): objects with exactly these keys in every language; only the container\'s name follows the language\'s casing.',
        },
        caseFormat: { type: 'the event type', fields: 'its keys, type first', alarm: 'whether an error follows', when: 'when the SDK raises it' },
        events: [
            event('unsigned_response_accepted', ['origin', 'operationId'], false, 'when-present mode, before the latch: the first unsigned response a client accepts (once per client); one warning is logged after it'),
            event('response_signature_latched', ['origin', 'rootId', 'latchedAt'], false, 'the first answer from an origin that carries any of the four response-signature headers, whether it verifies or not (rootId null when it does not; raised before its error): unsigned responses are refused from then on (response-mode-v1.json)'),
            event('response_verification_failed', ['origin', 'operationId', 'status', 'reason'], true, 'a response fails its signature check (reason: missing, invalid, expired, unknown_root, request_unbound, unsupported_version, ...); ResponseVerificationError follows and it is never retried'),
            event('vault_key_pinned', ['origin', 'vaultId', 'status'], false, 'a vault is pinned for the first time (status verified or unverified)'),
            event('vault_key_verified', ['origin', 'vaultId', 'status'], false, 'an unverified pin is confirmed by a signed vault list (status verified)'),
            event('vault_key_changed', ['origin', 'alarms'], true, 'a vault list differs from a pin; alarms as in VaultKeyChangedError; VaultKeyChangedError follows'),
            event('address_verification_failed', ['origin', 'operationId', 'vaultId', 'code'], true, 'an address in an answer can\'t be accepted (code as in AddressVerificationError: mismatch, unsupported, unknown_vault, ...); AddressVerificationError follows'),
        ],
        alarm: { fields: ['vaultId', 'algorithm', 'reason', 'pinned', 'seen'], reasons: ['xpub_changed', 'xpub_missing', 'xpub_added', 'type_changed'] },
        // The codes of AddressVerificationError (and of address_verification_failed) every SDK uses for the checks it
        // makes itself; a derivation reason (unsupported_format, missing_key, not_verifiable, ...) passes through.
        addressCodes: [
            { code: 'mismatch', when: 'the address does not derive from the vault\'s pinned xpub; addAssetToVaultAccount answers another address than the one sent; an item that carries its derivation path names another blockchain than the one asked for' },
            { code: 'network_mismatch', when: 'an item that carries its derivation path names another network than the one asked for (generateDepositAddress), or the network does not go with the vault type (mainnet with a main vault, any other with a test vault)' },
            { code: 'invalid', when: 'an answer item without an address, or with path fields that can\'t be read' },
            { code: 'unsupported', when: 'the chain of an address with its path is not given, or is not one the SDK can derive' },
            { code: 'unknown_vault', when: 'the vault of the answer is in neither vault list' },
            { code: 'path_missing', when: 'with requireAddressPaths on (the default once the derivation paths are public), generateDepositAddress answers an address without accountIndex, isChange and addressIndex for a vault with MPC keys, on a chain the SDK can derive (vault-key-pins-v1.json addressChecks)' },
        ],
        addressCheck: { fields: ['vaultId', 'address', 'status'], status: ['verified', 'unverified', 'not_verifiable'] },
        vaultKeyResult: { fields: ['vaultId', 'status', 'outcome'], status: ['verified', 'unverified', 'not_verifiable'], outcome: ['pinned', 'unchanged', 'upgraded', 'not_verifiable'] },
    };
}

// ---------------------------------------------------------------------------------------------------
// The response-signature mode and the latch
// ---------------------------------------------------------------------------------------------------

function buildResponseMode() {
    const responses = readJson(path.join(VECTORS_DIR, 'v1.json'));
    const v1 = name => {
        const found = responses.cases.find(c => c.name === name);
        if (!found) {
            throw new Error(`v1.json has no case ${name}`);
        }

        return found;
    };
    const rootIdOf = name => responses.keys.roots[name].rootId;
    const RC = '0.9.0-rc.1';
    const STABLE = '1.0.0';
    const PREVIOUS_LATCH = { latchedAt: 1794200000, rootId: rootIdOf('current') };

    const config = [
        ['release_candidate_default', 'A release candidate with nothing configured: when-present, the bridge until production signs.', { rootsOption: false, embeddedRoots: false, version: RC, buildDefault: 'when-present', option: null }, { mode: 'when-present', warning: false }],
        ['release_candidate_required', 'responseSignature required: strict from the start.', { rootsOption: false, embeddedRoots: false, version: RC, buildDefault: 'when-present', option: 'required' }, { mode: 'required', warning: false }],
        ['release_candidate_when_present_given', 'when-present given and no roots: kept.', { rootsOption: false, embeddedRoots: false, version: RC, buildDefault: 'when-present', option: 'when-present' }, { mode: 'when-present', warning: false }],
        ['roots_option', 'The roots option given: strict, so a signature stripped from the first answer on is refused.', { rootsOption: true, embeddedRoots: false, version: RC, buildDefault: 'when-present', option: null }, { mode: 'required', warning: false }],
        ['roots_option_when_present_ignored', 'The roots option and when-present: strict all the same, and one warning that when-present is ignored.', { rootsOption: true, embeddedRoots: false, version: RC, buildDefault: 'when-present', option: 'when-present' }, { mode: 'required', warning: true }],
        ['roots_option_required', 'The roots option and required: strict, no warning.', { rootsOption: true, embeddedRoots: false, version: RC, buildDefault: 'when-present', option: 'required' }, { mode: 'required', warning: false }],
        ['release_candidate_embedded_root', 'A release candidate that embeds the root: when-present, so it bridges to signing; the first signed answer latches.', { rootsOption: false, embeddedRoots: true, version: RC, buildDefault: 'when-present', option: null }, { mode: 'when-present', warning: false }],
        ['release_candidate_embedded_root_when_present', 'A release candidate that embeds the root, when-present given: kept, no warning.', { rootsOption: false, embeddedRoots: true, version: RC, buildDefault: 'when-present', option: 'when-present' }, { mode: 'when-present', warning: false }],
        ['stable_embedded_root', 'A stable release embeds the root: strict.', { rootsOption: false, embeddedRoots: true, version: STABLE, buildDefault: 'required', option: null }, { mode: 'required', warning: false }],
        ['stable_embedded_root_when_present_ignored', 'A stable release with an embedded root and when-present given: strict, one warning.', { rootsOption: false, embeddedRoots: true, version: STABLE, buildDefault: 'required', option: 'when-present' }, { mode: 'required', warning: true }],
        ['stable_embedded_root_old_default', 'A stable version that embeds the root is strict even if its build default were still when-present (the release guard refuses that build).', { rootsOption: false, embeddedRoots: true, version: STABLE, buildDefault: 'when-present', option: null }, { mode: 'required', warning: false }],
        ['stable_without_root_build_default', 'A stable version without an embedded root (the release guard refuses that build): the build default decides.', { rootsOption: false, embeddedRoots: false, version: STABLE, buildDefault: 'required', option: null }, { mode: 'required', warning: false }],
        ['stable_without_root_when_present_given', 'A stable version without roots, when-present given: kept (nothing to be strict with).', { rootsOption: false, embeddedRoots: false, version: STABLE, buildDefault: 'required', option: 'when-present' }, { mode: 'when-present', warning: false }],
        ['release_candidate_two_digits', 'A release candidate numbered 12 is still a release candidate.', { rootsOption: false, embeddedRoots: true, version: '1.0.0-rc.12', buildDefault: 'when-present', option: null }, { mode: 'when-present', warning: false }],
    ].map(([name, description, given, expected]) => ({ name, description, ...given, expected }));

    // One answer: the mode in force, the roots the client checks a signature with, the latch before.
    const latched = (rootName, now) => ({ latchedAt: now, rootId: rootName === null ? null : rootIdOf(rootName) });
    const answer = (name, description, { mode, roots, latchedBefore = false, response }, expected) => {
        const now = v1(response === 'unsigned' ? 'missing_all' : response).verify.now;
        const latch = expected.latch === 'before' ? PREVIOUS_LATCH : (expected.latch === undefined ? null : latched(expected.latch, now));

        return { name, description, mode, roots, latchedBefore, answer: response, expected: { result: expected.result, latch, events: expected.events } };
    };
    const LATCHED = 'response_signature_latched';
    const FAILED = 'response_verification_failed';
    const UNSIGNED = 'unsigned_response_accepted';
    const answers = [
        // unsigned answers
        answer('unsigned_when_present', 'An unsigned answer to a release candidate before the latch: accepted unverified, reported once.',
            { mode: 'when-present', roots: false, response: 'unsigned' }, { result: 'absent', events: [UNSIGNED] }),
        answer('unsigned_when_present_with_roots', 'The same with an embedded root (a release candidate bridging): accepted, no latch.',
            { mode: 'when-present', roots: true, response: 'unsigned' }, { result: 'absent', events: [UNSIGNED] }),
        answer('unsigned_after_latch', 'An unsigned answer from a latched origin: refused as missing; the latch is kept.',
            { mode: 'when-present', roots: false, latchedBefore: true, response: 'unsigned' }, { result: { error: 'missing' }, latch: 'before', events: [FAILED] }),
        answer('unsigned_required_with_roots', 'Roots configured and a signature stripped from the very first answer: refused as missing, nothing latched.',
            { mode: 'required', roots: true, response: 'unsigned' }, { result: { error: 'missing' }, events: [FAILED] }),
        answer('unsigned_required_without_roots', 'responseSignature required and no roots: an unsigned answer is refused all the same.',
            { mode: 'required', roots: false, response: 'unsigned' }, { result: { error: 'missing' }, events: [FAILED] }),
        // signed answers that verify
        answer('signed_latches', 'The first verified answer latches the origin with its root.',
            { mode: 'when-present', roots: true, response: 'valid_current_root' }, { result: 'verified', latch: 'current', events: [LATCHED] }),
        answer('signed_next_root_latches', 'Verified with the next root: the latch names it.',
            { mode: 'when-present', roots: true, response: 'valid_next_root' }, { result: 'verified', latch: 'next', events: [LATCHED] }),
        answer('signed_required_latches', 'Strict clients latch too: a store shared with a release candidate is strict for it from then on.',
            { mode: 'required', roots: true, response: 'valid_current_root' }, { result: 'verified', latch: 'current', events: [LATCHED] }),
        answer('signed_already_latched', 'An origin latched before is not latched again: no event, the latch as it was.',
            { mode: 'when-present', roots: true, latchedBefore: true, response: 'valid_current_root' }, { result: 'verified', latch: 'before', events: [] }),
        // signed answers that are refused: they latch all the same, before the error
        answer('unknown_root_latches', 'A signed answer from a root not pinned: refused, and the origin is latched with rootId null before the error.',
            { mode: 'when-present', roots: true, response: 'unknown_root' }, { result: { error: 'unknown_root' }, latch: null, events: [LATCHED, FAILED] }),
        answer('tampered_latches', 'A signed answer that fails its check: refused, latched with rootId null.',
            { mode: 'when-present', roots: true, response: 'tampered_response_body' }, { result: { error: 'invalid' }, latch: null, events: [LATCHED, FAILED] }),
        answer('partly_stripped_latches', 'Some of the four headers stripped: refused as missing, and latched (an attacker who strips part of the signature turns the client strict).',
            { mode: 'when-present', roots: true, response: 'missing_sign' }, { result: { error: 'missing' }, latch: null, events: [LATCHED, FAILED] }),
        answer('partly_stripped_without_roots', 'The same with no roots at all: the headers are checked before any root is needed.',
            { mode: 'when-present', roots: false, response: 'missing_sign' }, { result: { error: 'missing' }, latch: null, events: [LATCHED, FAILED] }),
        answer('refused_already_latched', 'A refused signed answer from a latched origin: no second latch.',
            { mode: 'when-present', roots: true, latchedBefore: true, response: 'unknown_root' }, { result: { error: 'unknown_root' }, latch: 'before', events: [FAILED] }),
        // signed answers and no root to check them with
        answer('signed_without_roots_latches', 'A signed answer to a client with no roots (a release candidate once production signs): ConfigurationError, and latched with rootId null, so a signature stripped from the next answer is refused.',
            { mode: 'when-present', roots: false, response: 'valid_current_root' }, { result: { configurationError: true }, latch: null, events: [LATCHED] }),
        answer('signed_without_roots_required', 'The same in required mode.',
            { mode: 'required', roots: false, response: 'valid_current_root' }, { result: { configurationError: true }, latch: null, events: [LATCHED] }),
        answer('signed_without_roots_already_latched', 'The same on a latched origin: no second latch.',
            { mode: 'when-present', roots: false, latchedBefore: true, response: 'valid_current_root' }, { result: { configurationError: true }, latch: 'before', events: [] }),
    ];

    return {
        format: 'vaultody response signature mode, v1',
        warning: 'TEST-ONLY: the answers are cases of v1.json, signed with its TEST-ONLY keys.',
        source: { ...SOURCE, responses: 'test-vectors/v1.json, by case name' },
        rules: {
            rootsConfigured: 'Roots are configured when the roots option is given (any value but null), or when the SDK is a stable version (X.Y.Z, no -rc.N; Python compares its PEP 440 form, X.Y.ZrcN) and its build embeds at least one response-signing root. A release candidate that embeds the root is not strict for that alone: it bridges to signing through the latch.',
            mode: 'The mode in force is required when roots are configured, whatever the option says; a when-present given explicitly (the option, or VAULTODY_RESPONSE_SIGNATURE when the option is not given) is then ignored, with one warning when the client is made. Otherwise: the option, else VAULTODY_RESPONSE_SIGNATURE, else the build default (DEFAULT_RESPONSE_SIGNATURE: when-present for a release candidate, required for a stable release). The client reports the mode in force (Node responseSignature, Python response_signature, PHP responseSignature()), also when it shows itself (inspect, repr, toJSON, __debugInfo).',
            unsigned: 'An answer with none of the four x-api-response-* headers is refused as missing when the mode in force is required or the origin is latched. Otherwise it is accepted as absent, with unsigned_response_accepted and one warning the first time (once per client).',
            signed: 'An answer with at least one of the four headers is always checked: valid is verified; a failure raises response_verification_failed and ResponseVerificationError with its reason, never retried; no root to check it with (no roots option and none embedded) is ConfigurationError, with no response_verification_failed.',
            latch: 'Any answer with at least one of the four headers latches its origin, verified or not, before anything is thrown: { latchedAt: now, rootId: the root that verified it, or null when it did not verify }, stored with the pins (vault-keys-file-v1.json), then response_signature_latched with the latch as stored. Set once, never cleared: an origin latched before is not latched again, and raises no event.',
            order: 'Events in this order: response_signature_latched, then response_verification_failed or unsigned_response_accepted.',
            writes: 'Before the first write to an origin, a client whose roots are configured and whose origin is not latched yet makes one signed read (GET /api-keys/current/signing-keys, the key-pair check when a signer is set): against an origin that does not sign, the write fails before it is sent instead of running unverified (no vector; each language tests it against its mock gateway).',
        },
        caseFormat: {
            config: '{ name, rootsOption, embeddedRoots, version, buildDefault, option } → expected { mode, warning }. rootsOption: whether the roots option is given; embeddedRoots: whether the build embeds a root; version: the SDK version; buildDefault: DEFAULT_RESPONSE_SIGNATURE; option: the responseSignature option (null: not given, and no VAULTODY_RESPONSE_SIGNATURE). mode: the mode in force; warning: whether the one "when-present is ignored" warning is logged.',
            answers: '{ name, mode, roots, latchedBefore, answer } → expected { result, latch, events }. mode: the mode in force; roots: whether the client has the case\'s pinnedRoots to check a signature with (a client built from its configuration: required with roots is the roots option, when-present with roots a release candidate embedding them, required without roots responseSignature required); latchedBefore: the store holds the latch { latchedAt: 1794200000, rootId: the current root } for the origin; answer: "unsigned" (v1.json missing_all) or a v1.json case, whose verify.request, verify.response and verify.now are used. result: "verified", "absent", { error: reason } (ResponseVerificationError) or { configurationError: true }; latch: the store\'s latch for the origin after the answer, or null; events: the security event types raised, in order.',
        },
        previousLatch: PREVIOUS_LATCH,
        config,
        answers,
    };
}

// ---------------------------------------------------------------------------------------------------

const OUTPUTS = [
    ['path-encoding-v1.json', buildPathEncoding],
    ['p1363-der-v1.json', buildP1363],
    ['envelope-errors-v1.json', buildEnvelopeErrors],
    ['pagination-v1.json', buildPagination],
    ['retry-v1.json', buildRetry],
    ['transport-errors-v1.json', buildTransportErrors],
    ['webhook-v1.json', buildWebhook],
    ['vault-keys-file-v1.json', buildVaultKeysFile],
    ['security-events-v1.json', buildSecurityEvents],
    ['response-mode-v1.json', buildResponseMode],
];

let differ = 0;
for (const [name, build] of OUTPUTS) {
    const file = path.join(VECTORS_DIR, name);
    const text = `${JSON.stringify(build(), null, 2)}\n`;
    if (CHECK) {
        const same = fs.existsSync(file) && fs.readFileSync(file, 'utf8') === text;
        differ += same ? 0 : 1;
        process.stdout.write(`test-vectors/${name}: ${same ? 'same' : 'differs'}\n`);
    } else {
        fs.writeFileSync(file, text);
        process.stdout.write(`test-vectors/${name}: written\n`);
    }
}
process.exitCode = differ === 0 ? 0 : 1;
