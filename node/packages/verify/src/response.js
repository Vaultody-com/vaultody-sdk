'use strict';

/**
 * Checks that a Vaultody API response came unchanged from the Vaultody API gateway.
 *
 * TLS for the API ends at a CDN in front of the gateway, so a valid TLS connection only proves that the
 * CDN answered. The gateway therefore signs every response itself, and this module checks that
 * signature against root keys pinned in the package. A response changed anywhere on the way, or moved
 * onto a different request, is refused.
 *
 * Two keys are involved. A P-256 root key, kept in an HSM, signs a short certificate for each gateway
 * instance's own Ed25519 key, valid for about an hour. The instance signs each response with that key,
 * over the status, the body bytes, and the request being answered: method, path, query, a hash of the
 * request body, the client's x-api-sign and its x-api-keypair-sign.
 *
 * The checks run in a fixed order, shared with the gateway's reference verifier and the other language
 * helpers. The order decides which reason a caller sees:
 *  1. all four signature headers present and non-empty, else `missing`;
 *  2. x-api-response-sign-version is exactly "1", else `unsupported_version`;
 *  3. x-api-response-cert is base64(CERT) "." base64(root signature), CERT is ASCII, its first line is the
 *     tag and its second a lowercase hex root id, else `invalid`;
 *  4. the root id names a trusted root, else `unknown_root`;
 *  5. the root's ECDSA P-256 / SHA-256 signature (DER) verifies over the CERT bytes, else `invalid`;
 *  6. CERT is canonical: 6 lines, canonical base64 key of 32 bytes, keyId matching the key, canonical
 *     decimal times, and valid for at most 3600 seconds (notAfter - notBefore), else `invalid`;
 *  7. x-api-response-timestamp is a canonical decimal, else `invalid`;
 *  8. notBefore <= timestamp <= notAfter and now <= notAfter + skew, else `expired`;
 *  9. the Ed25519 signature verifies over the message rebuilt from the request as sent (x-api-sign and
 *     x-api-keypair-sign included, empty when not sent) and the response as received. If it only verifies with the body hash "unread" (the gateway did not read the request
 *     body), the reason is `request_unbound`; otherwise `invalid`.
 */

const crypto = require('node:crypto');

const { REASONS, ResponseSignatureError, ConfigurationError } = require('./errors');
const { sha256, strictBase64, strictSeconds, toBytes } = require('./encoding');
const { parseRoots, requireRoots, embeddedFingerprints } = require('./rootKeys');

const SIGN_VERSION = '1';

const HEADERS = Object.freeze({
    sign: 'x-api-response-sign',
    timestamp: 'x-api-response-timestamp',
    version: 'x-api-response-sign-version',
    cert: 'x-api-response-cert',
});

const CERT_TAG = 'vaultody-response-key-v1';
const MESSAGE_TAG = 'vaultody-response-v1';
const CERT_LINES = 6;
// Signed in place of the request body hash when the gateway did not read the whole request body (too
// large, or the client aborted).
const UNREAD_BODY = 'unread';

const DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300;
// The longest a gateway certificate may be valid. A fixed rule, not an option: a looser value would let a
// certificate the root signed by mistake be used for years.
const MAX_CERT_LIFETIME_SECONDS = 3600;

const ROOT_ID = /^[0-9a-f]{64}$/;
const KEY_ID = /^[0-9a-f]{32}$/;
const CERT_TEXT = /^[\x20-\x7e\n]+$/;
// The request fields sit on their own lines in the signed message, so they must stay printable ASCII.
// Anything else can't be what the gateway signed.
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

const ED25519_SIGNATURE_BYTES = 64;
const ED25519_PUBLIC_KEY_BYTES = 32;
// An Ed25519 SubjectPublicKeyInfo in DER is this fixed 12-byte header followed by the raw 32-byte key.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Unix seconds stay below this for thousands of years, while Date.now() milliseconds are far above it.
// Catching the mix-up gives a clear error instead of every response being reported as expired.
const LARGEST_PLAUSIBLE_SECONDS = 1e11;

// fetch() upper-cases these methods whatever case they were given in, and sends any other method exactly
// as written.
const FETCH_NORMALISED_METHODS = new Set(['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT']);

const reject = (reason, detail) => new ResponseSignatureError(reason, detail);

/**
 * Every value given for one header, matched case-insensitively.
 *
 * @param {Object|Headers|Map|null|undefined} headers
 * @param {string} name lowercase header name
 * @returns {Array}
 */
function headerValues(headers, name) {
    if (headers === undefined || headers === null) {
        return [];
    }

    let values;
    if (headers instanceof Map) {
        values = [...headers].filter(([key]) => typeof key === 'string' && key.toLowerCase() === name).map(([, value]) => value);
    } else if (typeof headers.get === 'function') {
        // A fetch Headers object, or one shaped like it, matches names case-insensitively itself. It joins
        // repeated values with ", ", which the format checks further on refuse.
        values = [headers.get(name)];
    } else {
        values = Object.keys(headers).filter(key => key.toLowerCase() === name).map(key => headers[key]);
    }

    return values.flat().filter(value => value !== undefined && value !== null);
}

function readOptions(options) {
    if (options === undefined || options === null) {
        options = {};
    }
    if (typeof options !== 'object') {
        throw new TypeError('options must be an object');
    }

    const {
        requireResponseSignature = true,
        roots,
        now,
        maxClockSkewSeconds = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    } = options;

    if (typeof requireResponseSignature !== 'boolean') {
        throw new TypeError('requireResponseSignature must be true or false');
    }
    if (typeof maxClockSkewSeconds !== 'number' || !Number.isFinite(maxClockSkewSeconds) || maxClockSkewSeconds < 0) {
        throw new TypeError('maxClockSkewSeconds must be a non-negative number of seconds');
    }

    let nowSeconds;
    if (now === undefined || now === null) {
        nowSeconds = Math.floor(Date.now() / 1000);
    } else if (now instanceof Date && Number.isFinite(now.getTime())) {
        nowSeconds = Math.floor(now.getTime() / 1000);
    } else if (typeof now === 'number' && Number.isFinite(now)) {
        if (now > LARGEST_PLAUSIBLE_SECONDS) {
            throw new TypeError('now must be Unix seconds; this looks like milliseconds');
        }
        nowSeconds = now;
    } else {
        throw new TypeError('now must be Unix seconds (a number) or a Date');
    }

    return {
        requireResponseSignature,
        // Parsed now, so a malformed root is reported at once; a root is required only once the response
        // turns out to be signed, so an unsigned response needs none (see verifyResponse step 1).
        roots: parseRoots(roots),
        now: nowSeconds,
        maxClockSkewSeconds,
    };
}

function readRequest(request) {
    if (!request || typeof request !== 'object') {
        throw new TypeError('request must be an object: { method, url, body, apiSign, keypairSign }');
    }

    const { method, url, body, apiSign, keypairSign } = request;
    if (typeof method !== 'string' || method === '') {
        throw new TypeError('request.method must be the HTTP method exactly as sent, for example "POST"');
    }
    if (typeof url !== 'string' || !url.startsWith('/')) {
        throw new TypeError('request.url must be the path and query exactly as sent on the request line, starting with "/" (not a full URL)');
    }
    if (apiSign !== undefined && apiSign !== null && typeof apiSign !== 'string') {
        throw new TypeError('request.apiSign must be the x-api-sign header value that was sent, or empty');
    }
    if (keypairSign !== undefined && keypairSign !== null && typeof keypairSign !== 'string') {
        throw new TypeError('request.keypairSign must be the x-api-keypair-sign header value that was sent, or empty');
    }

    // Split at the first "?" only. Both halves are kept exactly as sent, because the gateway signs them
    // as it received them, percent-encoding and all.
    const queryAt = url.indexOf('?');

    return {
        method,
        path: queryAt === -1 ? url : url.slice(0, queryAt),
        query: queryAt === -1 ? '' : url.slice(queryAt + 1),
        body: toBytes(body, 'request.body'),
        apiSign: apiSign === undefined || apiSign === null ? '' : apiSign,
        keypairSign: keypairSign === undefined || keypairSign === null ? '' : keypairSign,
    };
}

function readResponse(response) {
    if (!response || typeof response !== 'object') {
        throw new TypeError('response must be an object: { status, headers, body }');
    }

    const { status, headers, body } = response;
    if (!Number.isInteger(status)) {
        throw new TypeError('response.status must be the HTTP status code as a number');
    }
    if (headers !== undefined && headers !== null && typeof headers !== 'object') {
        throw new TypeError('response.headers must be a plain object, a Headers instance or a Map');
    }

    return { status, headers, body: toBytes(body, 'response.body') };
}

/**
 * Verifies one signed API response.
 *
 * @param {Object} exchange
 * @param {{ method: string, url: string, body?: Buffer|Uint8Array|ArrayBuffer|string|null, apiSign?: string, keypairSign?: string }} exchange.request
 *        the request exactly as sent: `url` is the path plus query from the request line, `body` the raw
 *        bytes sent (before any Content-Encoding), `apiSign` the x-api-sign header sent, if any, and
 *        `keypairSign` the x-api-keypair-sign header sent, if any
 * @param {{ status: number, headers: Object|Headers|Map, body?: Buffer|Uint8Array|ArrayBuffer|string|null }} exchange.response
 *        the response as received, with `body` the raw bytes (after Content-Encoding is removed). Verify
 *        before parsing the body.
 * @param {Object} [options]
 * @param {boolean} [options.requireResponseSignature=true] when false, a response with no signature
 *        headers at all is returned as { verified: false, reason: 'missing' } instead of throwing;
 *        every other failure still throws
 * @param {string|Object|Array} [options.roots] root public keys to trust instead of the embedded ones
 * @param {number|Date} [options.now] the current time, as Unix seconds or a Date
 * @param {number} [options.maxClockSkewSeconds=300] how far past a certificate's notAfter this
 *        machine's clock may be
 * @returns {{ verified: true, keyId: string, rootId: string, timestamp: number } | { verified: false, reason: 'missing' }}
 * @throws {ResponseSignatureError} when the response fails verification
 * @throws {ConfigurationError} when a given root is unusable, or when the response is signed and no root keys
 *         are configured
 */
function verifyResponse(exchange, options) {
    const settings = readOptions(options);
    if (!exchange || typeof exchange !== 'object') {
        throw new TypeError('verifyResponse expects { request, response }');
    }
    const request = readRequest(exchange.request);
    const response = readResponse(exchange.response);

    // 1. Headers. A response with none of them was never signed (or had the signature stripped as a
    // whole), which is the one failure a non-strict caller may choose to accept. A partial set means
    // something removed some of them, which is never accepted.
    const found = {};
    for (const [field, name] of Object.entries(HEADERS)) {
        found[field] = headerValues(response.headers, name);
    }
    if (Object.values(found).every(values => values.every(value => value === ''))) {
        if (!settings.requireResponseSignature) {
            return { verified: false, reason: REASONS.MISSING };
        }
        throw reject(REASONS.MISSING, 'the response has no signature headers');
    }

    const raw = {};
    for (const [field, name] of Object.entries(HEADERS)) {
        const values = found[field];
        if (values.length === 0 || values[0] === '') {
            throw reject(REASONS.MISSING, `${name} is missing or empty`);
        }
        if (values.length > 1) {
            throw reject(REASONS.INVALID, `${name} appears more than once`);
        }
        if (typeof values[0] !== 'string') {
            throw reject(REASONS.INVALID, `${name} is not a string`);
        }
        raw[field] = values[0];
    }

    if (raw.version !== SIGN_VERSION) {
        throw reject(REASONS.UNSUPPORTED_VERSION, `signature version "${raw.version}" is not supported; this helper understands "${SIGN_VERSION}"`);
    }

    // 2. Find the root the certificate names and check its signature, before trusting anything else the
    // certificate says.
    const certParts = raw.cert.split('.');
    if (certParts.length !== 2) {
        throw reject(REASONS.INVALID, `${HEADERS.cert} must be two base64 parts joined by "."`);
    }
    const certBytes = strictBase64(certParts[0]);
    const rootSignature = strictBase64(certParts[1]);
    if (!certBytes || !rootSignature) {
        throw reject(REASONS.INVALID, `${HEADERS.cert} is not canonical base64`);
    }
    if (certBytes.some(byte => byte > 0x7f)) {
        throw reject(REASONS.INVALID, 'the certificate is not ASCII');
    }
    const certText = certBytes.toString('latin1');
    const lines = certText.split('\n');
    if (lines.length < 2 || lines[0] !== CERT_TAG || !ROOT_ID.test(lines[1])) {
        throw reject(REASONS.INVALID, 'the certificate does not start with the v1 tag and a root id');
    }
    const rootId = lines[1];

    // The roots are looked up only now that the response carries a signature: with none configured, a
    // signed response fails closed here, while an unsigned one was decided above without them.
    const root = requireRoots(settings.roots).find(candidate => candidate.rootId === rootId);
    if (!root) {
        throw reject(REASONS.UNKNOWN_ROOT, `the certificate names root ${rootId}, which is not trusted`);
    }

    let rootSignatureOk = false;
    try {
        rootSignatureOk = crypto.verify('sha256', certBytes, { key: root.key, dsaEncoding: 'der' }, rootSignature);
    } catch (e) {
        rootSignatureOk = false;
    }
    if (!rootSignatureOk) {
        throw reject(REASONS.INVALID, 'the root signature on the certificate does not verify');
    }

    // 3. The certificate must be in the one form the gateway writes, so it means the same thing to every
    // verifier.
    if (lines.length !== CERT_LINES || !CERT_TEXT.test(certText)) {
        throw reject(REASONS.INVALID, `the certificate must be ${CERT_LINES} lines of printable ASCII`);
    }
    const [, , publicKeyText, keyId, notBeforeText, notAfterText] = lines;
    const publicKey = strictBase64(publicKeyText);
    if (!publicKey || publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
        throw reject(REASONS.INVALID, 'the certificate public key is not canonical base64 of 32 bytes');
    }
    if (!KEY_ID.test(keyId) || keyId !== sha256(publicKey).toString('hex').slice(0, 32)) {
        throw reject(REASONS.INVALID, 'the certificate keyId does not match its public key');
    }
    const notBefore = strictSeconds(notBeforeText);
    const notAfter = strictSeconds(notAfterText);
    if (notBefore === null || notAfter === null) {
        throw reject(REASONS.INVALID, 'the certificate validity times are not canonical decimals');
    }
    if (notAfter - notBefore > MAX_CERT_LIFETIME_SECONDS) {
        throw reject(REASONS.INVALID, `the certificate is valid for more than ${MAX_CERT_LIFETIME_SECONDS} seconds`);
    }

    // 4. Time. The signing time must fall inside the certificate's window, and this machine's clock may
    // run at most the allowed skew past its end, so an old certificate can't be reused indefinitely.
    const timestamp = strictSeconds(raw.timestamp);
    if (timestamp === null) {
        throw reject(REASONS.INVALID, `${HEADERS.timestamp} is not a canonical decimal`);
    }
    if (timestamp < notBefore || timestamp > notAfter) {
        throw reject(REASONS.EXPIRED, `the response was signed at ${timestamp}, outside the certificate window ${notBefore}..${notAfter}`);
    }
    if (settings.now > notAfter + settings.maxClockSkewSeconds) {
        throw reject(REASONS.EXPIRED, `the certificate expired at ${notAfter}; the clock here reads ${settings.now}`);
    }

    // 5. The response signature, over the request as sent and the response as received.
    const signature = strictBase64(raw.sign);
    if (!signature || signature.length !== ED25519_SIGNATURE_BYTES) {
        throw reject(REASONS.INVALID, `${HEADERS.sign} is not canonical base64 of 64 bytes`);
    }
    let podKey;
    try {
        podKey = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]), format: 'der', type: 'spki' });
    } catch (e) {
        throw reject(REASONS.INVALID, 'the certificate public key is not a usable Ed25519 key');
    }

    const { method, path, query, apiSign, keypairSign } = request;
    if (![method, path, query, apiSign, keypairSign].every(value => PRINTABLE_ASCII.test(value))) {
        throw reject(REASONS.INVALID, 'the request method, url, apiSign and keypairSign must be printable ASCII exactly as sent; '
            + 'non-ASCII characters are percent-encoded on the wire');
    }

    const messageWith = bodyHash => Buffer.concat([
        Buffer.from(`${MESSAGE_TAG}\n${raw.timestamp}\n${response.status}\n${method}\n${path}\n${query}\n${bodyHash}\n${apiSign}\n${keypairSign}\n`, 'latin1'),
        response.body,
    ]);
    const verifies = message => {
        try {
            return crypto.verify(null, message, podKey, signature);
        } catch (e) {
            return false;
        }
    };

    if (verifies(messageWith(sha256(request.body).toString('hex')))) {
        return { verified: true, keyId, rootId, timestamp };
    }
    if (verifies(messageWith(UNREAD_BODY))) {
        throw reject(REASONS.REQUEST_UNBOUND, 'the response is genuine, but the gateway did not read the request body, '
            + 'so it is not tied to the body that was sent');
    }

    throw reject(REASONS.INVALID, 'the signature does not match this request and response');
}

const isFetchRequest = value => value !== null && typeof value === 'object'
    && typeof value.url === 'string' && typeof value.method === 'string'
    && typeof value.clone === 'function' && typeof value.arrayBuffer === 'function'
    && value.headers && typeof value.headers.get === 'function';

/**
 * The value fetch would send for one request header (x-api-sign, x-api-keypair-sign). fetch's own Headers
 * class is used where it exists, because it accepts every shape fetch does and trims values the same way.
 *
 * @param {HeadersInit|undefined|null} headers
 * @param {string} name lowercase header name
 * @returns {string} '' when not sent
 */
function headerFromInit(headers, name) {
    if (headers === undefined || headers === null) {
        return '';
    }
    if (typeof Headers === 'function') {
        return new Headers(headers).get(name) || '';
    }

    const values = headerValues(headers, name);

    return values.length === 0 ? '' : String(values.join(', ')).trim();
}

/**
 * What fetch puts on the wire for this request: the method after fetch's normalisation, the URL path and
 * query after WHATWG URL serialisation (fetch sends pathname + search, never the fragment), the body
 * bytes, and the x-api-sign and x-api-keypair-sign headers.
 */
async function describeFetchRequest(request) {
    if (isFetchRequest(request)) {
        // A Request has already applied fetch's rules to its method and URL.
        const url = new URL(request.url);
        let body = Buffer.alloc(0);
        if (request.body !== null && request.body !== undefined) {
            if (request.bodyUsed) {
                throw new TypeError('the Request body has already been sent, so it cannot be read back: pass a clone to fetch, '
                    + 'or pass { url, method, headers, body } with the body bytes instead');
            }
            body = Buffer.from(await request.clone().arrayBuffer());
        }

        return {
            method: request.method,
            url: url.pathname + url.search,
            body,
            apiSign: request.headers.get('x-api-sign') || '',
            keypairSign: request.headers.get('x-api-keypair-sign') || '',
        };
    }

    if (!request || typeof request !== 'object') {
        throw new TypeError('request must be a fetch Request or { url, method, headers, body, apiSign, keypairSign }');
    }

    const { url, method = 'GET', headers, body, apiSign, keypairSign } = request;
    if (typeof url !== 'string' && !(url instanceof URL)) {
        throw new TypeError('request.url must be the absolute URL given to fetch, as a string or URL');
    }
    if (typeof method !== 'string' || method === '') {
        throw new TypeError('request.method must be a string');
    }
    const parsed = new URL(url);
    const upperCased = method.replace(/[a-z]/g, letter => letter.toUpperCase());

    return {
        method: FETCH_NORMALISED_METHODS.has(upperCased) ? upperCased : method,
        url: parsed.pathname + parsed.search,
        body: toBytes(body, 'request.body'),
        apiSign: apiSign !== undefined && apiSign !== null ? apiSign : headerFromInit(headers, 'x-api-sign'),
        keypairSign: keypairSign !== undefined && keypairSign !== null ? keypairSign : headerFromInit(headers, 'x-api-keypair-sign'),
    };
}

/**
 * Reads a fetch Response's body as raw bytes and verifies it against the request that was sent.
 *
 * @param {Request|{ url: string|URL, method?: string, headers?: HeadersInit, body?: Buffer|Uint8Array|ArrayBuffer|string|null, apiSign?: string, keypairSign?: string }} request
 *        the Request passed to fetch (send a clone so its body can still be read here), or the URL and
 *        init passed to fetch, as { url, ...init }
 * @param {Response} response the fetch Response, body not yet read
 * @param {Object} [options] as for verifyResponse
 * @returns {Promise<{ verified: boolean, body: Buffer }>} the verifyResponse result plus the body bytes;
 *          parse those, not the Response, which has been read
 */
async function verifyFetchResponse(request, response, options) {
    const sent = await describeFetchRequest(request);
    if (!response || typeof response !== 'object' || typeof response.arrayBuffer !== 'function') {
        throw new TypeError('response must be a fetch Response');
    }
    if (response.bodyUsed) {
        throw new TypeError('the response body has already been read; verify before reading it');
    }

    const body = Buffer.from(await response.arrayBuffer());
    const result = verifyResponse({ request: sent, response: { status: response.status, headers: response.headers, body } }, options);

    return { ...result, body };
}

// The four headers a signed response carries; a response with none of them was not signed.
const RESPONSE_SIGN_HEADERS = Object.freeze(Object.values(HEADERS));

// Plain names only, so Node's ESM loader finds every one (`import { verifyResponse } from ...`).
module.exports = {
    verifyResponse,
    verifyFetchResponse,
    ResponseSignatureError,
    ConfigurationError,
    REASONS,
    DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    MAX_CERT_LIFETIME_SECONDS,
    RESPONSE_SIGN_HEADERS,
    // The `roots` option read the way verifyResponse reads it: a malformed root throws a ConfigurationError at
    // once (null when not given; empty slots allowed).
    parseRoots,
    embeddedFingerprints,
};
