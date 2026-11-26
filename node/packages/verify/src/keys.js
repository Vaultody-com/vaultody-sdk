'use strict';

/**
 * Request-signing key pairs for Vaultody API keys.
 *
 * An API key can hold up to two public keys of the customer's own. Once it holds one, every request made
 * with the API key also carries a signature by the matching private key (x-api-keypair-sign) next to the
 * HMAC, so a leaked API secret alone can no longer sign requests. This module makes and reads those keys,
 * computes their fingerprint, signs the proof of possession asked for when a key is registered, signs API
 * requests, and reads the API's list of the keys an API key holds. It does no I/O on the network: the
 * `vaultody keys` command line of @vaultody/sdk is built on it, and `keys verify` asks the API through the
 * SDK's client.
 *
 * The wire formats are shared with the Vaultody API and its docs
 * (test-vectors/request-keypair-v1.json and keypair-challenge-v1.json), so every format constant is here.
 *
 * Nothing in this module logs, and no error it throws carries key material, the API secret, the passphrase
 * or the API key.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { strictBase64 } = require('./encoding');

const ALGORITHMS = Object.freeze({
    ED25519: 'ed25519',
    P256: 'p-256',
});

const KEYPAIR_FORMAT = Object.freeze({
    /** "SHA256:" + base64 without padding of SHA-256 over the canonical SubjectPublicKeyInfo DER: 50 characters */
    FINGERPRINT_PREFIX: 'SHA256:',
    /** The proof of possession: this tag, the API key id, the fingerprint and the challenge, "\n"-joined, no trailing "\n" */
    CHALLENGE_TAG: 'vaultody-keypair-challenge-v1',
    /** "vk-chal-" + 64 lowercase hex characters (32 random bytes), issued by the dashboard */
    CHALLENGE_PATTERN: /^vk-chal-[0-9a-f]{64}$/,
    /** The string signed for x-api-keypair-sign: this tag, the x-api-key, then the HMAC v2 fields in the same order */
    REQUEST_TAG: 'vaultody-request-keypair-v1',
    /** The tag of the HMAC v2 string (x-api-sign with x-api-sign-version: 2) */
    HMAC_V2_TAG: 'v2',
    /** x-api-nonce: printable ASCII without spaces, 1 to 128 characters */
    NONCE_PATTERN: /^[\x21-\x7e]{1,128}$/,
    /** An API key id as the dashboard shows it (a 24 hex character id) */
    API_KEY_ID_PATTERN: /^[0-9a-fA-F]{24}$/,
});

const API_HEADERS = Object.freeze({
    apiKey: 'x-api-key',
    passphrase: 'x-api-passphrase',
    timestamp: 'x-api-timestamp',
    sign: 'x-api-sign',
    signVersion: 'x-api-sign-version',
    nonce: 'x-api-nonce',
    apiVersion: 'x-api-version',
    keypairSign: 'x-api-keypair-sign',
    keypairId: 'x-api-keypair-id',
});

/** The public endpoint that lists the signing keys of the API key that calls it */
const SIGNING_KEYS_PATH = '/api-keys/current/signing-keys';
/**
 * The x-api-version sent to it by default: the version the route was introduced in. Without the header the
 * gateway uses the API key's default version, which may be older and then has no such route (uri_not_found).
 */
const SIGNING_KEYS_API_VERSION = '2026-03-20';
// An API version as x-api-version names it: a date, YYYY-MM-DD
const API_VERSION_PATTERN = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$/;
const DEFAULT_API_ROOT = 'https://rest.vaultody.com';
const ACTIVE = 'active';

// A key file is read only up to this size; an Ed25519 or P-256 PEM is a few hundred bytes.
const MAX_KEY_FILE_BYTES = 16 * 1024;
// A registration reads a pasted public key only up to this length, as the API does. An Ed25519
// PEM is about 113 characters and a P-256 one about 182, CRLF line endings included.
const MAX_PUBLIC_KEY_PEM_LENGTH = 1024;

const PRIVATE_KEY_FILE_MODE = 0o600;
const PUBLIC_KEY_FILE_MODE = 0o644;

/** Why a key was refused. Callers branch on these; the message adds a sentence for people. */
const KEY_ERRORS = Object.freeze({
    // Not one readable Ed25519 or P-256 key in PEM.
    INVALID: 'invalid_key',
    // A private key where only a public key belongs.
    PRIVATE: 'private_key',
    // A public key where the private key is needed (to sign).
    PUBLIC: 'public_key',
    // A key of another type or curve, such as RSA or P-384.
    UNSUPPORTED_ALGORITHM: 'unsupported_algorithm',
    // A private key protected by a passphrase.
    ENCRYPTED: 'encrypted_key',
});

class SigningKeyError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'SigningKeyError';
        this.code = code;
    }
}

/** A wrong argument, file or environment: the caller must change how it asks. */
class UsageError extends Error {
    /**
     * @param {string} message
     * @param {string} [code] a stable code where callers need one, such as 'invalid_api_secret'
     */
    constructor(message, code) {
        super(message);
        this.name = 'UsageError';
        if (code !== undefined) {
            this.code = code;
        }
    }
}

/** A signature in a form that can't be converted (see p1363ToDer). `code` says why. */
class SignatureFormatError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'SignatureFormatError';
        this.code = code;
    }
}

/** The API answered something other than a verdict on the key: a server error, a rate limit, an unknown shape. */
class UnexpectedResponseError extends Error {
    constructor(message, { status, requestId, code } = {}) {
        super(message);
        this.name = 'UnexpectedResponseError';
        this.status = status;
        this.requestId = requestId;
        this.code = code;
    }
}

// The names a refusal uses for key types this module does not take, as a person would name them
const EC_CURVE_NAMES = Object.freeze({
    secp384r1: 'an ECDSA P-384 key',
    secp521r1: 'an ECDSA P-521 key',
    secp256k1: 'a secp256k1 key',
});
const KEY_TYPE_NAMES = Object.freeze({
    rsa: 'an RSA key',
    'rsa-pss': 'an RSA key',
    dsa: 'a DSA key',
    dh: 'a Diffie-Hellman key',
    ed448: 'an Ed448 key',
    x25519: 'an X25519 key',
    x448: 'an X448 key',
});

// Any PEM private key (PKCS#8, encrypted PKCS#8, SEC1, PKCS#1, OpenSSH), a PuTTY key file, or a JWK holding
// its private member "d": what a registration refuses as private before it parses anything
const PRIVATE_KEY_MARKERS = [/PRIVATE KEY/i, /PuTTY-User-Key-File/i, /"d"\s*:/];
const OPENSSH_PUBLIC_KEY = /^(?:ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)|^---- BEGIN SSH2 PUBLIC KEY ----/;
const PUTTY_KEY = /PuTTY-User-Key-File/i;
const PEM_LABEL = /-----BEGIN ([^-\n]{1,40})-----/g;
const PEM_BEGIN = '-----BEGIN PUBLIC KEY-----';
const PEM_END = '-----END PUBLIC KEY-----';
const NOT_PEM_BODY = /[^A-Za-z0-9+/=\s]/;
const BASE64_SHAPE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const PRIVATE_LABELS = new Set(['PRIVATE KEY', 'EC PRIVATE KEY']);

const SUPPORTED = 'Only Ed25519 and ECDSA P-256 keys are supported.';

const invalidKey = reason => new SigningKeyError(KEY_ERRORS.INVALID, `This is not a usable signing key: ${reason}.`);
const encryptedKey = () => new SigningKeyError(KEY_ERRORS.ENCRYPTED, 'This private key is protected by a passphrase, which this tool '
    + 'does not read. Use an unencrypted copy, for example from "openssl pkey -in encrypted.pem -out private.pem".');
const privateWherePublic = () => new SigningKeyError(KEY_ERRORS.PRIVATE, 'This is a private key. Give the public key (public.pem) '
    + 'instead, and never share the private key with anyone, Vaultody included.');

function unsupportedTypeOf(key) {
    if (key.asymmetricKeyType === 'ec') {
        const curve = key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve;

        return EC_CURVE_NAMES[curve] || 'an ECDSA key on another curve';
    }

    return KEY_TYPE_NAMES[key.asymmetricKeyType] || 'a key of another type';
}

/**
 * @param {Buffer} spkiDer the canonical SubjectPublicKeyInfo DER
 * @returns {string} "SHA256:" + base64 without padding, 50 characters
 */
function fingerprintOf(spkiDer) {
    return KEYPAIR_FORMAT.FINGERPRINT_PREFIX + crypto.createHash('sha256').update(spkiDer).digest('base64').replace(/=+$/, '');
}

/**
 * The public half in its one canonical form: a P-256 point uncompressed, which Node does only when the key
 * is rebuilt from its coordinates (it exports a key in the form it was read in).
 */
function describePublic(publicKey) {
    let algorithm;
    if (publicKey.asymmetricKeyType === 'ed25519') {
        algorithm = ALGORITHMS.ED25519;
    } else if (publicKey.asymmetricKeyType === 'ec' && publicKey.asymmetricKeyDetails
        && publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1') {
        algorithm = ALGORITHMS.P256;
    } else {
        throw new SigningKeyError(KEY_ERRORS.UNSUPPORTED_ALGORITHM, `This is ${unsupportedTypeOf(publicKey)}. ${SUPPORTED}`);
    }

    const canonical = algorithm === ALGORITHMS.P256
        ? crypto.createPublicKey({ key: publicKey.export({ format: 'jwk' }), format: 'jwk' })
        : publicKey;
    const spkiDer = canonical.export({ format: 'der', type: 'spki' });

    return {
        algorithm,
        publicKey: canonical,
        publicKeyPem: canonical.export({ format: 'pem', type: 'spki' }),
        spkiDer,
        fingerprint: fingerprintOf(spkiDer),
    };
}

/**
 * Reads one signing key in PEM: a public key ("BEGIN PUBLIC KEY", SubjectPublicKeyInfo) or a private key
 * ("BEGIN PRIVATE KEY", PKCS#8, or "BEGIN EC PRIVATE KEY", SEC1), Ed25519 or ECDSA P-256.
 *
 * With accept 'public' it applies the rules a registration applies to a pasted key, in the same order:
 * anything private is refused before it is parsed, then a text that is too long, OpenSSH keys, certificates,
 * several blocks and other PEM types, then keys of any other type. The fingerprint is taken over the
 * canonical SPKI DER, so a compressed and an uncompressed P-256 key give one fingerprint.
 *
 * @param {string} text the PEM text
 * @param {{ accept?: 'public'|'private'|'any' }} [options] which halves to take; 'any' by default
 * @returns {{ kind: 'public'|'private', algorithm: string, fingerprint: string, publicKey: crypto.KeyObject,
 *            publicKeyPem: string, spkiDer: Buffer, privateKey: crypto.KeyObject|null }}
 * @throws {SigningKeyError}
 */
function readSigningKey(text, { accept = 'any' } = {}) {
    if (!['public', 'private', 'any'].includes(accept)) {
        throw new TypeError('accept must be "public", "private" or "any"');
    }
    if (typeof text !== 'string' || text.trim() === '') {
        throw invalidKey('it is empty');
    }
    if (accept === 'public') {
        // Where only a public key belongs, anything private is refused before it is read any further.
        if (PRIVATE_KEY_MARKERS.some(marker => marker.test(text))) {
            throw privateWherePublic();
        }
        if (text.length > MAX_PUBLIC_KEY_PEM_LENGTH) {
            throw invalidKey(`it is longer than ${MAX_PUBLIC_KEY_PEM_LENGTH} characters`);
        }
    }
    if (text.length > MAX_KEY_FILE_BYTES) {
        throw invalidKey('it is far longer than an Ed25519 or P-256 key');
    }

    const pem = text.replace(/\r\n?/g, '\n').trim();
    if (PUTTY_KEY.test(pem)) {
        throw invalidKey('it is a PuTTY key file; use a PEM key');
    }
    if (OPENSSH_PUBLIC_KEY.test(pem)) {
        throw invalidKey('it is an OpenSSH public key; use a PEM public key (BEGIN PUBLIC KEY)');
    }

    const labels = Array.from(pem.matchAll(PEM_LABEL), match => match[1]);
    if (labels.includes('CERTIFICATE') || labels.includes('TRUSTED CERTIFICATE')) {
        throw invalidKey('it is a certificate, not a key');
    }
    if (labels.length === 0) {
        throw invalidKey('it is not a PEM key (BEGIN PUBLIC KEY or BEGIN PRIVATE KEY)');
    }
    if (labels.length > 1) {
        throw invalidKey('it holds more than one PEM block');
    }

    const label = labels[0];
    if (label === 'RSA PUBLIC KEY' || label === 'RSA PRIVATE KEY') {
        throw new SigningKeyError(KEY_ERRORS.UNSUPPORTED_ALGORITHM, `This is an RSA key. ${SUPPORTED}`);
    }
    // PKCS#8 encrypted, or a SEC1 key with the legacy OpenSSL encryption headers
    if (label === 'ENCRYPTED PRIVATE KEY' || /^Proc-Type:\s*4,ENCRYPTED/m.test(pem)) {
        throw encryptedKey();
    }
    if (label === 'OPENSSH PRIVATE KEY') {
        throw invalidKey('it is an OpenSSH private key; generate a PEM key pair with "vaultody keys generate" or openssl');
    }

    if (label === 'PUBLIC KEY') {
        if (accept === 'private') {
            throw new SigningKeyError(KEY_ERRORS.PUBLIC, 'This is a public key. Signing needs the private key (private.pem).');
        }

        return { kind: 'public', ...readPublicPem(pem), privateKey: null };
    }

    if (PRIVATE_LABELS.has(label)) {
        return readPrivatePem(pem);
    }

    throw invalidKey('it is not a PEM key (BEGIN PUBLIC KEY or BEGIN PRIVATE KEY)');
}

/**
 * The text between the BEGIN PUBLIC KEY and END PUBLIC KEY lines of one PEM block, whitespace included, or
 * null when the text is not exactly one such block holding only base64 and whitespace. Reads the text once,
 * in time linear in its length: a regular expression with a lazy body between two runs of whitespace
 * backtracks quadratically on a long run of spaces (seconds for a few thousand).
 *
 * @param {string} pem trimmed, "\n" line endings
 * @returns {string|null}
 */
function pemBody(pem) {
    if (pem.length < PEM_BEGIN.length + PEM_END.length || !pem.startsWith(PEM_BEGIN) || !pem.endsWith(PEM_END)) {
        return null;
    }

    const body = pem.slice(PEM_BEGIN.length, pem.length - PEM_END.length);

    return NOT_PEM_BODY.test(body) ? null : body;
}

function readPublicPem(pem) {
    const block = pemBody(pem);
    if (block === null) {
        throw invalidKey('it is not a PEM public key (BEGIN PUBLIC KEY)');
    }
    const body = block.replace(/\s+/g, '');
    if (body === '' || !BASE64_SHAPE.test(body)) {
        throw invalidKey('the PEM body is not base64');
    }

    let key;
    try {
        key = crypto.createPublicKey({ key: Buffer.from(body, 'base64'), format: 'der', type: 'spki' });
    } catch (e) {
        throw invalidKey('it is not a valid public key');
    }

    return describePublic(key);
}

function readPrivatePem(pem) {
    let privateKey;
    try {
        privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
    } catch (e) {
        if (e && e.code === 'ERR_MISSING_PASSPHRASE') {
            throw encryptedKey();
        }
        throw invalidKey('it is not a valid private key');
    }

    return { kind: 'private', ...describePublic(crypto.createPublicKey(privateKey)), privateKey };
}

/**
 * The checks a registration applies to a pasted public key, with the canonical key and fingerprint.
 *
 * @param {string} text
 * @returns {{ algorithm: string, fingerprint: string, spkiDer: Buffer, publicKeyPem: string, publicKey: crypto.KeyObject }}
 * @throws {SigningKeyError}
 */
function inspectPublicKey(text) {
    const { algorithm, fingerprint, spkiDer, publicKeyPem, publicKey } = readSigningKey(text, { accept: 'public' });

    return { algorithm, fingerprint, spkiDer, publicKeyPem, publicKey };
}

/**
 * @param {string} algorithm "ed25519" or "p-256"
 * @returns {{ algorithm: string, fingerprint: string, privateKeyPem: string, publicKeyPem: string }}
 *          the private key as PKCS#8 PEM, the public key as canonical SPKI PEM
 */
function generateSigningKeyPair(algorithm) {
    let pair;
    if (algorithm === ALGORITHMS.ED25519) {
        pair = crypto.generateKeyPairSync('ed25519');
    } else if (algorithm === ALGORITHMS.P256) {
        pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    } else {
        throw new UsageError(`the algorithm must be "${ALGORITHMS.ED25519}" or "${ALGORITHMS.P256}"`);
    }

    const { fingerprint, publicKeyPem } = describePublic(pair.publicKey);

    return {
        algorithm,
        fingerprint,
        privateKeyPem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
        publicKeyPem,
    };
}

function removeIfPresent(file) {
    try {
        fs.unlinkSync(file);
    } catch (e) {
        if (e.code !== 'ENOENT') {
            throw e;
        }
    }
}

/**
 * Writes a new key pair. Both files are created exclusively (flag "wx"), so an existing file, or a symlink
 * in its place, is never written through; the private key is created with mode 0600 and the public key
 * with 0644. With `force`, existing files are removed first and then created the same way, so a private
 * key never sits in a file with a wider mode. If the second file can't be created, the first is removed
 * again, so a refusal leaves nothing behind.
 *
 * @param {{ privatePath: string, publicPath: string, privateKeyPem: string, publicKeyPem: string, force?: boolean }} options
 * @throws {Error} the fs error, with code EEXIST when a file exists and force is not set
 */
function writeKeyPairFiles({ privatePath, publicPath, privateKeyPem, publicKeyPem, force = false }) {
    if (path.resolve(privatePath) === path.resolve(publicPath)) {
        throw new UsageError('the private and the public key must go to two different files');
    }
    if (force) {
        removeIfPresent(privatePath);
        removeIfPresent(publicPath);
    }

    const written = [];
    try {
        for (const [file, contents, mode] of [[privatePath, privateKeyPem, PRIVATE_KEY_FILE_MODE], [publicPath, publicKeyPem, PUBLIC_KEY_FILE_MODE]]) {
            const fd = fs.openSync(file, 'wx', mode);
            written.push(file);
            try {
                // The mode given to open is narrowed by the umask; set it exactly.
                fs.fchmodSync(fd, mode);
                fs.writeFileSync(fd, contents);
            } finally {
                fs.closeSync(fd);
            }
        }
    } catch (e) {
        for (const file of written) {
            removeIfPresent(file);
        }
        throw e;
    }
}

/**
 * Reads a key file without following it past a sane size.
 *
 * @param {string} file
 * @param {{ accept?: 'public'|'private'|'any' }} [options]
 */
function readSigningKeyFile(file, options) {
    let fd;
    try {
        fd = fs.openSync(file, 'r');
    } catch (e) {
        throw new UsageError(`cannot read the key file ${JSON.stringify(file)}: ${e.code || 'error'}`);
    }

    let text;
    try {
        const stat = fs.fstatSync(fd);
        if (!stat.isFile()) {
            throw new UsageError(`${JSON.stringify(file)} is not a file`);
        }
        if (stat.size > MAX_KEY_FILE_BYTES) {
            throw invalidKey('the file is far larger than an Ed25519 or P-256 key');
        }
        text = fs.readFileSync(fd, 'utf8');
    } finally {
        fs.closeSync(fd);
    }

    return readSigningKey(text, options);
}

/** @returns {boolean} whether text is a challenge exactly as the dashboard issues one */
const isChallenge = text => typeof text === 'string' && KEYPAIR_FORMAT.CHALLENGE_PATTERN.test(text);

/** @returns {boolean} whether text is an API version as x-api-version names it (YYYY-MM-DD) */
const isApiVersion = text => typeof text === 'string' && API_VERSION_PATTERN.test(text);

/** @returns {boolean} whether text has the shape of an API key id as the dashboard shows it */
const isApiKeyId = text => typeof text === 'string' && KEYPAIR_FORMAT.API_KEY_ID_PATTERN.test(text);

/**
 * @param {{ apiKeyId: string, fingerprint: string, challenge: string }} fields
 * @returns {Buffer} the UTF-8 bytes of the proof string
 */
function challengeProofMessage({ apiKeyId, fingerprint, challenge }) {
    return Buffer.from([KEYPAIR_FORMAT.CHALLENGE_TAG, apiKeyId, fingerprint, challenge].join('\n'), 'utf8');
}

function requireSigningKey(key) {
    if (!key || !key.privateKey || !Object.values(ALGORITHMS).includes(key.algorithm)) {
        throw new TypeError('key must be a private key read by readSigningKey or readSigningKeyFile');
    }
}

/** Ed25519: the raw 64-byte signature; P-256: ECDSA over SHA-256, DER encoded. Standard base64 with padding. */
function signMessage(key, message) {
    requireSigningKey(key);
    const signature = key.algorithm === ALGORITHMS.ED25519
        ? crypto.sign(null, message, key.privateKey)
        : crypto.sign('sha256', message, { key: key.privateKey, dsaEncoding: 'der' });

    return signature.toString('base64');
}

/**
 * Verifies a signature the way the gateway and the registration do: canonical padded base64, Ed25519
 * exactly 64 bytes, P-256 DER only (IEEE P1363 r||s, and any DER OpenSSL would not write that way, refused).
 */
function verifyMessage(key, message, signatureText) {
    if (!key || !key.publicKey || !Object.values(ALGORITHMS).includes(key.algorithm)) {
        throw new TypeError('key must be a key read by readSigningKey, inspectPublicKey or readSigningKeyFile');
    }
    const signature = strictBase64(signatureText);
    if (!signature) {
        return false;
    }

    try {
        return key.algorithm === ALGORITHMS.ED25519
            ? signature.length === 64 && crypto.verify(null, message, key.publicKey, signature)
            : crypto.verify('sha256', message, { key: key.publicKey, dsaEncoding: 'der' }, signature);
    } catch (e) {
        return false;
    }
}

function requireProofFields({ apiKeyId, challenge }) {
    if (typeof apiKeyId !== 'string' || apiKeyId === '' || !/^[\x21-\x7e]+$/.test(apiKeyId)) {
        throw new UsageError('the API key id must be the id the dashboard shows, with no spaces or line breaks');
    }
    if (!isChallenge(challenge)) {
        throw new UsageError('the challenge must be "vk-chal-" followed by 64 lowercase hex characters, exactly as the dashboard shows it');
    }
}

/**
 * Signs the proof of possession for a key being registered on an API key.
 *
 * @param {Object} key a private key from readSigningKey / readSigningKeyFile
 * @param {{ apiKeyId: string, challenge: string }} fields
 * @returns {string} the signature, standard base64 with padding
 */
function signChallengeProof(key, { apiKeyId, challenge }) {
    requireProofFields({ apiKeyId, challenge });

    return signMessage(key, challengeProofMessage({ apiKeyId, fingerprint: key.fingerprint, challenge }));
}

/**
 * Checks a proof of possession the way a registration does: over the proof string built from the API key
 * id, the fingerprint of the key given and the challenge.
 *
 * @param {Object} key a public (or private) key from readSigningKey / inspectPublicKey
 * @param {{ apiKeyId: string, challenge: string, signature: string }} proof
 * @returns {boolean}
 */
function verifyChallengeProof(key, { apiKeyId, challenge, signature }) {
    if (typeof apiKeyId !== 'string' || apiKeyId === '' || /\s/.test(apiKeyId) || !isChallenge(challenge)) {
        return false;
    }

    return verifyMessage(key, challengeProofMessage({ apiKeyId, fingerprint: key.fingerprint, challenge }), signature);
}

/**
 * The fields both request signatures cover, one per line. Header values, the nonce and the query string
 * can't hold a raw newline; the raw body can, so it goes last.
 *
 * @param {{ timestamp: string, method: string, path: string, apiVersion?: string, passphrase: string,
 *           nonce?: string, query?: string, body?: string }} fields
 *        path without the query (with the /v2 prefix if the request uses it); query = the raw text after
 *        "?"; body = the raw body as sent; apiVersion = the x-api-version header, if sent
 * @returns {string[]}
 */
function requestLines({ timestamp, method, path: requestPath, apiVersion, passphrase, nonce, query, body }) {
    return [
        timestamp,
        method,
        requestPath,
        apiVersion || '',
        passphrase,
        nonce || '',
        query || '',
        body || '',
    ];
}

/** @returns {Buffer} the string signed with the API secret for x-api-sign, version 2: UTF-8, no trailing newline */
const hmacV2RequestMessage = fields => Buffer.from([KEYPAIR_FORMAT.HMAC_V2_TAG, ...requestLines(fields)].join('\n'), 'utf8');

/**
 * The string signed with the private key for x-api-keypair-sign: the tag, the x-api-key the request is sent
 * with, then the HMAC v2 fields. The API key is in it because two API keys may hold the same public key: a
 * request signed for one is then refused under the other.
 *
 * @param {Object} fields apiKey = the x-api-key header, and the fields of requestLines
 * @returns {Buffer} UTF-8, no trailing newline
 */
function keypairRequestMessage({ apiKey, ...fields }) {
    if (typeof apiKey !== 'string' || apiKey === '' || /[\r\n]/.test(apiKey)) {
        throw new UsageError('the API key must be one line of text');
    }

    return Buffer.from([KEYPAIR_FORMAT.REQUEST_TAG, apiKey, ...requestLines(fields)].join('\n'), 'utf8');
}

/**
 * Checks x-api-keypair-sign the way the gateway does: x-api-keypair-id must name one of the registered
 * keys, and the signature must verify with it over the request as received, under the x-api-key it was
 * received with.
 *
 * @param {Array<Object>} registeredKeys keys from readSigningKey / inspectPublicKey
 * @param {Object} fields the request fields, as for keypairRequestMessage (apiKey included)
 * @param {{ keypairId: string, keypairSign: string }} headers
 * @returns {{ valid: true } | { valid: false, reason: 'unknown_api_keypair_id'|'invalid_api_keypair_sign' }}
 */
function verifyKeypairRequest(registeredKeys, fields, { keypairId, keypairSign }) {
    const key = registeredKeys.find(candidate => candidate.fingerprint === keypairId);
    if (!key) {
        return { valid: false, reason: 'unknown_api_keypair_id' };
    }

    return verifyMessage(key, keypairRequestMessage(fields), keypairSign)
        ? { valid: true }
        : { valid: false, reason: 'invalid_api_keypair_sign' };
}

// Standard base64, padding optional: how Vaultody issues API secrets (10 random bytes, padded).
const API_SECRET_SHAPE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?$/;

/**
 * The HMAC key of an API secret. Only standard base64 is taken (padding optional), decoding to at least one
 * byte: anything else is refused rather than decoded leniently, so every language derives the same key
 * from the same text or refuses it (test-vectors/request-hmac-v2.json).
 *
 * @param {string} apiSecret
 * @returns {Buffer}
 * @throws {UsageError} code 'invalid_api_secret'; the message never contains the secret
 */
function decodeApiSecret(apiSecret) {
    if (typeof apiSecret !== 'string' || apiSecret === '' || !API_SECRET_SHAPE.test(apiSecret)) {
        throw new UsageError('the API secret must be the base64 text the dashboard shows', 'invalid_api_secret');
    }
    const key = Buffer.from(apiSecret, 'base64');
    if (key.length === 0) {
        throw new UsageError('the API secret must be the base64 text the dashboard shows', 'invalid_api_secret');
    }

    return key;
}

/**
 * x-api-sign, version 2: base64 HMAC-SHA256 keyed with the decoded API secret over hmacV2RequestMessage.
 *
 * @param {string} apiSecret
 * @param {Object} fields as for hmacV2RequestMessage
 * @returns {string}
 */
function hmacV2Signature(apiSecret, fields) {
    return crypto.createHmac('sha256', decodeApiSecret(apiSecret)).update(hmacV2RequestMessage(fields)).digest('base64');
}

function requireCredentials({ apiKey, apiSecret, passphrase }) {
    for (const [name, value] of [['apiKey', apiKey], ['passphrase', passphrase]]) {
        if (typeof value !== 'string' || value === '') {
            throw new UsageError(`the ${name} is missing`);
        }
    }
    decodeApiSecret(apiSecret);
}

/**
 * The fields both request signatures cover, with the timestamp and nonce filled in when not given.
 *
 * @returns {Object}
 */
function requestFields(passphrase, request) {
    const timestamp = request.timestamp || String(Math.floor(Date.now() / 1000));
    const nonce = request.nonce || crypto.randomBytes(16).toString('hex');
    if (!KEYPAIR_FORMAT.NONCE_PATTERN.test(nonce)) {
        throw new UsageError('the nonce must be 1 to 128 printable ASCII characters without spaces');
    }

    return { ...request, timestamp, nonce, passphrase };
}

/**
 * The authentication headers of one API request signed with the API secret only (HMAC v2), for an API key
 * without a request-signing key pair. A fresh nonce is used unless one is given, so the gateway's replay
 * protection can tell a resend from a new request.
 *
 * @param {{ apiKey: string, apiSecret: string, passphrase: string }} credentials
 * @param {{ method: string, path: string, query?: string, body?: string, apiVersion?: string,
 *           timestamp?: string, nonce?: string }} request
 * @returns {Object} header name → value
 */
function signHmacV2Request(credentials, request) {
    requireCredentials(credentials);
    const fields = requestFields(credentials.passphrase, request);
    const headers = {
        [API_HEADERS.apiKey]: credentials.apiKey,
        [API_HEADERS.passphrase]: credentials.passphrase,
        [API_HEADERS.timestamp]: fields.timestamp,
        [API_HEADERS.sign]: hmacV2Signature(credentials.apiSecret, fields),
        [API_HEADERS.signVersion]: '2',
        [API_HEADERS.nonce]: fields.nonce,
    };
    if (request.apiVersion) {
        headers[API_HEADERS.apiVersion] = request.apiVersion;
    }

    return headers;
}

/**
 * The authentication headers of one API request, signed both ways: x-api-sign with the API secret (HMAC v2)
 * and x-api-keypair-sign with the private key.
 *
 * @param {Object} key a private key from readSigningKey / readSigningKeyFile
 * @param {{ apiKey: string, apiSecret: string, passphrase: string }} credentials
 * @param {{ method: string, path: string, query?: string, body?: string, apiVersion?: string,
 *           timestamp?: string, nonce?: string }} request
 * @returns {Object} header name → value
 */
function signApiRequest(key, credentials, request) {
    requireSigningKey(key);
    requireCredentials(credentials);
    const fields = requestFields(credentials.passphrase, request);
    const headers = signHmacV2Request(credentials, fields);
    const { [API_HEADERS.apiVersion]: apiVersion, ...rest } = headers;

    return {
        ...rest,
        [API_HEADERS.keypairSign]: signMessage(key, keypairRequestMessage({ ...fields, apiKey: credentials.apiKey })),
        [API_HEADERS.keypairId]: key.fingerprint,
        ...(apiVersion === undefined ? {} : { [API_HEADERS.apiVersion]: apiVersion }),
    };
}

const P1363_SIGNATURE_BYTES = 64;

function derInteger(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
        start += 1;
    }
    const body = bytes.subarray(start);
    const integer = body[0] & 0x80 ? Buffer.concat([Buffer.from([0]), body]) : body;

    return Buffer.concat([Buffer.from([0x02, integer.length]), integer]);
}

/**
 * A P-256 signature as IEEE P1363 (r || s, 32 bytes each, as Web Crypto, Azure Key Vault and some KMS APIs
 * return it) in the DER form the gateway requires for x-api-keypair-sign.
 *
 * @param {Buffer|Uint8Array} signature exactly 64 bytes
 * @returns {Buffer} DER SEQUENCE { INTEGER r, INTEGER s }
 * @throws {SignatureFormatError} 'invalid_length' unless 64 bytes; 'zero_integer' when r or s is zero
 */
function p1363ToDer(signature) {
    if (!(signature instanceof Uint8Array) || signature.length !== P1363_SIGNATURE_BYTES) {
        throw new SignatureFormatError('invalid_length', `a P1363 P-256 signature is ${P1363_SIGNATURE_BYTES} bytes`);
    }
    const bytes = Buffer.from(signature.buffer, signature.byteOffset, signature.byteLength);
    const r = bytes.subarray(0, 32);
    const s = bytes.subarray(32);
    if (r.every(byte => byte === 0) || s.every(byte => byte === 0)) {
        throw new SignatureFormatError('zero_integer', 'r and s of a signature are never zero');
    }
    const body = Buffer.concat([derInteger(r), derInteger(s)]);

    return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

// Hosts that are this machine: plain HTTP is allowed only to these, for a port-forward to a test environment.
const LOOPBACK_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])$/;

/**
 * The URL of the signing-keys endpoint under an API root such as https://rest.vaultody.com. The request
 * carries the API key and the passphrase in its headers, so it goes over HTTPS, or over plain HTTP only to
 * this machine (a port-forward). Credentials, a query or a fragment in the root are refused, and the root
 * itself is never repeated in an error.
 *
 * @param {string} [apiRoot]
 * @returns {URL}
 */
function signingKeysUrl(apiRoot = DEFAULT_API_ROOT) {
    let url;
    try {
        url = new URL(apiRoot);
    } catch (e) {
        throw new UsageError('the API root must be an absolute URL such as https://rest.vaultody.com');
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        throw new UsageError('the API root must be an https URL');
    }
    if (url.protocol === 'http:' && !LOOPBACK_HOST.test(url.hostname)) {
        throw new UsageError('the API root must be an https URL: the request carries the passphrase, so plain http is allowed '
            + 'only to this machine (localhost, for a port-forward)');
    }
    if (url.username !== '' || url.password !== '') {
        throw new UsageError('the API root must not hold a user name or password');
    }
    if (url.search !== '' || url.hash !== '' || apiRoot.includes('?') || apiRoot.includes('#')) {
        throw new UsageError('the API root must not have a query or fragment');
    }
    url.pathname = url.pathname.replace(/\/+$/, '') + SIGNING_KEYS_PATH;

    return url;
}

function parseJson(body, status) {
    try {
        return JSON.parse(body.toString('utf8'));
    } catch (e) {
        throw new UnexpectedResponseError(`the API answered ${status} with a body that is not JSON`, { status });
    }
}

/**
 * Reads an answer of GET /api-keys/current/signing-keys, already verified, and says whether the key with
 * this fingerprint is registered and active. No I/O: the caller sends the request and checks the response
 * signature first (test-vectors/signing-keys-v1.json).
 *
 * @param {{ status: number, body: Buffer|Uint8Array|string }} response
 * @param {string} fingerprint the fingerprint of the key that signed the request
 * @param {string} [algorithm] reported back unchanged
 * @returns {{ outcome: 'active'|'inactive'|'not_listed'|'refused', fingerprint: string, algorithm: string|undefined,
 *          status: number, requestId: string|null, keys: Array<Object>, error: { code: string, message: string }|null }}
 * @throws {UnexpectedResponseError} an answer that is neither the list nor a refusal
 */
function readSigningKeysResponse(response, fingerprint, algorithm) {
    const { status } = response;
    const body = typeof response.body === 'string' ? Buffer.from(response.body, 'utf8') : Buffer.from(response.body);
    const result = {
        fingerprint,
        algorithm,
        status,
        requestId: null,
        keys: [],
        error: null,
    };

    if (status === 401 || status === 403) {
        const parsed = parseJson(body, status);
        const error = parsed && typeof parsed.error === 'object' && parsed.error !== null ? parsed.error : {};
        result.requestId = parsed && typeof parsed.requestId === 'string' ? parsed.requestId : null;
        result.error = {
            code: typeof error.code === 'string' ? error.code : 'unknown',
            message: typeof error.message === 'string' ? error.message : '',
        };

        return { ...result, outcome: 'refused' };
    }

    if (status !== 200) {
        let code;
        let requestId;
        try {
            const parsed = JSON.parse(body.toString('utf8'));
            code = parsed && parsed.error && typeof parsed.error.code === 'string' ? parsed.error.code : undefined;
            requestId = parsed && typeof parsed.requestId === 'string' ? parsed.requestId : undefined;
        } catch (e) {
            // not JSON: the status says enough
        }
        throw new UnexpectedResponseError(`the API answered ${status}${code ? ` (${code})` : ''}`, { status, requestId, code });
    }

    const parsed = parseJson(body, status);
    const items = parsed && parsed.data && Array.isArray(parsed.data.items) ? parsed.data.items : null;
    if (!items) {
        throw new UnexpectedResponseError('the API answered 200 without a list of signing keys', { status });
    }
    result.requestId = typeof parsed.requestId === 'string' ? parsed.requestId : null;
    result.keys = items.filter(item => item && typeof item === 'object').map(item => ({
        fingerprint: String(item.fingerprint),
        algorithm: String(item.algorithm),
        status: String(item.status),
        createdTimestamp: item.createdTimestamp === undefined ? null : item.createdTimestamp,
        approvedTimestamp: item.approvedTimestamp === undefined ? null : item.approvedTimestamp,
    }));

    const listed = result.keys.find(item => item.fingerprint === fingerprint);
    let outcome = 'not_listed';
    if (listed) {
        outcome = listed.status === ACTIVE ? 'active' : 'inactive';
    }

    return { ...result, outcome };
}

module.exports = {
    ALGORITHMS,
    KEYPAIR_FORMAT,
    API_HEADERS,
    KEY_ERRORS,
    SIGNING_KEYS_PATH,
    SIGNING_KEYS_API_VERSION,
    DEFAULT_API_ROOT,
    SigningKeyError,
    SignatureFormatError,
    UsageError,
    UnexpectedResponseError,
    fingerprintOf,
    pemBody,
    readSigningKey,
    readSigningKeyFile,
    inspectPublicKey,
    generateSigningKeyPair,
    writeKeyPairFiles,
    isChallenge,
    isApiKeyId,
    isApiVersion,
    challengeProofMessage,
    signChallengeProof,
    verifyChallengeProof,
    hmacV2RequestMessage,
    keypairRequestMessage,
    verifyKeypairRequest,
    decodeApiSecret,
    hmacV2Signature,
    signHmacV2Request,
    signApiRequest,
    p1363ToDer,
    signingKeysUrl,
    readSigningKeysResponse,
};
