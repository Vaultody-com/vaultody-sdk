'use strict';

/**
 * Checks the X-Signature Vaultody puts on every webhook delivery: lowercase hex HMAC-SHA256, keyed with
 * the webhook's signing secret, over the raw body bytes (test-vectors/webhook-v1.json).
 *
 * The scheme has no timestamp, and Vaultody may deliver the same event more than once, so a valid signature
 * does not prove a delivery is new: before acting on an event, check whether it was acted on already, keyed on
 * what the event is about (the docs' Webhook Notifications page names the fields). Several secrets can be
 * given, to keep accepting deliveries while a secret is rotated.
 */

const crypto = require('node:crypto');

const { ConfigurationError } = require('./errors');
const { toBytes } = require('./encoding');

const SIGNATURE_HEADER = 'x-signature';
// Exactly what the signer writes: no prefix, no whitespace, lowercase.
const SIGNATURE_FORMAT = /^[0-9a-f]{64}$/;

const WEBHOOK_REASONS = Object.freeze({
    // No X-Signature header, or an empty one.
    MISSING: 'missing',
    // Not 64 lowercase hex characters.
    MALFORMED: 'malformed',
    // Well formed, but no configured secret produces it over this body.
    MISMATCH: 'mismatch',
});

/** Thrown when a delivery's signature does not check out. Treat the body as untrusted; `reason` says why. */
class WebhookSignatureError extends Error {
    constructor(reason, detail) {
        super(`Vaultody webhook signature check failed (${reason}): ${detail}`);
        this.name = 'WebhookSignatureError';
        this.reason = reason;
    }
}

function signatureHeader(headers) {
    if (headers === undefined || headers === null || typeof headers !== 'object') {
        throw new TypeError('headers must be the request headers: a plain object, a Headers instance or a Map');
    }

    let values;
    if (headers instanceof Map) {
        values = [...headers].filter(([key]) => typeof key === 'string' && key.toLowerCase() === SIGNATURE_HEADER).map(([, value]) => value);
    } else if (typeof headers.get === 'function') {
        values = [headers.get(SIGNATURE_HEADER)];
    } else {
        values = Object.keys(headers).filter(key => key.toLowerCase() === SIGNATURE_HEADER).map(key => headers[key]);
    }
    values = values.flat().filter(value => value !== undefined && value !== null);

    if (values.length === 0 || values.every(value => value === '')) {
        throw new WebhookSignatureError(WEBHOOK_REASONS.MISSING, 'the delivery has no X-Signature header');
    }
    if (values.length > 1 || typeof values[0] !== 'string' || !SIGNATURE_FORMAT.test(values[0])) {
        throw new WebhookSignatureError(WEBHOOK_REASONS.MALFORMED, 'X-Signature must be one value of 64 lowercase hex characters');
    }

    return Buffer.from(values[0], 'hex');
}

function readSecrets(secrets) {
    const list = Array.isArray(secrets) ? secrets : [secrets];
    if (list.length === 0 || !list.every(secret => typeof secret === 'string' && secret !== '')) {
        throw new ConfigurationError('the webhook signing secret must be a non-empty string, or a non-empty array of them during a rotation');
    }

    return list;
}

/**
 * Verifies one webhook delivery before its body is parsed.
 *
 * @param {Buffer|Uint8Array|ArrayBuffer|string} rawBody the body exactly as received (not parsed JSON)
 * @param {Object|Headers|Map} headers the request headers; X-Signature is matched case-insensitively
 * @param {string|string[]} secrets the signing secret, or the secrets accepted during a rotation, in order
 * @returns {{ valid: true, secretIndex: number }} the index of the first secret that matches
 * @throws {WebhookSignatureError} the signature is missing, malformed or matches no secret
 * @throws {ConfigurationError} no usable secret is configured
 */
function verifyWebhookSignature(rawBody, headers, secrets) {
    const list = readSecrets(secrets);
    const body = toBytes(rawBody, 'rawBody');
    const received = signatureHeader(headers);

    // Every secret is tried, so the time taken does not tell which one matched.
    let secretIndex = -1;
    list.forEach((secret, index) => {
        const expected = crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest();
        if (crypto.timingSafeEqual(expected, received) && secretIndex === -1) {
            secretIndex = index;
        }
    });
    if (secretIndex === -1) {
        throw new WebhookSignatureError(WEBHOOK_REASONS.MISMATCH, 'no configured secret produces this signature over the body received');
    }

    return { valid: true, secretIndex };
}

module.exports = {
    verifyWebhookSignature,
    WebhookSignatureError,
    WEBHOOK_REASONS,
    SIGNATURE_HEADER,
};
