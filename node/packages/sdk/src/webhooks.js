'use strict';

/**
 * Webhook deliveries: verify X-Signature over the raw body, then read the event (test-vectors/webhook-v1.json).
 *
 * The signature is checked before anything is parsed, against each configured secret in constant time, so a
 * rotation can accept the old and the new secret for a while. The scheme has no timestamp, and Vaultody may
 * deliver the same event more than once, so a valid signature does not prove a delivery is new: before acting
 * on an event, check whether it was acted on already, keyed on what the event is about, as the docs' Webhook
 * Notifications page says (outgoing transaction events: item.requestId and event; incoming ones:
 * item.transactionId, item.address, event and item.currentConfirmations, with item.parentTransactionId and
 * item.operationId in place of transactionId for an internal transfer). The SDK stores nothing. The headers
 * are taken whole, so a future signature header with a timestamp fits without a new signature here.
 */

const { verifyWebhookSignature, WebhookSignatureError: VerifyWebhookError } = require('@vaultody-com/verify/webhook');
const { ConfigurationError: VerifyConfigurationError } = require('@vaultody-com/verify/response');
const { WebhookSignatureError, WebhookPayloadError, ConfigurationError } = require('./errors');

/** The events the API documents; any other value of data.event is returned as it is, with known: false. */
const WEBHOOK_EVENTS = Object.freeze([
    'TRANSACTION_REQUEST',
    'TRANSACTION_APPROVED',
    'TRANSACTION_REJECTED',
    'TRANSACTION_BROADCASTED',
    'OUTGOING_MINED',
    'OUTGOING_MINED_WITH_ERRORS',
    'OUTGOING_FAILED',
    'INCOMING_MINED_TX',
    'INCOMING_CONFIRMED_COIN_TX',
    'INCOMING_CONFIRMED_TOKEN_TX',
    'INCOMING_CONFIRMED_INTERNAL_TX',
    // An incoming transaction that was in a block the chain left (a reorganisation).
    'INCOMING_TX_REVERTED',
]);
const KNOWN = new Set(WEBHOOK_EVENTS);

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const stringOrNull = value => (typeof value === 'string' ? value : null);

/**
 * Verifies one delivery and reads its event.
 *
 * @param {Buffer|Uint8Array|ArrayBuffer|string} rawBody the body exactly as received, not parsed JSON
 * @param {Object|Headers|Map} headers the request headers
 * @param {string|string[]} secrets the webhook's signing secret, or the secrets accepted during a rotation
 * @returns {{ event: string, known: boolean, item: Object|null, idempotencyKey: string|null, webhookId: string|null,
 *            walletId: string|null, apiVersion: string|null, inclusion: *, secretIndex: number, body: Object }}
 *          item is data.item; inclusion is data.inclusion when the event carries one (where the transaction sits
 *          in the chain); body is the whole parsed delivery, unknown fields included
 * @throws {WebhookSignatureError} missing, malformed or mismatch: treat the body as untrusted
 * @throws {WebhookPayloadError} it verified but is not a JSON object with data.event
 * @throws {ConfigurationError} no usable secret
 */
function verifyWebhook(rawBody, headers, secrets) {
    let verdict;
    try {
        verdict = verifyWebhookSignature(rawBody, headers, secrets);
    } catch (error) {
        if (error instanceof VerifyWebhookError) {
            throw new WebhookSignatureError(error.reason, `the webhook delivery failed its signature check (${error.reason}); do not use its body`);
        }
        if (error instanceof VerifyConfigurationError) {
            throw new ConfigurationError('invalid_webhook_secret', error.message);
        }
        throw error;
    }

    let body;
    try {
        body = JSON.parse(Buffer.from(typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody).toString('utf8'));
    } catch (e) {
        throw new WebhookPayloadError('the webhook delivery verified, but its body is not JSON');
    }
    const data = isObject(body) ? body.data : null;
    if (!isObject(data) || typeof data.event !== 'string' || data.event === '') {
        throw new WebhookPayloadError('the webhook delivery verified, but it has no data.event');
    }

    return {
        event: data.event,
        known: KNOWN.has(data.event),
        item: isObject(data.item) ? data.item : null,
        idempotencyKey: stringOrNull(body.idempotencyKey),
        webhookId: stringOrNull(body.webhookId),
        walletId: stringOrNull(body.walletId),
        apiVersion: stringOrNull(body.apiVersion),
        inclusion: data.inclusion === undefined ? null : data.inclusion,
        secretIndex: verdict.secretIndex,
        body,
    };
}

module.exports = {
    WEBHOOK_EVENTS,
    verifyWebhook,
};
