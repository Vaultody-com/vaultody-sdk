'use strict';

// test-vectors/webhook-v1.json through the client's webhook helper: every verdict, then the typed event.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { Vaultody, MemoryVaultKeyStore, verifyWebhook, WebhookSignatureError, WebhookPayloadError, ConfigurationError, WEBHOOK_EVENTS } = require('../src');
const { CREDENTIALS } = require('./helpers');
const { load } = require('./vectors');

const VECTORS = load('webhook-v1.json');

const client = secrets => new Vaultody({ apiKey: CREDENTIALS.apiKey, apiSecret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, vaultKeyStore: new MemoryVaultKeyStore(), ...(secrets ? { webhookSecrets: secrets } : {}) });
const sign = (body, secret) => crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(body).digest('hex');

describe('test-vectors/webhook-v1.json through the webhook helper', () => {
    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            const body = Buffer.from(vector.bodyBase64, 'base64');
            const fromClient = () => client(vector.secrets).webhooks.verify(body, vector.headers);
            if (vector.expected.valid) {
                const event = fromClient();
                assert.equal(event.secretIndex, vector.expected.secretIndex);
                const parsed = JSON.parse(body.toString('utf8'));
                assert.equal(event.event, parsed.data.event);
                assert.equal(event.idempotencyKey, parsed.idempotencyKey === undefined ? null : parsed.idempotencyKey);
                assert.deepEqual(event.body, parsed);
                assert.deepEqual(verifyWebhook(body, vector.headers, vector.secrets), event);
            } else {
                assert.throws(fromClient, error => error instanceof WebhookSignatureError && error.reason === vector.expected.reason);
            }
        });
    }
});

describe('webhook events', () => {
    const secret = 'TEST-ONLY webhook signing secret A';
    const deliver = data => {
        const body = Buffer.from(JSON.stringify({ walletId: 'w', webhookId: 'h', idempotencyKey: 'k', apiVersion: '2026-03-20', data }), 'utf8');

        return verifyWebhook(body, { 'X-Signature': sign(body, secret) }, secret);
    };

    it('types the documented events, INCOMING_TX_REVERTED included, and passes inclusion through', () => {
        assert.ok(WEBHOOK_EVENTS.includes('INCOMING_TX_REVERTED'));
        const event = deliver({ event: 'INCOMING_TX_REVERTED', item: { transactionId: 't' }, inclusion: { blockHeight: 7, blockHash: 'b' } });
        assert.equal(event.known, true);
        assert.deepEqual(event.inclusion, { blockHeight: 7, blockHash: 'b' });
        assert.deepEqual(event.item, { transactionId: 't' });
        assert.equal(event.webhookId, 'h');
    });

    it('returns an unknown event as a generic one, never an error', () => {
        const event = deliver({ event: 'SOMETHING_NEW', item: { a: 1 } });
        assert.equal(event.known, false);
        assert.equal(event.event, 'SOMETHING_NEW');
    });

    it('refuses a parsed object, and a body that verified but is no event', () => {
        assert.throws(() => verifyWebhook({ data: {} }, { 'x-signature': 'a'.repeat(64) }, secret), TypeError);
        const body = Buffer.from('[]');
        assert.throws(() => verifyWebhook(body, { 'x-signature': sign(body, secret) }, secret), WebhookPayloadError);
    });

    it('needs a secret: from the call or the client', () => {
        assert.throws(() => client().webhooks.verify(Buffer.from('{}'), {}), error => error instanceof ConfigurationError && error.code === 'invalid_webhook_secret');
        assert.throws(() => verifyWebhook(Buffer.from('{}'), { 'x-signature': 'a'.repeat(64) }, []), error => error instanceof ConfigurationError);
    });
});
