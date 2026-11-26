'use strict';

// The mock gateway (conformance/mock-gateway) is written apart from the SDK, from the wire formats. These tests
// hold it to the vectors the real gateway's code produced, so a pipeline test passing against it means the
// gateway would accept the same request: its HMAC v2 check (request-hmac-v2.json), its key-pair check
// (request-keypair-v1.json, every verdict) and its response signatures (v1.json).

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { MockGateway, responseMessage, signResponse } = require('../../../../conformance/mock-gateway');
const { CREDENTIALS } = require('./helpers');
const { load } = require('./vectors');

const HMAC = load('request-hmac-v2.json');
const KEYPAIR = load('request-keypair-v1.json');
const RESPONSES = load('v1.json');

const NOW = 1794201000 * 1000;

function receivedRequest(fields, headers) {
    return {
        method: fields.method,
        path: fields.path,
        query: fields.query,
        body: Buffer.from(fields.body, 'utf8'),
        headers: {
            'x-api-key': fields.apiKey || CREDENTIALS.apiKey,
            'x-api-passphrase': fields.passphrase,
            'x-api-timestamp': fields.timestamp,
            'x-api-sign-version': '2',
            ...(fields.nonce ? { 'x-api-nonce': fields.nonce } : {}),
            ...(fields.apiVersion ? { 'x-api-version': fields.apiVersion } : {}),
            ...headers,
        },
    };
}

const hmacV2 = (secret, fields) => crypto.createHmac('sha256', Buffer.from(secret, 'base64'))
    .update(['v2', fields.timestamp, fields.method, fields.path, fields.apiVersion, fields.passphrase, fields.nonce, fields.query, fields.body].join('\n'), 'utf8')
    .digest('base64');

describe('the mock gateway agrees with the gateway vectors', () => {
    describe('test-vectors/request-hmac-v2.json: x-api-sign', () => {
        for (const vector of HMAC.cases.filter(item => !item.expected.error)) {
            it(vector.name, () => {
                const gw = new MockGateway({ clock: () => NOW, keys: { [CREDENTIALS.apiKey]: { secret: vector.secret, passphrase: vector.request.passphrase } } });
                assert.equal(gw.authenticate(receivedRequest(vector.request, { 'x-api-sign': vector.expected.signature })), null);
                const tampered = { ...vector.request, body: `${vector.request.body} ` };
                assert.deepEqual(gw.authenticate(receivedRequest(tampered, { 'x-api-sign': vector.expected.signature })), { status: 401, code: 'invalid_api_sign' });
            });
        }
    });

    describe('test-vectors/request-keypair-v1.json: x-api-keypair-sign', () => {
        for (const vector of KEYPAIR.cases) {
            it(vector.name, () => {
                const registered = vector.verify.registeredKeys.map(name => KEYPAIR.keys[name].publicKeySpkiPem);
                // The request comes with the vector's x-api-key, which is in the key-pair string.
                const gw = new MockGateway({ clock: () => NOW, keys: { [vector.verify.request.apiKey]: { secret: CREDENTIALS.apiSecret, passphrase: vector.verify.request.passphrase, keypairs: registered } } });
                const request = receivedRequest(vector.verify.request, { ...vector.verify.headers, 'x-api-sign': hmacV2(CREDENTIALS.apiSecret, vector.verify.request) });
                const verdict = gw.authenticate(request);
                assert.deepEqual(verdict === null ? { valid: true } : { valid: false, reason: verdict.code }, vector.expected);
            });
        }
    });

    describe('test-vectors/v1.json: response signatures', () => {
        for (const vector of RESPONSES.cases.filter(item => item.signed.messageBase64)) {
            it(vector.name, () => {
                const { signed } = vector;
                const request = {
                    method: signed.request.method,
                    path: signed.request.path,
                    query: signed.request.query,
                    body: Buffer.from(signed.request.bodyBase64, 'base64'),
                    headers: { 'x-api-sign': signed.request.apiSign, 'x-api-keypair-sign': signed.request.keypairSign },
                };
                const body = Buffer.from(signed.bodyBase64, 'base64');
                if (signed.bodyHash !== 'unread' && signed.bodyHash !== crypto.createHash('sha256').update(request.body).digest('hex')) {
                    // tampered_body_hash: the vector's gateway signed a forged body hash on purpose.
                    assert.equal(vector.name, 'tampered_body_hash');

                    return;
                }
                const message = responseMessage({ request, status: signed.status, body, nowSeconds: signed.ts, unreadBody: signed.bodyHash === 'unread' });
                assert.equal(message.toString('base64'), signed.messageBase64);
                if (vector.category === 'valid') {
                    const headers = signResponse({ request, status: signed.status, body, nowSeconds: signed.ts, signing: { pod: signed.signingPod, root: signed.rootSigner } });
                    assert.equal(headers['x-api-response-sign'], signed.headers['x-api-response-sign']);
                    assert.equal(headers['x-api-response-timestamp'], signed.headers['x-api-response-timestamp']);
                }
            });
        }
    });
});
