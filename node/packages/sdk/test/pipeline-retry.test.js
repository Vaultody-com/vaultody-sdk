'use strict';

// Retries through the pipeline (test-vectors/retry-v1.json, transport-errors-v1.json): each scenario makes real
// calls against the mock gateway, with its faults (429, 5xx before or after the route ran, dropped connections,
// a held answer, a moved clock) and its replay protection, and a decision the transport took is matched to the
// vector case of the same name: same class, key mode and outcome, same action, mode and in-progress flag, and
// the same delay where the attempt and the jitter draw are the vector's. (The vectors' counters are set per
// case; the pipeline keeps its own, so they are not compared: the scenario asserts what they decide instead.)
// What the gateway ran is counted, so "a write never runs twice" is checked where it happens.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const {
    ConflictError, DuplicateTransferError, PermissionDeniedError, RateLimitError, ServerError, NotFoundError, AuthenticationError,
    InvalidRequestError, RequestOutcomeUnknownError, TransportError, ResponseVerificationError, RequestSigningError,
} = require('../src');
const { setup, decisions, refused, failingFetch, VAULT } = require('./helpers');
const { load } = require('./vectors');
const internal = require('../src/internal');

const RETRY = load('retry-v1.json');
const TRANSPORT_ERRORS = load('transport-errors-v1.json');

const TRANSFER = { vaultId: VAULT, amount: '0.1', assetId: '6630f1c2a9e4b5d7c8e9f0b7', fromAddress: 'from', toAddress: 'to', note: 'test', vaultAccountId: '6630f1c2a9e4b5d7c8e9f0e2' };
const TX = '6630f1c2a9e4b5d7c8e9f0c4';

const sameInput = (a, b) => a.operation === b.operation && a.keyMode === b.keyMode && a.outcome.type === b.outcome.type
    && (b.outcome.type !== 'response' || (a.outcome.status === b.outcome.status && a.outcome.code === b.outcome.code && a.outcome.replayed === b.outcome.replayed));

/** The transport made the decision of this vector case, on the same facts. */
function assertDecision(trace, name) {
    const vector = RETRY.cases.find(item => item.name === name);
    assert.ok(vector, `no vector ${name}`);
    const found = decisions(trace).find(event => sameInput(event.input, vector.input)
        && event.decision.action === vector.expected.action && event.decision.mode === vector.expected.mode
        && event.decision.nonce === vector.expected.nonce && event.decision.inProgress === vector.expected.inProgress);
    assert.ok(found, `${name}: the transport decided ${JSON.stringify(decisions(trace).map(event => [event.input.outcome, event.input.resends, event.input.mayHaveRun, event.decision]))}`);
    if (vector.expected.delayMs !== undefined && found.input.attempt === vector.input.attempt && found.input.random === vector.input.random) {
        assert.equal(found.decision.delayMs, vector.expected.delayMs, `${name}: delay`);
    }
}

/**
 * One call in a fresh environment.
 *
 * @param {Object} spec
 * @param {boolean} [spec.write=true] createSingleTransfer, else getTransactionRequestDetails
 * @param {'ed25519'|null} [spec.key] a key pair, confirmed active before the call (key-pair mode)
 * @param {Array} [spec.faults] queued on the mock gateway after the confirmation
 * @param {Array} [spec.fetchErrors] thrown by fetch for the call's requests
 */
async function run({ write = true, key = null, faults = [], fetchErrors = null, random = 0, client = {}, gateway = {}, mitm, nonce, before }) {
    let failing = null;
    const unsupported = { random: () => random, ...(nonce ? { nonce } : {}) };
    if (fetchErrors) {
        failing = failingFetch(fetchErrors, init => init.method === (write ? 'POST' : 'GET'));
        unsupported.fetch = failing;
    }
    // The origin signed for this client before, so no signed read precedes the first write: only the call is counted.
    const env = await setup({ key, latched: true, client: { ...client, unsupported }, gateway });
    env.gw.route('POST', /\/single-transfer$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1d1', data: { item: { transactionRequestId: TX } } } }));
    env.gw.route('GET', /^\/transaction-requests\//, () => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: '6630f1c2a9e4b5d7c8e9f1d2', data: { item: { transactionRequestId: TX } } } }));
    if (key) {
        assert.equal((await env.client.confirmSigningKey()).keyMode, 'keypair');
    }
    env.gw.requests.length = 0;
    env.gw.executions.length = 0;
    env.trace.length = 0;
    env.gw.fault(...faults);
    if (mitm) {
        env.gw.mitm = mitm;
    }
    if (before) {
        await before(env);
    }
    let result;
    let error;
    try {
        result = write ? await internal.request(env.client, 'createSingleTransfer', TRANSFER) : await internal.request(env.client, 'getTransactionRequestDetails', { transactionRequestId: TX });
    } catch (e) {
        error = e;
    }
    await env.close();
    const sent = env.gw.requests.map(request => request.headers['x-api-nonce']);

    return { ...env, result, error, failing, runs: env.gw.executions.filter(execution => execution.method === (write ? 'POST' : 'GET')).length, sent };
}

const tamper = ({ response }) => ({ ...response, body: Buffer.from(response.body.toString().replace(TX, `${TX.slice(0, -1)}0`)) });
const advancing = (clockRef, ms, error) => () => {
    clockRef.clock.advance(ms);

    return error;
};

describe('test-vectors/retry-v1.json through the pipeline: reads', () => {
    it('read_ok', async () => {
        const env = await run({ write: false });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'read_ok');
    });

    for (const [name, status, code, ErrorClass] of [
        ['read_not_found', 404, 'resource_not_found', NotFoundError],
        ['read_bad_request', 400, 'invalid_pagination', InvalidRequestError],
    ]) {
        it(name, async () => {
            const env = await run({ write: false, faults: [{ when: 'after', status, code }] });
            assert.ok(env.error instanceof ErrorClass && env.error.code === code);
            assert.equal(env.gw.requests.length, 1);
            assertDecision(env.trace, name);
        });
    }

    it('read_auth_error', async () => {
        const env = await run({ write: false, before: async ({ gw }) => { gw.keys.values().next().value.secret = 'c29tZXRoaW5nIGVsc2U='; } });
        assert.ok(env.error instanceof AuthenticationError && env.error.code === 'invalid_api_sign');
        assertDecision(env.trace, 'read_auth_error');
    });

    it('read_not_sent: re-signed with a new nonce', async () => {
        const env = await run({ write: false, fetchErrors: [refused()], random: 0.5 });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'read_not_sent');
        const [first, second] = env.failing.calls.map(call => call.headers['x-api-nonce']);
        assert.notEqual(first, second);
    });

    it('read_sent_unknown', async () => {
        const env = await run({ write: false, faults: [{ drop: true }] });
        assert.equal(env.result.item.transactionRequestId, TX);
        assert.ok(decisions(env.trace).some(event => event.input.outcome.type === 'sent_unknown' && event.decision.mode === 'resign'));
    });

    it('read_429', async () => {
        const env = await run({ write: false, faults: [{ status: 429, code: 'request_limit_reached' }, { status: 429, code: 'request_limit_reached' }, { status: 429, code: 'request_limit_reached' }], random: 0.25 });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'read_429');
    });

    it('read_503_backoff_cap', async () => {
        const env = await run({ write: false, faults: [1, 2, 3, 4].map(() => ({ when: 'after', status: 503, code: null })), random: 0.999 });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'read_503_backoff_cap');
        assert.deepEqual(env.sleeps, [999, 1998, 3996, 7992]);
    });

    it('read_500_last_attempt', async () => {
        const env = await run({ write: false, faults: [1, 2, 3, 4, 5].map(() => ({ when: 'after', status: 500, code: 'unexpected_server_error' })) });
        assert.ok(env.error instanceof ServerError);
        assert.equal(env.gw.requests.length, 5);
        assertDecision(env.trace, 'read_500_last_attempt');
    });

    it('read_not_sent_last_attempt', async () => {
        const env = await run({ write: false, fetchErrors: [1, 2, 3, 4, 5].map(refused) });
        assert.ok(env.error instanceof TransportError && env.error.sent === false);
        assertDecision(env.trace, 'read_not_sent_last_attempt');
    });

    it('read_retry_after and read_retry_after_shorter', async () => {
        const env = await run({ write: false, faults: [{ status: 429, code: 'request_limit_reached', headers: { 'retry-after': '3' } }], random: 0.1 });
        assertDecision(env.trace, 'read_retry_after');
        assert.deepEqual(env.sleeps, [3000]);
        const shorter = await run({ write: false, faults: [{ status: 429, code: 'request_limit_reached' }, { status: 429, code: 'request_limit_reached', headers: { 'retry-after': '1' } }], random: 0.9 });
        assertDecision(shorter.trace, 'read_retry_after_shorter');
    });

    it('read_deadline', async () => {
        const env = await run({ write: false, faults: [{ when: 'after', status: 502, code: null, advanceClockMs: 29500 }], random: 0.9 });
        assert.ok(env.error instanceof ServerError && env.error.status === 502);
        assertDecision(env.trace, 'read_deadline');
    });

    it('read_verification_failed: thrown at once, never retried', async () => {
        const env = await run({ write: false, mitm: tamper });
        assert.ok(env.error instanceof ResponseVerificationError && env.error.reason === 'invalid');
        assert.equal(env.gw.requests.length, 1);
    });
});

describe('test-vectors/retry-v1.json through the pipeline: writes with a confirmed key pair', () => {
    const key = 'ed25519';

    it('write_created', async () => {
        const env = await run({ key });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'write_created');
    });

    it('write_sent_unknown_resend, then write_replayed_created: the first answer, run once', async () => {
        const env = await run({ key, faults: [{ when: 'after', drop: true }] });
        assert.equal(env.result.item.transactionRequestId, TX);
        assert.equal(env.result.meta.replayed, true);
        assertDecision(env.trace, 'write_sent_unknown_resend');
        assertDecision(env.trace, 'write_replayed_created');
        assert.equal(env.runs, 1);
        assert.equal(new Set(env.sent).size, 1);
    });

    it('write_sent_unknown_too_late', async () => {
        const env = await run({ key, faults: [{ when: 'after', drop: true, advanceClockMs: 2600 }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError && env.error.inProgress === false);
        assertDecision(env.trace, 'write_sent_unknown_too_late');
        assert.equal(env.gw.requests.length, 1);
        assert.equal(env.error.nonce, env.sent[0]);
    });

    it('write_sent_unknown_twice', async () => {
        const env = await run({ key, faults: [{ when: 'after', drop: true }, { drop: true }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError);
        assertDecision(env.trace, 'write_sent_unknown_twice');
        assert.equal(env.runs, 1);
    });

    it('write_500_resend, then write_replayed_500', async () => {
        const env = await run({ key, faults: [{ when: 'after', status: 500, code: 'unexpected_server_error' }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError);
        assertDecision(env.trace, 'write_500_resend');
        assertDecision(env.trace, 'write_replayed_500');
        assert.equal(env.runs, 1);
    });

    it('write_500_too_late', async () => {
        const env = await run({ key, faults: [{ when: 'after', status: 500, code: 'unexpected_server_error', advanceClockMs: 2700 }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError);
        assertDecision(env.trace, 'write_500_too_late');
    });

    it('write_in_progress: the first is still running when the resend arrives', async () => {
        const env = await run({ key, faults: [{ when: 'after', delayMs: 400 }], client: { timeoutMs: 100 }, gateway: { inProgressWaitMs: 50 } });
        assert.ok(env.error instanceof RequestOutcomeUnknownError && env.error.inProgress === true, String(env.error));
        assertDecision(env.trace, 'write_in_progress');
        assert.equal(env.runs, 1);
    });

    it('write_duplicate_after_resend: the resend arrives after the 3 s replay window', async () => {
        const env = await run({ key, faults: [{ when: 'after', drop: true }, { advanceClockMs: 3500 }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError);
        assertDecision(env.trace, 'write_duplicate_after_resend');
        assert.equal(env.runs, 1);
    });

    it('write_duplicate_first_send: a plain error', async () => {
        const nonce = () => 'n-fixed-0001';
        const env = await run({
            key,
            nonce,
            before: async ({ client, clock }) => {
                await internal.request(client, 'createSingleTransfer', TRANSFER);
                clock.advance(4000);
            },
        });
        assert.ok(env.error instanceof AuthenticationError && env.error.code === 'duplicate_api_request');
        assertDecision(env.trace, 'write_duplicate_first_send');
    });

    it('write_not_sent_resend: the same signed request again', async () => {
        const env = await run({ key, fetchErrors: [refused()], random: 0.5 });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'write_not_sent_resend');
        const [first, second] = env.failing.calls.filter(call => call.method === 'POST');
        assert.equal(first.headers['x-api-nonce'], second.headers['x-api-nonce']);
        assert.equal(first.headers['x-api-sign'], second.headers['x-api-sign']);
        assert.equal(first.headers['x-api-keypair-sign'], second.headers['x-api-keypair-sign']);
    });

    it('write_not_sent_signature_too_old: re-signed over the same nonce and body, nothing ran yet', async () => {
        const ref = {};
        const env = await run({ key, fetchErrors: [advancing(ref, 24800, refused())], random: 0.5, before: async ({ clock }) => { ref.clock = clock; } });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'write_not_sent_signature_too_old');
        const posts = env.failing.calls.filter(call => call.method === 'POST');
        // One operation per nonce: only the timestamp and the signatures are new
        assert.equal(posts[0].headers['x-api-nonce'], posts[1].headers['x-api-nonce']);
        assert.deepEqual(posts[0].body, posts[1].body);
        assert.notEqual(posts[0].headers['x-api-timestamp'], posts[1].headers['x-api-timestamp']);
        assert.notEqual(posts[0].headers['x-api-sign'], posts[1].headers['x-api-sign']);
        assert.notEqual(posts[0].headers['x-api-keypair-sign'], posts[1].headers['x-api-keypair-sign']);
    });

    it('write_429_resend: refused before the route, sent again as it was, runs once', async () => {
        const env = await run({ key, faults: [{ status: 429, code: 'request_limit_reached' }] });
        assert.equal(env.result.item.transactionRequestId, TX);
        assert.equal(env.runs, 1);
        assert.equal(new Set(env.sent).size, 1);
        assert.ok(decisions(env.trace).some(event => event.input.outcome.status === 429 && event.decision.mode === 'resend'));
    });

    it('write_429_signature_too_old: re-signed over the same nonce', async () => {
        const env = await run({ key, faults: [{ status: 429, code: 'request_limit_reached', advanceClockMs: 24500 }], random: 0.5 });
        assert.equal(env.result.item.transactionRequestId, TX);
        assert.ok(decisions(env.trace).some(event => event.input.outcome.status === 429 && event.decision.mode === 'resign' && event.decision.nonce === 'same'));
        assert.equal(env.gw.requests.length, 2);
        assert.equal(new Set(env.sent).size, 1);
        assert.equal(new Set(env.gw.requests.map(request => request.headers['x-api-timestamp'])).size, 2);
        assert.equal(env.runs, 1);
    });

    it('write_429_after_possible_run', async () => {
        const env = await run({ key, faults: [{ drop: true }, { status: 429, code: 'request_limit_reached' }] });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'write_429_after_possible_run');
        assert.equal(env.runs, 1);
    });

    // The conflict says nothing was executed, so its one retry is a new operation for the gateway: signed again with
    // a new nonce over the same body (with the same nonce the gateway would only replay the 409), and it runs.
    for (const [name, code] of [['write_address_conflict', 'address_derivation_conflict'], ['write_vault_accounts_conflict', 'vault_accounts_creation_failed']]) {
        it(`${name}: re-signed with a new nonce over the same body, and the retry runs`, async () => {
            const env = await run({ key, faults: [{ status: 409, code }] });
            assertDecision(env.trace, name);
            assert.equal(env.result.item.transactionRequestId, TX);
            const posts = env.gw.requests.filter(request => request.method === 'POST');
            assert.equal(posts.length, 2);
            assert.notEqual(posts[0].headers['x-api-nonce'], posts[1].headers['x-api-nonce']);
            assert.deepEqual(posts[0].body, posts[1].body);
            assert.equal(posts[1].headers['x-api-replayed'], undefined);
            assert.equal(env.runs, 1);
        });
    }

    it('after the conflict retry, a further retry keeps the new nonce', async () => {
        const env = await run({ key, faults: [{ status: 409, code: 'address_derivation_conflict' }, { status: 429, code: 'request_limit_reached' }] });
        assert.equal(env.result.item.transactionRequestId, TX);
        const [first, second, third] = env.gw.requests.filter(request => request.method === 'POST').map(request => request.headers['x-api-nonce']);
        assert.notEqual(first, second);
        assert.equal(second, third);
        assert.equal(env.runs, 1);
    });

    it('write_address_conflict_twice: one conflict retry only', async () => {
        const env = await run({ key, faults: [{ status: 409, code: 'address_derivation_conflict' }, { status: 409, code: 'address_derivation_conflict' }] });
        assert.ok(env.error instanceof ConflictError && env.error.retryable === true);
        const [, second] = decisions(env.trace);
        assert.equal(second.input.conflictRetried, true);
        assert.deepEqual(second.decision, RETRY.cases.find(item => item.name === 'write_address_conflict_twice').expected);
        assert.equal(decisions(env.trace).length, 2);
    });

    it('write_conflict_after_possible_run', async () => {
        const env = await run({ key, faults: [{ drop: true }, { when: 'after', status: 409, code: 'address_derivation_conflict' }] });
        assert.ok(env.error instanceof ConflictError);
        assertDecision(env.trace, 'write_conflict_after_possible_run');
    });

    for (const [name, status, code, ErrorClass] of [
        ['write_double_spending', 409, 'double_spending', DuplicateTransferError],
        ['write_forbidden', 403, 'wallet_as_a_service_wallet_balance_not_enough', PermissionDeniedError],
        ['write_nonce_reused', 409, 'api_nonce_reused', RequestSigningError],
    ]) {
        it(name, async () => {
            const env = await run({ key, faults: [{ when: 'after', status, code }] });
            assert.ok(env.error instanceof ErrorClass && env.error.code === code);
            assertDecision(env.trace, name);
            assert.equal(env.gw.requests.length, 1);
        });
    }

    it('write_verification_failed: thrown at once, never resent', async () => {
        const env = await run({ key, mitm: tamper });
        assert.ok(env.error instanceof ResponseVerificationError);
        assert.equal(env.gw.requests.length, 1);
    });

    it('write_not_sent_last_attempt', async () => {
        const env = await run({ key, fetchErrors: [1, 2, 3, 4, 5].map(refused) });
        assert.ok(env.error instanceof TransportError && env.error.sent === false);
        assertDecision(env.trace, 'write_not_sent_last_attempt');
    });

    it('write_429_last_attempt', async () => {
        const env = await run({ key, faults: [1, 2, 3, 4, 5].map(() => ({ status: 429, code: 'request_limit_reached' })) });
        assert.ok(env.error instanceof RateLimitError);
        assertDecision(env.trace, 'write_429_last_attempt');
    });

    it('write_not_sent_deadline', async () => {
        const ref = {};
        const env = await run({ key, fetchErrors: [1, 2, 3].map(() => advancing(ref, 14000, refused())), random: 0.9, before: async ({ clock }) => { ref.clock = clock; } });
        assert.ok(env.error instanceof TransportError && env.error.sent === false);
        assert.equal(decisions(env.trace).pop().decision.action, 'fail');
    });
});

describe('test-vectors/retry-v1.json through the pipeline: writes with a legacy key', () => {
    it('legacy_created', async () => {
        const env = await run({});
        assertDecision(env.trace, 'legacy_created');
    });

    it('legacy_sent_unknown: never resent, outcome unknown', async () => {
        const env = await run({ faults: [{ when: 'after', drop: true }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError);
        assertDecision(env.trace, 'legacy_sent_unknown');
        assert.equal(env.gw.requests.length, 1);
    });

    it('legacy_500', async () => {
        const env = await run({ faults: [{ when: 'after', status: 500, code: 'unexpected_server_error' }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError);
        assertDecision(env.trace, 'legacy_500');
        assert.equal(env.gw.requests.length, 1);
    });

    it('legacy_not_sent: resent as it was', async () => {
        const env = await run({ fetchErrors: [refused()], random: 0.5 });
        assert.equal(env.result.item.transactionRequestId, TX);
        assertDecision(env.trace, 'legacy_not_sent');
    });

    it('legacy_429, legacy_429_retry_after and legacy_429_signature_too_old', async () => {
        const env = await run({ faults: [{ status: 429, code: 'request_limit_reached' }], random: 0.5 });
        assertDecision(env.trace, 'legacy_429');
        assert.equal(env.runs, 1);
        const after = await run({ faults: [{ status: 429, code: 'request_limit_reached', headers: { 'retry-after': '2' } }], random: 0.1 });
        assertDecision(after.trace, 'legacy_429_retry_after');
        assert.deepEqual(after.sleeps, [2000]);
        const old = await run({ faults: [{ status: 429, code: 'request_limit_reached', advanceClockMs: 24900 }], random: 0.5 });
        assertDecision(old.trace, 'legacy_429_signature_too_old');
    });

    it('legacy_address_conflict', async () => {
        const env = await run({ faults: [{ status: 409, code: 'address_derivation_conflict' }] });
        assertDecision(env.trace, 'legacy_address_conflict');
        assert.equal(env.result.item.transactionRequestId, TX);
        assert.equal(new Set(env.sent).size, 2);
    });

    it('a write is resent only when the key pair is confirmed: unconfirmed counts as legacy', async () => {
        // A signer whose key the API key does not hold: confirmation says not_listed, so a lost answer is not resent.
        const env = await run({ key: null, client: { signer: require('../src').pemSigner(require('./helpers').KEYS.ed25519.privateKeyPkcs8Pem) }, faults: [null, { when: 'after', drop: true }] });
        assert.ok(env.error instanceof RequestOutcomeUnknownError);
        // The retry decisions were made for a legacy key.
        assert.ok(env.trace.some(event => event.type === 'decision' && event.input.keyMode === 'legacy'));
        assert.equal(env.gw.requests.filter(request => request.method === 'POST').length, 1);
    });
});

describe('test-vectors/transport-errors-v1.json through the pipeline (node)', () => {
    function build(description) {
        const { name, message = '', code, cause, errors } = description;
        const error = errors ? new AggregateError(errors.map(build), message) : name === 'TypeError' ? new TypeError(message) : new Error(message);
        if (!errors && name !== 'TypeError' && name !== 'Error') {
            error.name = name;
        }
        if (code !== undefined) {
            error.code = code;
        }
        if (cause !== undefined) {
            error.cause = build(cause);
        }

        return error;
    }

    for (const vector of TRANSPORT_ERRORS.node) {
        it(vector.name, async () => {
            const read = await run({ write: false, client: {}, fetchErrors: [1, 2, 3, 4, 5].map(() => build(vector.error)) });
            assert.ok(read.error instanceof TransportError, String(read.error));
            assert.equal(read.error.sent, vector.expected.sent);
            assert.equal(read.failing.calls.length, 5);
            const write = await run({ fetchErrors: [1, 2, 3, 4, 5].map(() => build(vector.error)) });
            if (vector.expected.sent === false) {
                assert.ok(write.error instanceof TransportError && write.error.sent === false);
            } else {
                assert.ok(write.error instanceof RequestOutcomeUnknownError, String(write.error));
                assert.equal(write.failing.calls.length, 1);
            }
        });
    }
});
