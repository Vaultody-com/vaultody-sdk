'use strict';

/**
 * Whether and how to try a call again after one attempt, without I/O (test-vectors/retry-v1.json).
 *
 * The rule that matters most: a write is never signed again with a new nonce once any attempt of it may
 * have reached the gateway, because the gateway's replay protection recognises a duplicate only by its
 * nonce. A resend of the same signed request is safe: within about 3 s the gateway answers it with the
 * first request's answer (x-api-replayed), later it refuses it (duplicate_api_request). Where the outcome
 * can't be learned, the caller gets RequestOutcomeUnknownError instead of a second transfer.
 *
 * Every retry of a write keeps the call's x-api-nonce (and its body): a resend is the same signed request, and
 * a re-signed write gets a fresh x-api-timestamp and fresh signatures over the same nonce, so the gateway's
 * idempotency (per API key and nonce) always sees one operation. One
 * exception: the one immediate retry after address_derivation_conflict or vault_accounts_creation_failed, which
 * say that nothing was executed, is signed again with a new nonce (and the same body); with the same nonce the
 * gateway would only replay the 409. Later retries of that call keep the new nonce. A read re-signed gets a new
 * nonce. `nonce` in a retry decision says which: 'same' or 'new'.
 */

const RETRY = Object.freeze({
    maxAttempts: 5,
    baseDelayMs: 1000,
    maxDelayMs: 8000,
    deadlineMs: 30000,
    // The gateway replays the first answer to a duplicate for 3 s; resend only well inside that.
    resendWindowMs: 2500,
    // A signature is accepted for about 30 s (+10 s drift); a resend must arrive before that.
    signatureMaxAgeMs: 25000,
});

/** The conflicts the docs say to retry at once: collisions with no side effect. */
const CONFLICT_RETRY_CODES = new Set(['address_derivation_conflict', 'vault_accounts_creation_failed']);

const isServerError = status => status >= 500 && status <= 599;

/** Full jitter: a random delay up to min(cap, base × 2^(attempt − 1)), raised to a longer Retry-After. */
function backoffMs(attempt, random, retryAfterSeconds) {
    const ceiling = Math.min(RETRY.maxDelayMs, RETRY.baseDelayMs * (2 ** (attempt - 1)));
    const jitter = Math.floor(random * ceiling);
    const asked = typeof retryAfterSeconds === 'number' && retryAfterSeconds > 0 ? retryAfterSeconds * 1000 : 0;

    return Math.max(jitter, asked);
}

/**
 * @param {Object} input
 * @param {'read'|'write'} input.operation the operation's retry class (contract/overlay.json)
 * @param {'keypair'|'legacy'} input.keyMode keypair only when the key pair was confirmed active, so the
 *        gateway's replay protection is enforced; legacy otherwise
 * @param {number} input.attempt attempts made so far, this one included (1 for the first)
 * @param {number} input.elapsedMs since the call started
 * @param {number} input.signedAgeMs age of the current signature
 * @param {number} input.sinceFirstSendMs since the current signed request was first sent
 * @param {number} input.resends resends of the current signed request before this attempt
 * @param {boolean} input.mayHaveRun whether an earlier attempt of this call may have been carried out
 * @param {boolean} input.conflictRetried whether a conflict retry was made already
 * @param {number} input.random a draw in [0, 1) for the jitter
 * @param {{ type: 'not_sent'|'sent_unknown'|'verification_failed' } | { type: 'response', status: number,
 *          code: string|null, replayed: boolean, retryAfterSeconds: number|null }} input.outcome
 * @returns {{ action: 'return'|'fail' } | { action: 'retry', mode: 'resign'|'resend', nonce: 'same'|'new', delayMs: number }
 *          | { action: 'outcome_unknown', inProgress: boolean }}
 */
function decideRetry(input) {
    const { operation, keyMode, attempt, elapsedMs, signedAgeMs, sinceFirstSendMs, resends, mayHaveRun, conflictRetried, random, outcome } = input;
    const isWrite = operation === 'write';
    const isResponse = outcome.type === 'response';
    const status = isResponse ? outcome.status : null;
    const code = isResponse ? outcome.code : null;

    if (outcome.type === 'verification_failed') {
        return { action: 'fail' };
    }
    if (isResponse && status >= 200 && status <= 299) {
        return { action: 'return' };
    }

    const thisMayHaveRun = outcome.type === 'sent_unknown' || (isResponse && isServerError(status));
    const anyMayHaveRun = mayHaveRun || thisMayHaveRun;
    // What happens when no (further) retry is made
    const stop = () => {
        if (isWrite && anyMayHaveRun) {
            return { action: 'outcome_unknown', inProgress: false };
        }

        return { action: isResponse ? 'return' : 'fail' };
    };
    const retry = (mode, delayMs, nonce = isWrite ? 'same' : 'new') => {
        if (attempt >= RETRY.maxAttempts || elapsedMs + delayMs > RETRY.deadlineMs) {
            return stop();
        }

        return { action: 'retry', mode, nonce, delayMs };
    };

    if (isWrite && isResponse) {
        if (code === 'duplicate_api_request_in_progress') {
            return { action: 'outcome_unknown', inProgress: true };
        }
        if (code === 'duplicate_api_request' && resends > 0) {
            return { action: 'outcome_unknown', inProgress: false };
        }
        if (outcome.replayed && isServerError(status)) {
            return { action: 'outcome_unknown', inProgress: false };
        }
    }

    if (isResponse && CONFLICT_RETRY_CODES.has(code)) {
        // Nothing was executed, so the retry is a new operation for the gateway: a new nonce, the same body.
        return !conflictRetried && !(isWrite && mayHaveRun) ? retry('resign', 0, 'new') : { action: 'return' };
    }

    const transient = !isResponse || status === 429 || isServerError(status);
    if (!transient) {
        return { action: 'return' };
    }

    const delayMs = backoffMs(attempt, random, isResponse ? outcome.retryAfterSeconds : null);
    if (!isWrite) {
        return retry('resign', delayMs);
    }

    if (thisMayHaveRun) {
        // Sent, outcome unknown: only an immediate resend of the same request can still learn it, and only
        // where a duplicate is certainly refused.
        if (keyMode === 'keypair' && resends === 0 && sinceFirstSendMs < RETRY.resendWindowMs) {
            return retry('resend', 0);
        }

        return { action: 'outcome_unknown', inProgress: false };
    }

    // Not sent, or a 429 (refused before the route): it did not run.
    if (signedAgeMs + delayMs < RETRY.signatureMaxAgeMs) {
        return retry('resend', delayMs);
    }
    if (!mayHaveRun) {
        return retry('resign', delayMs);
    }

    return { action: 'outcome_unknown', inProgress: false };
}

module.exports = {
    RETRY,
    backoffMs,
    decideRetry,
};
