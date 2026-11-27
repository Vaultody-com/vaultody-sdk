'use strict';

/**
 * The pipeline every call goes through:
 *
 *   rate limit → sign → send → verify the response → read the envelope → retry decision → back, or return
 *
 * Signing is HMAC v2 with a nonce, the passphrase and the pinned x-api-version on every request, plus the
 * key-pair signature when a signer is configured. A call gets a fresh nonce; a write keeps it on every retry
 * (re-signed with a fresh timestamp, or resent as it was), except the one retry after a conflict where nothing was
 * executed, and a read gets a new one when re-signed (retry.js). The response is verified before a byte of it is
 * parsed, error responses included (a forged 429 must not steer the retries); a failed check is never retried.
 *
 * Retries follow retry.js (test-vectors/retry-v1.json): reads are re-signed and retried after a backoff; a write
 * is never signed again with a new nonce once an attempt of it may have reached the gateway. It is resent as
 * the same signed request only where the gateway's replay protection makes that safe, and where its outcome
 * can't be learned the caller gets RequestOutcomeUnknownError instead of a second transfer.
 */

const crypto = require('node:crypto');

const { signHmacV2Request, keypairRequestMessage, API_HEADERS } = require('@vaultody-com/verify/keys');
const { decideRetry } = require('./retry');
const { classifyTransportError } = require('./transportErrors');
const {
    readEnvelope, ApiError, RequestOutcomeUnknownError, TransportError, ResponseVerificationError,
} = require('./errors');

// A response body larger than this is not read; no answer of the API comes close.
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

const isServerError = status => status >= 500 && status <= 599;

/** Reads a fetch body as bytes, up to the cap. */
async function readBody(response) {
    if (!response.body) {
        return Buffer.alloc(0);
    }
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        size += value.byteLength;
        if (size > MAX_RESPONSE_BYTES) {
            await reader.cancel().catch(() => {});
            const error = new Error(`the response is larger than ${MAX_RESPONSE_BYTES} bytes`);
            error.code = 'response_too_large';
            throw error;
        }
        chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }

    return Buffer.concat(chunks);
}

function retryAfterSeconds(headers) {
    const value = headers.get('retry-after');
    if (typeof value === 'string' && /^[0-9]{1,6}$/.test(value.trim())) {
        return Number(value.trim());
    }

    return null;
}

/** What decideRetry needs from an answer, without trusting more of it than its status and error code. */
function outcomeOf(response) {
    let code = null;
    let requestId = null;
    try {
        readEnvelope(response);
    } catch (error) {
        if (error instanceof ApiError) {
            ({ code, requestId } = error);
        }
    }
    if (!requestId) {
        try {
            const parsed = JSON.parse(response.body.toString('utf8'));
            requestId = parsed && typeof parsed.requestId === 'string' ? parsed.requestId : null;
        } catch (e) {
            requestId = null;
        }
    }

    return {
        outcome: {
            type: 'response',
            status: response.status,
            code,
            replayed: response.headers.get('x-api-replayed') === 'true',
            retryAfterSeconds: retryAfterSeconds(response.headers),
        },
        requestId,
    };
}

class Transport {
    /**
     * @param {Object} options
     * @param {URL} options.baseUrl the API root
     * @param {function(): { apiKey: string, apiSecret: string, passphrase: string }} options.credentials
     * @param {Object|null} options.signer a prepared signer (signer.js prepareSigner), or null
     * @param {string} options.apiVersion '' to send none (tests only)
     * @param {Object} options.limiter a RateLimiter
     * @param {Object} options.verifier a ResponseVerifier
     * @param {function(): Promise<'keypair'|'legacy'>} options.keyMode whether the key pair is confirmed active
     * @param {string} options.userAgent
     * @param {number} options.timeoutMs per attempt
     * @param {function(): number} options.clock milliseconds
     * @param {function(number): Promise<void>} options.sleep
     * @param {function(): number} options.random [0, 1), for the backoff jitter
     * @param {function(): string} options.nonce
     * @param {Function} options.fetch
     * @param {*} [options.dispatcher] passed to fetch (a proxy, or a custom CA)
     * @param {function(Object): void} [options.trace] sees every attempt and decision (tests)
     */
    constructor(options) {
        Object.assign(this, options);
        this.basePath = options.baseUrl.pathname.replace(/\/+$/, '');
    }

    /**
     * @param {Object} request
     * @param {string|null} [nonce] the call's nonce, when a write is re-signed; a fresh one otherwise
     */
    async sign(request, nonce = null) {
        const signedAt = this.clock();
        const timestamp = String(Math.floor(signedAt / 1000));
        if (nonce === null) {
            nonce = this.nonce();
        }
        const fields = {
            timestamp,
            method: request.method,
            path: request.signedPath,
            apiVersion: this.apiVersion,
            nonce,
            query: request.query,
            body: request.bodyText,
        };
        const headers = signHmacV2Request(this.credentials(), fields);
        if (this.signer) {
            const { apiKey, passphrase } = this.credentials();
            headers[API_HEADERS.keypairSign] = await this.signer.sign(keypairRequestMessage({ ...fields, apiKey, passphrase }));
            headers[API_HEADERS.keypairId] = this.signer.fingerprint;
        }
        headers.accept = 'application/json';
        headers['user-agent'] = this.userAgent;
        if (request.body !== null) {
            headers['content-type'] = 'application/json';
        }

        return { headers, signedAt, timestamp, nonce, apiSign: headers[API_HEADERS.sign], keypairSign: headers[API_HEADERS.keypairSign] || '' };
    }

    /** One HTTP exchange of a signed request. */
    async send(request, signed, signal) {
        const timeout = AbortSignal.timeout(this.timeoutMs);
        const init = {
            method: request.method,
            headers: signed.headers,
            body: request.body === null ? undefined : request.body,
            // A redirect is answered like any other response (and verified); it is never followed with the
            // credentials to another place.
            redirect: 'manual',
            signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
        };
        if (this.dispatcher !== undefined) {
            init.dispatcher = this.dispatcher;
        }
        const response = await this.fetch(request.url, init);
        const body = await readBody(response);

        return { status: response.status, headers: response.headers, body };
    }

    /**
     * Runs one call to the end.
     *
     * @param {Object} operation the operation table entry
     * @param {{ method: string, target: string, path: string, query: string, bodyText: string, body: Buffer|null }} built
     * @param {{ signal?: AbortSignal }} [options]
     * @returns {Promise<{ response: { status, headers, body }, verdict: Object, sent: Object }>} the answer to
     *          return (2xx, or an error status the caller turns into its typed error)
     */
    async exchange(operation, built, { signal } = {}) {
        const url = new URL(this.basePath + built.target, this.baseUrl.origin);
        // What fetch sends, and so what is signed and bound to the response: the WHATWG serialisation.
        const request = {
            ...built,
            url,
            signedPath: url.pathname,
            query: url.search === '' ? '' : url.search.slice(1),
            target: url.pathname + url.search,
        };
        const isWrite = operation.retry === 'write';
        const keyMode = isWrite ? await this.keyMode() : 'legacy';
        const startedAt = this.clock();
        let attempt = 0;
        let mayHaveRun = false;
        let conflictRetried = false;
        let signed = null;
        let firstSentAt = null;
        let resends = 0;
        let mode = 'resign';
        // Kept from the last signing on every retry of a write; null: a new one (the first, a read re-signed, or the
        // conflict retry, where nothing was executed).
        let keepNonce = null;
        let lastRequestId = null;

        for (;;) {
            attempt += 1;
            if (mode === 'resign' || signed === null) {
                signed = await this.sign(request, keepNonce);
                firstSentAt = null;
                resends = 0;
            } else {
                resends += 1;
            }
            await this.limiter.take();
            const sentAt = this.clock();
            if (firstSentAt === null) {
                firstSentAt = sentAt;
            }
            const sent = { method: request.method, target: request.target, body: request.body || Buffer.alloc(0), apiSign: signed.apiSign, keypairSign: signed.keypairSign };
            this.traceEvent({ type: 'attempt', operationId: operation.operationId, attempt, mode: resends > 0 ? 'resend' : 'sign', nonce: signed.nonce, timestamp: signed.timestamp });

            let response = null;
            let failure = null;
            let outcome;
            try {
                response = await this.send(request, signed, signal);
            } catch (error) {
                failure = error;
            }

            if (failure && failure.code === 'response_too_large') {
                // Sent, and answered with something no API answer looks like: never retried.
                outcome = { type: 'verification_failed' };
            } else if (failure) {
                if (signal && signal.aborted) {
                    throw this.stopped(isWrite && (mayHaveRun || classifyTransportError(failure).sent !== false), signed, lastRequestId, failure, 'the call was aborted');
                }
                outcome = { type: classifyTransportError(failure).sent === false ? 'not_sent' : 'sent_unknown' };
            }

            let verdict = null;
            if (response) {
                // Nothing of the answer is read before this: a failure throws, and is never retried.
                verdict = await this.verifier.verify(sent, response, { nowSeconds: Math.floor(this.clock() / 1000), operationId: operation.operationId });
                const read = outcomeOf(response);
                outcome = read.outcome;
                lastRequestId = read.requestId || lastRequestId;
            }

            const now = this.clock();
            const input = {
                operation: operation.retry,
                keyMode,
                attempt,
                elapsedMs: now - startedAt,
                signedAgeMs: now - signed.signedAt,
                sinceFirstSendMs: now - firstSentAt,
                resends,
                mayHaveRun,
                conflictRetried,
                random: this.random(),
                outcome,
            };
            const decision = decideRetry(input);
            this.traceEvent({ type: 'decision', operationId: operation.operationId, input, decision });

            if (decision.action === 'return') {
                return { response, verdict, sent };
            }
            if (decision.action === 'outcome_unknown') {
                throw new RequestOutcomeUnknownError({
                    inProgress: decision.inProgress,
                    nonce: signed.nonce,
                    timestamp: signed.timestamp,
                    requestId: lastRequestId,
                    cause: failure || undefined,
                });
            }
            if (decision.action === 'fail') {
                if (failure && failure.code === 'response_too_large') {
                    if (isWrite) {
                        throw new RequestOutcomeUnknownError({ nonce: signed.nonce, timestamp: signed.timestamp, requestId: lastRequestId, cause: failure });
                    }
                    throw new TransportError(failure.message, { sent: 'unknown', cause: failure });
                }
                if (failure) {
                    const { sent: wasSent } = classifyTransportError(failure);
                    throw new TransportError(`the request to the Vaultody API failed: ${failure.message}`, { sent: wasSent, cause: failure });
                }
                throw new ResponseVerificationError('invalid', { operationId: operation.operationId });
            }

            // retry
            mayHaveRun = mayHaveRun || outcome.type === 'sent_unknown' || (outcome.type === 'response' && isServerError(outcome.status));
            if (outcome.type === 'response' && (outcome.code === 'address_derivation_conflict' || outcome.code === 'vault_accounts_creation_failed')) {
                conflictRetried = true;
            }
            mode = decision.mode;
            keepNonce = decision.nonce === 'same' ? signed.nonce : null;
            if (decision.delayMs > 0) {
                await this.sleep(decision.delayMs);
            }
        }
    }

    stopped(mayHaveRun, signed, requestId, cause, message) {
        if (mayHaveRun) {
            return new RequestOutcomeUnknownError({ nonce: signed.nonce, timestamp: signed.timestamp, requestId, cause });
        }

        return new TransportError(message, { sent: classifyTransportError(cause).sent, cause });
    }

    traceEvent(event) {
        if (this.trace) {
            this.trace(event);
        }
    }
}

/** 16 random bytes as hex: the nonce of one signed request. */
const randomNonce = () => crypto.randomBytes(16).toString('hex');

module.exports = {
    MAX_RESPONSE_BYTES,
    Transport,
    randomNonce,
    outcomeOf,
};
