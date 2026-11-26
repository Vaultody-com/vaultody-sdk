'use strict';

/**
 * Whether to accept a response, decided before a byte of it is parsed (@vaultody-com/verify does the check).
 * test-vectors/response-mode-v1.json pins every rule here, the same in every language.
 *
 * The mode in force (readResponseSignatureConfig):
 *  - 'required' when response-signing roots are configured: the roots option is given, or this is a stable
 *    release (no -rc.N) and its build embeds the root. Such a client refuses an unsigned answer from its very first
 *    call, so a signature stripped on the way is caught from the start; a 'when-present' given explicitly is then
 *    ignored, with one warning. A release candidate that embeds the root is not strict for that alone: it bridges
 *    to signing through the latch below.
 *  - otherwise the option responseSignature, else VAULTODY_RESPONSE_SIGNATURE, else the build default
 *    (DEFAULT_RESPONSE_SIGNATURE in defaults.js: 'when-present' for release candidates, 'required' from 1.0):
 *      - 'when-present': a response with none of the four signature headers is accepted, marked signature
 *        'absent'; the first one a client accepts raises the security event { type: 'unsigned_response_accepted',
 *        origin, operationId } and then logs one warning, once per client;
 *      - 'required': every response must carry a valid signature.
 *
 * A signed response (any of the four headers) is always checked: a failure throws ResponseVerificationError and is
 * never retried, and so does a response with only some of the headers (a stripped signature).
 *
 * The latch: the first answer from an origin that carries any of the four headers turns the client strict for that
 * origin, whether it verifies or not, before anything is thrown, and is stored with the vault pins so it survives
 * restarts: { latchedAt, rootId } with the root that verified it, or rootId null when it did not (refused, or no
 * root to check it with). From then on an unsigned response is refused as `missing`. Latching an answer that did not
 * verify means an attacker who strips the signature after the gateway starts signing can't keep a client lenient:
 * the first signed answer it lets through, or only part of, is enough.
 */

const {
    verifyResponse, ResponseSignatureError, ConfigurationError: VerifyConfigurationError, RESPONSE_SIGN_HEADERS,
} = require('@vaultody-com/verify/response');
const { ResponseVerificationError, ConfigurationError } = require('./errors');
const { DEFAULT_RESPONSE_SIGNATURE } = require('./defaults');

const MODES = Object.freeze({ REQUIRED: 'required', WHEN_PRESENT: 'when-present' });

const LATCH_REREAD_SECONDS = 60;

// A stable release: X.Y.Z, without -rc.N.
const STABLE_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/;

const IGNORED_WARNING = 'responseSignature \'when-present\' is ignored: response-signing roots are configured, so every response must be signed';

/**
 * The response-signature mode in force (test-vectors/response-mode-v1.json, config).
 *
 * @param {Object} given
 * @param {string|null|undefined} given.option the responseSignature option
 * @param {Object} [given.env] VAULTODY_RESPONSE_SIGNATURE is read from it when the option is not given
 * @param {boolean} given.rootsOption whether the roots option is given
 * @param {boolean} given.embeddedRoots whether this build embeds at least one response-signing root
 * @param {string} given.version the SDK version
 * @param {string} [given.buildDefault] DEFAULT_RESPONSE_SIGNATURE
 * @returns {{ mode: 'required'|'when-present', rootsConfigured: boolean, ignored: boolean }} ignored: a
 *          'when-present' that was given and is not in force (the client warns once)
 * @throws {ConfigurationError} a value that is not a mode
 */
function readResponseSignatureConfig({ option, env = process.env, rootsOption, embeddedRoots, version, buildDefault = DEFAULT_RESPONSE_SIGNATURE }) {
    let value = option !== undefined && option !== null ? option : env.VAULTODY_RESPONSE_SIGNATURE;
    if (value === '') {
        value = undefined;
    }
    if (value !== undefined && value !== null && value !== MODES.REQUIRED && value !== MODES.WHEN_PRESENT) {
        throw new ConfigurationError('invalid_option', 'responseSignature (VAULTODY_RESPONSE_SIGNATURE) must be "required" or "when-present"');
    }
    const rootsConfigured = Boolean(rootsOption) || (Boolean(embeddedRoots) && typeof version === 'string' && STABLE_VERSION.test(version));
    if (rootsConfigured) {
        return { mode: MODES.REQUIRED, rootsConfigured, ignored: value === MODES.WHEN_PRESENT };
    }

    return { mode: value === undefined || value === null ? buildDefault : value, rootsConfigured, ignored: false };
}

/** Whether an answer carries any of the four response-signature headers (a value that is not empty). */
function carriesSignature(headers) {
    if (!headers) {
        return false;
    }
    const present = value => (Array.isArray(value) ? value.some(present) : typeof value === 'string' && value !== '');
    if (typeof headers.get === 'function' && !(headers instanceof Map)) {
        return RESPONSE_SIGN_HEADERS.some(name => present(headers.get(name)));
    }
    const entries = headers instanceof Map ? [...headers] : Object.entries(headers);

    return entries.some(([name, value]) => typeof name === 'string' && RESPONSE_SIGN_HEADERS.includes(name.toLowerCase()) && present(value));
}

class ResponseVerifier {
    /**
     * @param {{ origin: string, mode: string, roots?: *, maxClockSkewSeconds?: number, store: Object,
     *           securityEvent: function(Object): void, warn: function(string): void }} options mode: the mode in
     *        force (readResponseSignatureConfig); roots: the roots a signature is checked with (undefined: the
     *        embedded ones)
     */
    constructor({ origin, mode, roots, maxClockSkewSeconds, store, securityEvent, warn }) {
        this.origin = origin;
        this.mode = mode;
        this.roots = roots;
        this.maxClockSkewSeconds = maxClockSkewSeconds;
        this.store = store;
        this.securityEvent = securityEvent;
        this.warn = warn;
        // The latch as last read or set; it only ever goes from off to on. While off, the store is read again
        // now and then, so a latch set by another process sharing the store is seen too. It is read in every mode:
        // a strict client latches too, so a release candidate sharing its store is strict as well.
        this.latched = false;
        this.latchReadAt = null;
        this.latching = null;
        this.unsignedReported = false;
    }

    /** Whether the origin is latched now (the store is read again at most once a minute while it is not). */
    async isLatched(nowSeconds) {
        if (!this.latched && (this.latchReadAt === null || nowSeconds - this.latchReadAt >= LATCH_REREAD_SECONDS || nowSeconds < this.latchReadAt)) {
            this.latched = (await this.store.getResponseSignatureLatch(this.origin)) !== null;
            this.latchReadAt = nowSeconds;
        }

        return this.latched;
    }

    /** Whether an unsigned response is refused for this origin now. */
    async strict(nowSeconds) {
        const latched = await this.isLatched(nowSeconds);

        return this.mode === MODES.REQUIRED || latched;
    }

    /** Stores the latch for this origin once, before an answer that carries a signature is returned or refused. */
    async latch(nowSeconds, rootId) {
        if (this.latched) {
            return;
        }
        // One write for answers that arrive together, so the event is raised once.
        if (!this.latching) {
            this.latching = (async () => {
                const latch = await this.store.latchResponseSignature(this.origin, { latchedAt: nowSeconds, rootId });
                this.latched = true;
                this.securityEvent({ type: 'response_signature_latched', origin: this.origin, rootId: latch.rootId, latchedAt: latch.latchedAt });
            })().finally(() => {
                this.latching = null;
            });
        }
        await this.latching;
    }

    /**
     * @param {{ method: string, target: string, body: Buffer, apiSign: string, keypairSign: string }} sent the
     *        request exactly as sent
     * @param {{ status: number, headers: Headers, body: Buffer }} received the response as received
     * @param {{ nowSeconds: number, operationId: string }} context
     * @returns {Promise<{ signature: 'verified', rootId: string, keyId: string, timestamp: number } | { signature: 'absent' }>}
     * @throws {ResponseVerificationError}
     * @throws {ConfigurationError} a signed response and no root keys to check it with
     */
    async verify(sent, received, { nowSeconds, operationId }) {
        const strict = await this.strict(nowSeconds);
        const signed = carriesSignature(received.headers);
        let verdict;
        try {
            verdict = verifyResponse({
                request: { method: sent.method, url: sent.target, body: sent.body, apiSign: sent.apiSign, keypairSign: sent.keypairSign },
                response: { status: received.status, headers: received.headers, body: received.body },
            }, {
                requireResponseSignature: strict,
                roots: this.roots,
                now: nowSeconds,
                ...(this.maxClockSkewSeconds === undefined ? {} : { maxClockSkewSeconds: this.maxClockSkewSeconds }),
            });
        } catch (error) {
            if (error instanceof ResponseSignatureError) {
                if (signed) {
                    await this.latch(nowSeconds, null);
                }
                this.securityEvent({ type: 'response_verification_failed', origin: this.origin, operationId, status: received.status, reason: error.reason });
                throw new ResponseVerificationError(error.reason, { status: received.status, operationId, cause: error });
            }
            if (error instanceof VerifyConfigurationError) {
                // A setup error (no root keys to check a signed answer with), not a refused answer: no event, as in
                // Python and PHP. The answer is signed all the same, so the origin latches.
                if (signed) {
                    await this.latch(nowSeconds, null);
                }
                throw new ConfigurationError('no_root_keys', `${error.message} Pass the root public keys in the roots option.`, { cause: error });
            }
            throw error;
        }

        if (!verdict.verified) {
            if (!this.unsignedReported) {
                this.unsignedReported = true;
                this.securityEvent({ type: 'unsigned_response_accepted', origin: this.origin, operationId });
                this.warn(`Vaultody API responses from ${this.origin} are not signed: accepted unverified until the first signed one, `
                    + 'after which this client refuses unsigned responses from this origin (responseSignature: \'required\' refuses them now)');
            }

            return { signature: 'absent' };
        }

        await this.latch(nowSeconds, verdict.rootId);

        return { signature: 'verified', rootId: verdict.rootId, keyId: verdict.keyId, timestamp: verdict.timestamp };
    }
}

module.exports = {
    MODES,
    DEFAULT_RESPONSE_SIGNATURE,
    IGNORED_WARNING,
    readResponseSignatureConfig,
    carriesSignature,
    ResponseVerifier,
};
