'use strict';

/**
 * The Vaultody client: credentials, the transport, response verification, vault xpub pins and address
 * checks, retries, the rate limiter, paging and webhooks, and the API methods: one namespace per group of the
 * API reference (vaults, vaultAccounts, assetsAddresses, transactions, apiKeys), one method per documented
 * operation (api/).
 */

const util = require('node:util');

const { decodeApiSecret, isApiVersion } = require('@vaultody-com/verify/keys');
const { embeddedFingerprints, parseRoots } = require('@vaultody-com/verify/response');
const { API_VERSION, SDK_VERSION } = require('./version');
const { operationById } = require('./operations');
const { buildRequest } = require('./requestBuilder');
const { Transport, randomNonce } = require('./transport');
const { RateLimiter } = require('./rateLimiter');
const { ResponseVerifier, readResponseSignatureConfig, MODES, IGNORED_WARNING } = require('./responseVerification');
const { ADDRESS_PATHS_PUBLIC } = require('./defaults');
const { AddressGuard, ADDRESS_OPERATIONS, InvalidVaultList } = require('./addressGuard');
const { MemoryVaultKeyStore, FileVaultKeyStore, defaultVaultKeysFile } = require('./vaultKeyStore');
const { readConfiguredPins } = require('./vaultKeys');
const { prepareSigner } = require('./signer');
const { Page, Pager, pagingOf } = require('./page');
const { paginate } = require('./pagination');
const { verifyWebhook } = require('./webhooks');
const { validateParams } = require('./params');
const { NAMESPACES } = require('./api');
const { securityEvent } = require('./securityEvents');
const { pageRequest } = require('./api/common');
const {
    readEnvelope, ApiError, ConfigurationError, ParameterError, AuthenticationError, PermissionDeniedError, TransportError,
} = require('./errors');

const DEFAULT_BASE_URL = 'https://rest.vaultody.com';
// Plain HTTP only to this machine (a port-forward to a test environment): requests carry the passphrase.
const LOOPBACK_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])$/;
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;
// The key pair's confirmation is asked again after this long; a failed one sooner.
const KEY_CONFIRMATION_MS = 10 * 60 * 1000;
const KEY_CONFIRMATION_RETRY_MS = 60 * 1000;
const NONCE = /^[\x21-\x7e]{1,128}$/;

const OPTIONS = new Set([
    'apiKey', 'apiSecret', 'passphrase', 'baseUrl', 'signer', 'verifySignerLocally', 'responseSignature', 'roots',
    'maxClockSkewSeconds', 'vaultKeyStore', 'vaultKeysFile', 'pinnedVaultKeys', 'requireAddressPaths', 'maxRequestsPerSecond', 'timeoutMs',
    'onSecurityEvent', 'logger', 'webhookSecrets', 'dispatcher', 'unsupported',
]);
// For tests and conformance runs only; not a supported API and may change without notice. embeddedRoots: roots that
// act as this build's embedded ones (in the form the roots option takes); sdkVersion: the version the client takes
// itself for (whether it is a stable release).
const UNSUPPORTED = new Set(['apiVersion', 'nonce', 'clock', 'sleep', 'random', 'fetch', 'trace', 'embeddedRoots', 'sdkVersion']);
const CALL_OPTIONS = new Set(['context', 'signal']);
const PAGING_OPTIONS = new Set(['context', 'signal', 'limit', 'maxItems']);
const STORE_METHODS = ['get', 'list', 'pinIfAbsent', 'upgradeTrust', 'getResponseSignatureLatch', 'latchResponseSignature'];

const isObject = value => value !== null && typeof value === 'object';
const configError = (code, message) => new ConfigurationError(code, message);
const defaultSleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function requireText(value, name, pattern = PRINTABLE_ASCII) {
    if (typeof value !== 'string' || value === '' || !pattern.test(value)) {
        throw configError('invalid_credentials', `${name} must be the non-empty printable text the dashboard shows`);
    }

    return value;
}

function readBaseUrl(value) {
    let url;
    try {
        url = new URL(value === undefined ? DEFAULT_BASE_URL : value);
    } catch (e) {
        throw configError('invalid_base_url', 'baseUrl must be an absolute URL such as https://rest.vaultody.com');
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK_HOST.test(url.hostname))) {
        throw configError('invalid_base_url', 'baseUrl must be https; plain http is allowed only to this machine (localhost)');
    }
    if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
        throw configError('invalid_base_url', 'baseUrl must not hold a user name, password, query or fragment');
    }

    return url;
}

const METHODS = new Set(['GET', 'POST', 'PUT']);
const PARAM_IN = new Set(['path', 'query', 'body']);

/**
 * An operationId of the table, or an operation entry of the same shape (the API methods pass the table's own
 * entries; tests pass their own).
 */
function resolveOperation(operation) {
    if (typeof operation === 'string') {
        const entry = operationById(operation);
        if (!entry) {
            throw new ParameterError('unknown_operation', `no operation ${operation} in the operation table`);
        }

        return entry;
    }
    if (!isObject(operation) || typeof operation.operationId !== 'string' || !METHODS.has(operation.method)
        || typeof operation.path !== 'string' || !operation.path.startsWith('/') || !Array.isArray(operation.params)
        || !operation.params.every(param => isObject(param) && typeof param.name === 'string' && PARAM_IN.has(param.in))
        || (operation.retry !== 'read' && operation.retry !== 'write')) {
        throw new ParameterError('unknown_operation', 'operation must be an operationId or an operation table entry');
    }
    const known = operationById(operation.operationId);
    if (known && known !== operation) {
        // A changed copy of a documented operation would skip its checks (pins, addresses): refused.
        throw new ParameterError('unknown_operation', `${operation.operationId} is in the operation table: pass its id`);
    }

    return { paging: null, ...operation };
}

function readKnown(object, allowed, what) {
    for (const key of Object.keys(object)) {
        if (!allowed.has(key)) {
            throw (what === 'option' ? configError('unknown_option', `unknown option ${key}`) : new ParameterError('unknown_option', `unknown ${what} ${key}`));
        }
    }
}

/** Set by the class's static block; see src/internal.js. */
let lowLevelCalls;

class Vaultody {
    #apiKey;
    #apiSecret;
    #passphrase;
    #origin;
    #mode;
    #rootsConfigured;
    #verifier;
    #signedReadDone = false;
    #signedReadRunning = null;
    #signer;
    #store;
    #transport;
    #guard;
    #clock;
    #webhookSecrets;
    #securityEvent;
    #keyMode = null;
    #keyModeRunning = null;

    /**
     * @param {Object} options
     * @param {string} options.apiKey
     * @param {string} options.apiSecret the base64 text the dashboard shows
     * @param {string} options.passphrase
     * @param {string} [options.baseUrl='https://rest.vaultody.com'] https; http only to localhost
     * @param {Object} [options.signer] a request-signing key pair (signer.js): fileSigner, pemSigner, a KMS
     *        adapter, or any { algorithm, publicKeyPem, sign }
     * @param {boolean} [options.verifySignerLocally=true] check each key-pair signature before sending
     * @param {'when-present'|'required'} [options.responseSignature] VAULTODY_RESPONSE_SIGNATURE, else the build
     *        default ('when-present' for release candidates: strict after the first signed response). Ignored, with one
     *        warning, when response-signing roots are configured: such a client is always 'required'
     *        (responseVerification.js)
     * @param {*} [options.roots] response-signing root keys to trust instead of the embedded ones (test environments).
     *        Given, they make the client strict: every response must be signed, from the first one
     * @param {number} [options.maxClockSkewSeconds]
     * @param {Object} [options.vaultKeyStore] a custom pin store (vaultKeyStore.js); default a file
     * @param {string} [options.vaultKeysFile] the pin file (default VAULTODY_VAULT_KEYS_FILE, else
     *        ~/.vaultody/vault-keys.json); an explicit file must be writable
     * @param {Array<{ vaultId: string, type: 'main'|'test', keys: { ECDSA: string|null, EDDSA: string|null } }>}
     *        [options.pinnedVaultKeys] vault xpubs you confirmed yourself, for this client's API origin. Each counts
     *        as verified, is checked against every vault list like any pin (a difference is the alarm), is never
     *        written to the store, and takes the place of the stored pin of its vault
     * @param {boolean} [options.requireAddressPaths] refuse (path_missing) an address generateDepositAddress answers
     *        without its derivation path for a vault with MPC keys, on a chain the SDK can derive. Default: on once the
     *        API returns the paths (ADDRESS_PATHS_PUBLIC in defaults.js), off before
     * @param {number} [options.maxRequestsPerSecond=5]
     * @param {number} [options.timeoutMs=30000] per attempt
     * @param {function(Object): void} [options.onSecurityEvent] pins, the latch, refused responses and
     *        addresses, the alarm; never carries a secret or an xpub
     * @param {{ warn: function(string): void }} [options.logger] default process.emitWarning
     * @param {string|string[]} [options.webhookSecrets] for webhooks.verify
     * @param {*} [options.dispatcher] passed to fetch: a proxy, or a custom CA (TLS checks can't be switched off)
     */
    constructor(options = {}) {
        if (!isObject(options)) {
            throw configError('invalid_option', 'options must be an object');
        }
        readKnown(options, OPTIONS, 'option');
        const unsupported = options.unsupported === undefined ? {} : options.unsupported;
        if (!isObject(unsupported)) {
            throw configError('invalid_option', 'unsupported must be an object');
        }
        readKnown(unsupported, UNSUPPORTED, 'option');

        this.#apiKey = requireText(options.apiKey, 'apiKey');
        this.#passphrase = requireText(options.passphrase, 'passphrase');
        try {
            decodeApiSecret(options.apiSecret);
        } catch (e) {
            throw configError('invalid_api_secret', 'apiSecret must be the base64 text the dashboard shows');
        }
        this.#apiSecret = options.apiSecret;

        const baseUrl = readBaseUrl(options.baseUrl);
        this.#origin = baseUrl.origin;
        const verifyRoots = options.roots !== undefined && options.roots !== null ? options.roots : unsupported.embeddedRoots;
        let embeddedRoots = embeddedFingerprints().length > 0;
        if (unsupported.embeddedRoots !== undefined) {
            try {
                embeddedRoots = (parseRoots(unsupported.embeddedRoots) || []).length > 0;
            } catch (e) {
                throw configError('invalid_option', `unsupported.embeddedRoots: ${e.message}`);
            }
        }
        const sdkVersion = unsupported.sdkVersion === undefined ? SDK_VERSION : unsupported.sdkVersion;
        if (typeof sdkVersion !== 'string') {
            throw configError('invalid_option', 'unsupported.sdkVersion must be a version string');
        }
        const signatureConfig = readResponseSignatureConfig({
            option: options.responseSignature,
            rootsOption: options.roots !== undefined && options.roots !== null,
            embeddedRoots,
            version: sdkVersion,
        });
        this.#mode = signatureConfig.mode;
        this.#rootsConfigured = signatureConfig.rootsConfigured;
        const requireAddressPaths = options.requireAddressPaths === undefined ? ADDRESS_PATHS_PUBLIC : options.requireAddressPaths;
        if (typeof requireAddressPaths !== 'boolean') {
            throw configError('invalid_option', 'requireAddressPaths must be true or false');
        }

        const logger = options.logger === undefined ? { warn: message => process.emitWarning(message, 'VaultodyWarning') } : options.logger;
        if (!isObject(logger) || typeof logger.warn !== 'function') {
            throw configError('invalid_option', 'logger must be { warn(message) }');
        }
        const warn = message => {
            try {
                logger.warn(message);
            } catch (e) {
                // a logger must not break a call
            }
        };
        if (signatureConfig.ignored) {
            warn(IGNORED_WARNING);
        }
        const onSecurityEvent = options.onSecurityEvent;
        if (onSecurityEvent !== undefined && typeof onSecurityEvent !== 'function') {
            throw configError('invalid_option', 'onSecurityEvent must be a function');
        }
        this.#securityEvent = event => {
            // Exactly the catalogued fields (securityEvents.js), as in Python and PHP. With no hook, every event is
            // logged once as a warning, its JSON as given to a hook (it never holds a secret, an xpub or an address).
            const frozen = securityEvent(event);
            if (onSecurityEvent) {
                try {
                    onSecurityEvent(frozen);
                } catch (e) {
                    warn(`the security event hook raised on ${event.type}; the call still fails or continues as it would`);
                }
            } else {
                warn(`Vaultody security event: ${JSON.stringify(frozen)}`);
            }
        };

        const clock = unsupported.clock === undefined ? Date.now : unsupported.clock;
        const sleep = unsupported.sleep === undefined ? defaultSleep : unsupported.sleep;
        const random = unsupported.random === undefined ? Math.random : unsupported.random;
        const nonce = unsupported.nonce === undefined ? randomNonce : unsupported.nonce;
        const fetchImpl = unsupported.fetch === undefined ? globalThis.fetch : unsupported.fetch;
        for (const [name, fn] of [['clock', clock], ['sleep', sleep], ['random', random], ['nonce', nonce], ['fetch', fetchImpl]]) {
            if (typeof fn !== 'function') {
                throw configError('invalid_option', `unsupported.${name} must be a function`);
            }
        }
        if (unsupported.trace !== undefined && typeof unsupported.trace !== 'function') {
            throw configError('invalid_option', 'unsupported.trace must be a function');
        }
        const apiVersion = unsupported.apiVersion === undefined ? API_VERSION : unsupported.apiVersion;
        if (apiVersion !== '' && !isApiVersion(apiVersion)) {
            throw configError('invalid_option', 'unsupported.apiVersion must be YYYY-MM-DD, or empty to send none');
        }
        this.#clock = clock;

        const verifyLocally = options.verifySignerLocally === undefined ? true : options.verifySignerLocally;
        if (typeof verifyLocally !== 'boolean') {
            throw configError('invalid_option', 'verifySignerLocally must be true or false');
        }
        this.#signer = options.signer === undefined || options.signer === null ? null : prepareSigner(options.signer, { verifyLocally });

        this.#store = this.#readStore(options, warn);
        let configuredPins = new Map();
        if (options.pinnedVaultKeys !== undefined) {
            try {
                configuredPins = readConfiguredPins(options.pinnedVaultKeys);
            } catch (e) {
                throw configError('invalid_option', `pinnedVaultKeys: ${e.message}`);
            }
        }

        const perSecond = options.maxRequestsPerSecond === undefined ? 5 : options.maxRequestsPerSecond;
        if (typeof perSecond !== 'number' || !Number.isFinite(perSecond) || perSecond <= 0) {
            throw configError('invalid_option', 'maxRequestsPerSecond must be a positive number');
        }
        const timeoutMs = options.timeoutMs === undefined ? 30000 : options.timeoutMs;
        if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
            throw configError('invalid_option', 'timeoutMs must be a positive number of milliseconds');
        }
        if (options.webhookSecrets !== undefined) {
            const list = Array.isArray(options.webhookSecrets) ? options.webhookSecrets : [options.webhookSecrets];
            if (list.length === 0 || !list.every(secret => typeof secret === 'string' && secret !== '')) {
                throw configError('invalid_option', 'webhookSecrets must be a non-empty string or array of them');
            }
            this.#webhookSecrets = [...list];
        }

        const verifier = new ResponseVerifier({
            origin: this.#origin,
            mode: this.#mode,
            roots: verifyRoots,
            maxClockSkewSeconds: options.maxClockSkewSeconds,
            store: this.#store,
            securityEvent: this.#securityEvent,
            warn,
        });
        this.#verifier = verifier;
        this.#transport = new Transport({
            baseUrl,
            credentials: () => ({ apiKey: this.#apiKey, apiSecret: this.#apiSecret, passphrase: this.#passphrase }),
            signer: this.#signer,
            apiVersion,
            limiter: new RateLimiter({ perSecond, clock, sleep }),
            verifier,
            keyMode: () => this.#currentKeyMode(),
            userAgent: `vaultody-sdk-node/${SDK_VERSION} (node/${process.versions.node}; ${process.platform})`,
            timeoutMs,
            clock,
            sleep,
            random,
            nonce: () => {
                const value = nonce();
                if (typeof value !== 'string' || !NONCE.test(value)) {
                    throw configError('invalid_option', 'unsupported.nonce must return 1 to 128 printable characters');
                }

                return value;
            },
            fetch: fetchImpl,
            dispatcher: options.dispatcher,
            trace: unsupported.trace,
        });
        this.#guard = new AddressGuard({
            origin: this.#origin,
            store: this.#store,
            configured: configuredPins,
            securityEvent: this.#securityEvent,
            clock,
            requireAddressPaths,
            listVaultPages: type => this.#paginate('listVaults', { networkType: type }),
        });

        // The API methods, one namespace per group of the API reference.
        const invoke = (operationId, params, options) => this.#invoke(operationId, params, options);
        for (const [namespace, Group] of Object.entries(NAMESPACES)) {
            this[namespace] = Object.freeze(new Group(invoke));
        }

        this.webhooks = Object.freeze({
            /**
             * Verifies a webhook delivery and reads its event (webhooks.js).
             *
             * @param {Buffer|Uint8Array|ArrayBuffer|string} rawBody
             * @param {Object|Headers|Map} headers
             * @param {string|string[]} [secrets] the client's webhookSecrets when not given
             */
            verify: (rawBody, headers, secrets) => {
                const use = secrets === undefined ? this.#webhookSecrets : secrets;
                if (use === undefined) {
                    throw configError('invalid_webhook_secret', 'pass the webhook signing secret, or set webhookSecrets on the client');
                }

                return verifyWebhook(rawBody, headers, use);
            },
        });
    }

    #readStore(options, warn) {
        if (options.vaultKeyStore !== undefined) {
            if (options.vaultKeysFile !== undefined) {
                throw configError('invalid_option', 'give vaultKeyStore or vaultKeysFile, not both');
            }
            const store = options.vaultKeyStore;
            if (!isObject(store) || !STORE_METHODS.every(method => typeof store[method] === 'function')) {
                throw configError('invalid_option', `vaultKeyStore must have the methods ${STORE_METHODS.join(', ')}`);
            }

            return store;
        }
        if (options.vaultKeysFile !== undefined) {
            if (typeof options.vaultKeysFile !== 'string' || options.vaultKeysFile === '') {
                throw configError('invalid_option', 'vaultKeysFile must be a path');
            }

            return new FileVaultKeyStore({ file: options.vaultKeysFile });
        }
        const file = defaultVaultKeysFile();
        if (file === null) {
            warn('No home directory for the vault key pins (~/.vaultody/vault-keys.json): they are kept in memory and last only as long '
                + 'as this process. Set VAULTODY_VAULT_KEYS_FILE, or pass vaultKeysFile or vaultKeyStore.');

            return new MemoryVaultKeyStore();
        }

        return new FileVaultKeyStore({
            file,
            fallbackToMemory: true,
            onFallback: error => warn(`The vault key pins can't be written to ${file} (${error.code}): they are kept in memory from now on and last `
                + 'only as long as this process. Set VAULTODY_VAULT_KEYS_FILE, or pass vaultKeysFile or vaultKeyStore.'),
        });
    }

    /** The API origin this client talks to; pins and the response-signature latch are kept per origin. */
    get origin() {
        return this.#origin;
    }

    /**
     * The response-signature mode in force: 'when-present' or 'required'. 'required' whenever response-signing roots
     * are configured, whatever the option said.
     */
    get responseSignature() {
        return this.#mode;
    }

    /** The fingerprint of the request-signing key pair, or null. */
    get signerFingerprint() {
        return this.#signer ? this.#signer.fingerprint : null;
    }

    /**
     * What every API method runs: its params checked against the API reference, then #request(). A list returns
     * its first page as a promise that can also be iterated over every item.
     */
    #invoke(operationId, params = {}, options = {}) {
        const operation = operationById(operationId);
        let firstAnswer;
        try {
            validateParams(operation, params);
            firstAnswer = this.#request(operation, params, options);
        } catch (error) {
            firstAnswer = Promise.reject(error);
        }

        return operation.paging ? pageRequest(firstAnswer) : firstAnswer;
    }

    /**
     * Calls one operation: the low-level call the API methods are built on, after their check. Internal: it takes
     * any operationId and does not check params against the API reference (it refuses only a param the operation
     * does not have, and path and query values it can't send), so the client does not expose it. The SDK's own
     * tests reach it through src/internal.js.
     *
     * @param {string|Object} operationId as in the operation table (the documented operationId), or an operation
     *        entry of the same shape for an operation the table does not have
     * @param {Object} [params] path, query and body fields in one flat object
     * @param {{ context?: string, signal?: AbortSignal }} [options]
     * @returns {Promise<{ item: Object, meta: Object }|Page>} meta: operationId, requestId, apiVersion,
     *          context, replayed, signature ('verified' | 'absent'), rootId, addressChecks, vaultKeys
     * @throws {ApiError} and its subclasses, for an error answer
     * @throws {ResponseVerificationError|AddressVerificationError|VaultKeyChangedError} never retried
     * @throws {RequestOutcomeUnknownError} a write that may or may not have run
     * @throws {TransportError|ParameterError|ConfigurationError|VaultKeyStoreError}
     */
    async #request(operationId, params = {}, options = {}) {
        const operation = resolveOperation(operationId);
        if (!isObject(options)) {
            throw new ParameterError('invalid_options', 'options must be an object');
        }
        readKnown(options, CALL_OPTIONS, 'call option');

        const built = buildRequest(operation, params, { context: options.context });
        if (operation.retry === 'write') {
            await this.#signedReadBeforeWrite();
        }
        const { response, verdict } = await this.#transport.exchange(operation, built, { signal: options.signal });
        let envelope;
        try {
            envelope = readEnvelope(response);
        } catch (error) {
            // Whether the error answer itself was verified (it always passed the check to get here).
            if (error instanceof ApiError) {
                error.signature = verdict.signature;
            }
            throw error;
        }
        const meta = {
            operationId: operation.operationId,
            requestId: envelope.requestId,
            apiVersion: envelope.apiVersion,
            context: envelope.context,
            replayed: envelope.replayed,
            signature: verdict.signature,
        };
        if (verdict.signature === 'verified') {
            meta.rootId = verdict.rootId;
            meta.signedAt = verdict.timestamp;
        }

        if (operation.operationId === 'listVaults') {
            // A vault list that can't be read, or that lists a vault under the other type, is refused as an
            // answer of the API that is wrong (ApiError, as in Python and PHP).
            const refuse = message => new ApiError({ status: response.status, code: null, message, requestId: envelope.requestId, apiVersion: envelope.apiVersion, replayed: envelope.replayed });
            if (envelope.kind !== 'page') {
                throw refuse('the answer of listVaults is not a list');
            }
            try {
                meta.vaultKeys = await this.#guard.observeVaultList(params.networkType, envelope.items, verdict);
            } catch (error) {
                throw error instanceof InvalidVaultList ? refuse(error.message) : error;
            }
        }
        if (ADDRESS_OPERATIONS[operation.operationId]) {
            meta.addressChecks = await this.#guard.check(operation.operationId, params, envelope, verdict);
        }

        if (envelope.kind === 'page') {
            return new Page({ operation, params, envelope, meta, request: next => this.#request(operationId, next, options) });
        }

        return { item: envelope.item, meta };
    }

    /**
     * Every item of a list operation, page by page; each page is an ordinary #request(). Internal, as #request()
     * is: the client pins vault keys with it (listVaults), and the SDK's own tests reach it through
     * src/internal.js. After the loop, the pager's `stop` says why it ended: 'end', 'empty_page' or 'max_items'.
     *
     * @param {string} operationId
     * @param {Object} [params] startingAfter in them starts mid-list
     * @param {{ limit?: number, maxItems?: number, context?: string, signal?: AbortSignal }} [options] limit:
     *        the page size (the operation's maximum by default)
     * @returns {Pager}
     */
    #paginate(operationId, params = {}, options = {}) {
        const operation = resolveOperation(operationId);
        readKnown(options, PAGING_OPTIONS, 'paging option');
        const { limit, maxItems, ...callOptions } = options;
        const pages = pagingOf(operation, params, next => this.#request(operationId, next, callOptions), { limit, maxItems });

        return new Pager(paginate(pages.options, pages.fetchPage));
    }

    /**
     * Asks the API which signing keys this API key holds (listApiKeySigningKeys) and whether the signer's key
     * is among them and active. Writes are resent as the same signed request after a lost answer only when this
     * came back active in a signed (verified) answer: only then is the gateway's replay protection certain to
     * refuse a second run. It is asked before the first write and again every 10 minutes.
     *
     * @returns {Promise<{ fingerprint: string|null, outcome: 'active'|'inactive'|'not_listed'|'refused'|'no_signer',
     *          signature: 'verified'|'absent'|null, keyMode: 'keypair'|'legacy', code?: string }>}
     */
    async confirmSigningKey() {
        if (!this.#signer) {
            return { fingerprint: null, outcome: 'no_signer', signature: null, keyMode: 'legacy' };
        }
        const { fingerprint } = this.#signer;
        let result;
        try {
            const page = await this.#request('listApiKeySigningKeys');
            const listed = page.items.find(item => isObject(item) && item.fingerprint === fingerprint);
            const outcome = listed ? (listed.status === 'active' ? 'active' : 'inactive') : 'not_listed';
            result = { fingerprint, outcome, signature: page.meta.signature, keyMode: outcome === 'active' && page.meta.signature === 'verified' ? 'keypair' : 'legacy' };
        } catch (error) {
            if (!(error instanceof AuthenticationError || error instanceof PermissionDeniedError)) {
                throw error;
            }
            result = { fingerprint, outcome: 'refused', code: error.code, signature: error.signature || null, keyMode: 'legacy' };
        }
        this.#keyMode = { mode: result.keyMode, at: this.#clock(), ttl: KEY_CONFIRMATION_MS };

        return result;
    }

    /**
     * Before the first write, a client with response-signing roots makes one signed read unless its origin is latched
     * already (listApiKeySigningKeys; with a signer, the key-pair check is that read). Against an origin that does not
     * sign, or a signature stripped from the start, the read is refused and the write is never sent, instead of
     * running and coming back as an answer that can't be trusted. Any answer that passes its check settles it for this
     * client; a network failure leaves it open, and the write goes ahead with its own answer checked as always.
     */
    async #signedReadBeforeWrite() {
        if (!this.#rootsConfigured || this.#signedReadDone) {
            return;
        }
        if (await this.#verifier.isLatched(Math.floor(this.#clock() / 1000))) {
            this.#signedReadDone = true;

            return;
        }
        if (!this.#signedReadRunning) {
            this.#signedReadRunning = (async () => {
                try {
                    if (this.#signer) {
                        await this.confirmSigningKey();
                    } else {
                        await this.#request('listApiKeySigningKeys');
                    }
                    this.#signedReadDone = true;
                } catch (error) {
                    if (error instanceof ApiError) {
                        // An error answer that passed its signature check: the origin signs.
                        this.#signedReadDone = true;
                    } else if (!(error instanceof TransportError)) {
                        throw error;
                    }
                }
            })().finally(() => {
                this.#signedReadRunning = null;
            });
        }
        await this.#signedReadRunning;
    }

    async #currentKeyMode() {
        if (!this.#signer) {
            return 'legacy';
        }
        if (this.#keyMode && this.#clock() - this.#keyMode.at < this.#keyMode.ttl) {
            return this.#keyMode.mode;
        }
        if (!this.#keyModeRunning) {
            this.#keyModeRunning = this.confirmSigningKey().then(result => result.keyMode, () => {
                // Not confirmed: the write goes ahead as for a legacy key, so a lost answer is never resent.
                this.#keyMode = { mode: 'legacy', at: this.#clock(), ttl: KEY_CONFIRMATION_RETRY_MS };

                return 'legacy';
            }).finally(() => {
                this.#keyModeRunning = null;
            });
        }

        return this.#keyModeRunning;
    }

    [util.inspect.custom]() {
        return `Vaultody { origin: '${this.#origin}', responseSignature: '${this.#mode}', signer: ${this.#signer ? `'${this.#signer.fingerprint}'` : 'none'}, credentials: [redacted] }`;
    }

    toJSON() {
        return { origin: this.#origin, responseSignature: this.#mode, signer: this.signerFingerprint };
    }

    static {
        // The low-level calls, handed only to src/internal.js (the SDK's own tests and conformance runs).
        lowLevelCalls = client => {
            if (!(client instanceof Vaultody)) {
                throw new TypeError('not a Vaultody client');
            }

            return {
                request: (operationId, params, options) => client.#request(operationId, params, options),
                paginate: (operationId, params, options) => client.#paginate(operationId, params, options),
            };
        };
    }
}

module.exports = {
    Vaultody,
    DEFAULT_BASE_URL,
    MODES,
    // Internal (src/internal.js), not exported by the package.
    lowLevelCalls: client => lowLevelCalls(client),
};
