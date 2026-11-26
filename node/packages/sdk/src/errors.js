'use strict';

/**
 * The errors the SDK raises, the same names in every language, and the reading of a response envelope
 * into a result or a typed error (test-vectors/envelope-errors-v1.json).
 *
 * Callers branch on the class and on `code`, never on `message`.
 */

class VaultodyError extends Error {
    constructor(message) {
        super(message);
        this.name = new.target.name;
    }
}

/**
 * An answer the SDK can't return as a result: an error status, or a success it can't read.
 */
class ApiError extends VaultodyError {
    /**
     * @param {{ status: number, code: string|null, message: string|null, details?: *, requestId: string|null,
     *           apiVersion: string|null, replayed: boolean }} fields
     */
    constructor({ status, code, message, details, requestId, apiVersion, replayed }) {
        // The API's own message when it gave one, as written for people; never branch on it.
        super(message || `Vaultody API answered ${status}${code ? ` ${code}` : ''}`);
        this.status = status;
        this.code = code;
        if (details !== undefined) {
            this.details = details;
        }
        this.requestId = requestId;
        this.apiVersion = apiVersion;
        this.replayed = replayed;
        // Only the two conflicts the docs say to retry at once: a collision with no side effect.
        this.retryable = code === 'address_derivation_conflict' || code === 'vault_accounts_creation_failed';
    }
}

class AuthenticationError extends ApiError {}
class RequestSigningError extends ApiError {}
class PermissionDeniedError extends ApiError {}
class NotFoundError extends ApiError {}
class InvalidRequestError extends ApiError {}
class ConflictError extends ApiError {}
class DuplicateTransferError extends ApiError {}
class RateLimitError extends ApiError {}
class ServerError extends ApiError {}

/**
 * A write may or may not have been carried out: it was sent, and its outcome could not be learned (see
 * retry.js). Check with getTransactionRequestDetails or the dashboard before sending it again.
 */
class RequestOutcomeUnknownError extends VaultodyError {
    constructor({ inProgress = false, nonce = null, timestamp = null, requestId = null, cause } = {}) {
        super(inProgress
            ? 'the request was received and is still being processed; its outcome is not known yet'
            : 'the request may or may not have been carried out; its outcome is not known');
        this.inProgress = inProgress;
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.requestId = requestId;
        if (cause !== undefined) {
            this.cause = cause;
        }
    }
}

/** A network failure. `sent` is false only when the request certainly never left (transportErrors.js). */
class TransportError extends VaultodyError {
    constructor(message, { sent, cause } = {}) {
        super(message);
        this.sent = sent;
        if (cause !== undefined) {
            this.cause = cause;
        }
    }
}

/**
 * Arguments of a call that can't be turned into a request. `code` says why; `param`, when set, names the
 * field (nested ones as `recipients[0].amount`).
 */
class ParameterError extends VaultodyError {
    constructor(code, message, { param } = {}) {
        super(message);
        this.code = code;
        if (param !== undefined) {
            this.param = param;
        }
    }
}

/** A list that can't be paged through safely. `code` says why. */
class PaginationError extends VaultodyError {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}

/**
 * A vault's xpub differs from the one pinned, or a pinned one is gone. Each alarm names the vault, the
 * algorithm and short hashes of both xpubs, never an xpub itself.
 */
class VaultKeyChangedError extends VaultodyError {
    constructor(alarms) {
        super(`the xpub of ${alarms.map(alarm => `vault ${alarm.vaultId} (${alarm.algorithm})`).join(', ')} differs from the one pinned; nothing in the response was used`);
        this.alarms = alarms;
    }
}

/**
 * An address that does not derive from its vault's pinned xpub, or that can't be checked although it carries
 * its derivation path. `code`: mismatch (the address, or the chain an item names, is not the one asked for or
 * derived), network_mismatch (the network an item names is not the one asked for, or does not go with the
 * vault type), invalid (an item without an address, unreadable path fields), unsupported, unknown_vault, or
 * another reason of the derivation. The whole response is refused: no part of it
 * reaches the caller. (A vault list that can't be read is an ApiError.)
 */
class AddressVerificationError extends VaultodyError {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}

/**
 * A response that failed its signature check, or that came without one where one is required. `reason` is
 * @vaultody/verify's: missing, invalid, expired, unknown_root, request_unbound, unsupported_version. Never
 * retried, and nothing in the response was used. For a write, the request may still have been carried out.
 */
class ResponseVerificationError extends VaultodyError {
    constructor(reason, { status = null, operationId = null, cause } = {}) {
        super(`the response failed its signature check (${reason}); nothing in it was used`);
        this.reason = reason;
        this.status = status;
        this.operationId = operationId;
        if (cause !== undefined) {
            this.cause = cause;
        }
    }
}

/** The client is set up wrongly: credentials, base URL, signer, root keys, the pin store. `code` says why. */
class ConfigurationError extends VaultodyError {
    constructor(code, message, { cause } = {}) {
        super(message);
        this.code = code;
        if (cause !== undefined) {
            this.cause = cause;
        }
    }
}

/** A webhook delivery whose X-Signature does not check out. `reason`: missing, malformed or mismatch. */
class WebhookSignatureError extends VaultodyError {
    constructor(reason, message) {
        super(message);
        this.reason = reason;
    }
}

/** A webhook delivery that verified but is not a JSON object with data.event. */
class WebhookPayloadError extends VaultodyError {}

/**
 * The vault xpub pin store could not be read or written; it is never treated as empty. `code`, the same in every
 * language: not_json, unknown_format, malformed, insecure_permissions, not_regular_file, too_large (the file);
 * unreadable, unwritable, locked, invalid_pin, store_conflict (a pin changed in the store while the client wrote
 * it; call again).
 */
class VaultKeyStoreError extends VaultodyError {
    constructor(code, message, { cause } = {}) {
        super(message);
        this.code = code;
        if (cause !== undefined) {
            this.cause = cause;
        }
    }
}

/** Error class by code, which comes before the class of the status. */
const CLASS_OF_CODE = Object.freeze({
    api_keypair_required: RequestSigningError,
    missing_api_keypair_sign: RequestSigningError,
    missing_api_nonce: RequestSigningError,
    // The gateway's idempotency: the nonce was used before for a different request; never retried.
    api_nonce_reused: RequestSigningError,
    unknown_api_keypair_id: RequestSigningError,
    invalid_api_keypair_sign: RequestSigningError,
    invalid_api_key: AuthenticationError,
    invalid_api_sign: AuthenticationError,
    invalid_api_timestamp: AuthenticationError,
    missing_authorization_header: AuthenticationError,
    invalid_data: InvalidRequestError,
    missing_required_attributes: InvalidRequestError,
    extra_body_attributes: InvalidRequestError,
    extra_query_attributes: InvalidRequestError,
    invalid_api_version: InvalidRequestError,
    double_spending: DuplicateTransferError,
});

const CLASS_OF_STATUS = Object.freeze({
    400: InvalidRequestError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    415: InvalidRequestError,
    422: InvalidRequestError,
    429: RateLimitError,
});

/**
 * @param {number} status
 * @param {string|null} code
 * @returns {typeof ApiError}
 */
function errorClassFor(status, code) {
    if (code && Object.prototype.hasOwnProperty.call(CLASS_OF_CODE, code)) {
        return CLASS_OF_CODE[code];
    }
    if (status >= 500 && status <= 599) {
        return ServerError;
    }

    return CLASS_OF_STATUS[status] || ApiError;
}

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const stringOrNull = value => (typeof value === 'string' ? value : null);

function headerValue(headers, name) {
    if (!headers) {
        return undefined;
    }
    if (typeof headers.get === 'function') {
        const value = headers.get(name);

        return value === null ? undefined : value;
    }
    const key = Object.keys(headers).find(candidate => candidate.toLowerCase() === name);

    return key === undefined ? undefined : headers[key];
}

function parseJson(body) {
    const text = typeof body === 'string' ? body : Buffer.from(body || []).toString('utf8');
    try {
        return JSON.parse(text);
    } catch (e) {
        return undefined;
    }
}

/**
 * Reads an API response, already verified, into a result or a typed error.
 *
 * @param {{ status: number, headers?: Object|Headers, body: Buffer|Uint8Array|string }} response
 * @returns {{ kind: 'item', item: Object, apiVersion: string|null, requestId: string|null, context: string|null, replayed: boolean }
 *         | { kind: 'page', paging: 'cursor'|'offset', items: Array, limit: number|null, hasMore?: boolean, startingAfter?: string|null,
 *             offset?: number|null, total?: number|null, apiVersion: string|null, requestId: string|null, context: string|null, replayed: boolean }}
 * @throws {ApiError} an error status, or a success the SDK can't read
 */
function readEnvelope({ status, headers, body }) {
    const replayed = headerValue(headers, 'x-api-replayed') === 'true';
    const parsed = parseJson(body);
    const top = isObject(parsed) ? parsed : {};
    const meta = {
        apiVersion: stringOrNull(top.apiVersion),
        requestId: stringOrNull(top.requestId),
        context: stringOrNull(top.context),
        replayed,
    };

    if (status >= 200 && status <= 299) {
        const data = isObject(top.data) ? top.data : null;
        if (data && isObject(data.item)) {
            return { kind: 'item', item: data.item, ...meta };
        }
        if (data && Array.isArray(data.items)) {
            const limit = typeof data.limit === 'number' ? data.limit : null;
            if ('offset' in data || 'total' in data) {
                return {
                    kind: 'page', paging: 'offset', items: data.items, limit,
                    offset: typeof data.offset === 'number' ? data.offset : null,
                    total: typeof data.total === 'number' ? data.total : null,
                    ...meta,
                };
            }

            return {
                kind: 'page', paging: 'cursor', items: data.items, limit,
                hasMore: data.hasMore === true,
                startingAfter: stringOrNull(data.startingAfter),
                ...meta,
            };
        }

        throw new ApiError({ status, code: null, message: null, requestId: meta.requestId, apiVersion: meta.apiVersion, replayed });
    }

    const error = isObject(top.error) ? top.error : {};
    const code = stringOrNull(error.code);
    const ErrorClass = errorClassFor(status, code);
    const fields = {
        status,
        code,
        message: stringOrNull(error.message),
        requestId: meta.requestId,
        apiVersion: meta.apiVersion,
        replayed,
    };
    if ('details' in error) {
        fields.details = error.details;
    }

    throw new ErrorClass(fields);
}

module.exports = {
    VaultodyError,
    ApiError,
    AuthenticationError,
    RequestSigningError,
    PermissionDeniedError,
    NotFoundError,
    InvalidRequestError,
    ConflictError,
    DuplicateTransferError,
    RateLimitError,
    ServerError,
    RequestOutcomeUnknownError,
    TransportError,
    ParameterError,
    PaginationError,
    VaultKeyChangedError,
    AddressVerificationError,
    ResponseVerificationError,
    ConfigurationError,
    WebhookSignatureError,
    WebhookPayloadError,
    VaultKeyStoreError,
    errorClassFor,
    readEnvelope,
};
