'use strict';

/**
 * Why a response was refused. Callers branch on these strings, so they are part of the public API and
 * are the same in every language the helper ships in.
 */
const REASONS = Object.freeze({
    // A signature header is absent or empty: the response was not signed, or the signature was stripped.
    MISSING: 'missing',
    // Malformed headers or certificate, or a signature that does not match the request and response.
    INVALID: 'invalid',
    // The response timestamp is outside the certificate's window, or this machine's clock is past it.
    EXPIRED: 'expired',
    // The certificate names a root key this helper does not trust.
    UNKNOWN_ROOT: 'unknown_root',
    // Genuine, but the gateway did not read the request body, so the response is not tied to it.
    REQUEST_UNBOUND: 'request_unbound',
    // A signature format this version of the helper does not understand.
    UNSUPPORTED_VERSION: 'unsupported_version',
});

/**
 * Thrown when a response fails verification. `reason` is one of REASONS; the message adds detail for
 * logs but is not meant to be matched on.
 */
class ResponseSignatureError extends Error {
    constructor(reason, detail) {
        super(`Vaultody response signature check failed (${reason}): ${detail}`);
        this.name = 'ResponseSignatureError';
        this.reason = reason;
    }
}

/**
 * Thrown when the helper itself is set up wrongly, for example with no root keys to check against. It is
 * a separate class so that a broken setup can never be mistaken for, or handled like, a bad response.
 */
class ConfigurationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ConfigurationError';
    }
}

module.exports = {
    REASONS,
    ResponseSignatureError,
    ConfigurationError,
};
