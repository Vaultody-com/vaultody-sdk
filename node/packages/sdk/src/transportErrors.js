'use strict';

/**
 * Whether a request that failed on the network may have reached the gateway
 * (test-vectors/transport-errors-v1.json). Only a failure that proves the request never left counts as
 * not sent; anything else is 'unknown', and a write in that state is never sent again as new.
 */

// fetch (undici) and Node codes that fail before any byte of the request is written
const NOT_SENT_CODES = new Set([
    'ECONNREFUSED',
    'ENOTFOUND',
    'EAI_AGAIN',
    'UND_ERR_CONNECT_TIMEOUT',
    // TLS: the certificate was refused during the handshake
    'CERT_HAS_EXPIRED',
    'CERT_NOT_YET_VALID',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'SELF_SIGNED_CERT_IN_CHAIN',
    'ERR_TLS_CERT_ALTNAME_INVALID',
]);

const MAX_DEPTH = 8;

function notSent(error, depth) {
    if (!error || typeof error !== 'object' || depth > MAX_DEPTH) {
        return false;
    }
    // Several addresses tried (happy eyeballs): not sent only when none of them got a connection.
    if (Array.isArray(error.errors) && error.errors.length > 0) {
        return error.errors.every(inner => notSent(inner, depth + 1));
    }
    if (typeof error.code === 'string' && NOT_SENT_CODES.has(error.code)) {
        return true;
    }

    return notSent(error.cause, depth + 1);
}

/**
 * @param {*} error what fetch threw
 * @returns {{ sent: false | 'unknown' }}
 */
function classifyTransportError(error) {
    return { sent: notSent(error, 0) ? false : 'unknown' };
}

module.exports = {
    NOT_SENT_CODES,
    classifyTransportError,
};
