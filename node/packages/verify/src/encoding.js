'use strict';

const crypto = require('node:crypto');

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest();

/**
 * Standard base64 with padding, accepted only in the one form an encoder prints. Node's decoder skips
 * characters it doesn't know, also accepts the URL-safe alphabet and ignores leftover bits, so several
 * different header values could decode to the same bytes. Re-encoding and comparing refuses all of them,
 * which keeps this helper in agreement with the gateway and with the other language helpers.
 *
 * @param {string} text
 * @returns {Buffer|null} the bytes, or null when the text is not canonical base64
 */
function strictBase64(text) {
    if (typeof text !== 'string' || text === '') {
        return null;
    }

    const bytes = Buffer.from(text, 'base64');

    return bytes.toString('base64') === text ? bytes : null;
}

// No sign, no leading zero, no fraction or exponent, ASCII digits only: the one spelling every language
// prints for a non-negative integer.
const DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * Unix seconds in canonical decimal. Values above 2^53 - 1 are refused because JavaScript numbers can't
 * hold them exactly, and a rounded expiry time is not one the gateway issued.
 *
 * @param {string} text
 * @returns {number|null}
 */
function strictSeconds(text) {
    if (typeof text !== 'string' || !DECIMAL.test(text)) {
        return null;
    }

    const value = Number(text);

    return Number.isSafeInteger(value) ? value : null;
}

const isArrayBuffer = value => Object.prototype.toString.call(value) === '[object ArrayBuffer]';

/**
 * The raw bytes of a request or response body. A string is taken as UTF-8. Anything else, in particular
 * an already parsed JSON object, is refused: the signature covers the exact bytes on the wire, and
 * re-serialising parsed JSON rarely gives the same bytes back.
 *
 * @param {Buffer|Uint8Array|ArrayBuffer|string|null|undefined} value
 * @param {string} name used in the error message
 * @returns {Buffer}
 */
function toBytes(value, name) {
    if (value === undefined || value === null) {
        return Buffer.alloc(0);
    }
    if (typeof value === 'string') {
        return Buffer.from(value, 'utf8');
    }
    if (Buffer.isBuffer(value)) {
        return value;
    }
    if (ArrayBuffer.isView(value)) {
        return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    if (isArrayBuffer(value)) {
        return Buffer.from(value);
    }

    throw new TypeError(`${name} must be the raw body bytes (Buffer, Uint8Array, ArrayBuffer) or a string; `
        + 'verify the response before parsing it as JSON');
}

module.exports = {
    sha256,
    strictBase64,
    strictSeconds,
    toBytes,
};
