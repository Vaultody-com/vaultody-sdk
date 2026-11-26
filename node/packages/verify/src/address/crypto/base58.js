'use strict';

/**
 * Base58 and Base58Check, as Bitcoin defines them (the reference is base58.cpp in Bitcoin Core): the
 * bytes read as one big-endian number written in base 58, each leading zero byte written as the
 * alphabet's first character. Base58Check appends the first 4 bytes of SHA-256(SHA-256(payload)).
 *
 * XRP uses the same scheme with its own alphabet, which starts with "r".
 */

const crypto = require('node:crypto');

const BITCOIN_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const RIPPLE_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest();
const checksum = payload => sha256(sha256(payload)).subarray(0, 4);

/** Bytes to Base58 text. */
function encode(bytes, alphabet = BITCOIN_ALPHABET) {
    const input = Buffer.from(bytes);
    let zeros = 0;
    while (zeros < input.length && input[zeros] === 0) {
        zeros++;
    }

    let value = input.length === zeros ? 0n : BigInt(`0x${input.subarray(zeros).toString('hex')}`);
    let digits = '';
    while (value > 0n) {
        digits = alphabet[Number(value % 58n)] + digits;
        value /= 58n;
    }

    return alphabet[0].repeat(zeros) + digits;
}

/** Base58 text to bytes, or null when it holds a character outside the alphabet. */
function decode(text, alphabet = BITCOIN_ALPHABET) {
    if (typeof text !== 'string') {
        return null;
    }
    let zeros = 0;
    while (zeros < text.length && text[zeros] === alphabet[0]) {
        zeros++;
    }

    let value = 0n;
    for (let i = zeros; i < text.length; i++) {
        const digit = alphabet.indexOf(text[i]);
        if (digit === -1) {
            return null;
        }
        value = value * 58n + BigInt(digit);
    }

    let hex = value === 0n ? '' : value.toString(16);
    if (hex.length % 2) {
        hex = `0${hex}`;
    }

    return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, 'hex')]);
}

/** Payload to Base58Check text. */
const encodeCheck = (payload, alphabet = BITCOIN_ALPHABET) => encode(Buffer.concat([Buffer.from(payload), checksum(payload)]), alphabet);

/** Base58Check text to its payload, or null when it is not Base58 or its checksum does not match. */
function decodeCheck(text, alphabet = BITCOIN_ALPHABET) {
    const bytes = decode(text, alphabet);
    if (bytes === null || bytes.length < 4) {
        return null;
    }
    const payload = bytes.subarray(0, bytes.length - 4);

    return checksum(payload).equals(bytes.subarray(bytes.length - 4)) ? payload : null;
}

module.exports = {
    BITCOIN_ALPHABET,
    RIPPLE_ALPHABET,
    encode,
    decode,
    encodeCheck,
    decodeCheck,
};
