'use strict';

/**
 * CashAddr, the Bitcoin Cash address format, as its specification defines it
 * (github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md). It uses the Bech32
 * character set with a 40-bit checksum over the prefix and the payload. The payload is a version byte
 * (type in the high bits, hash size in the low three) followed by the hash.
 *
 * The 40-bit arithmetic is done in BigInt, since JavaScript's bitwise operators stop at 32 bits.
 */

const { CHARSET, convertBits } = require('./bech32');

const GENERATOR = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];

const TYPE_P2PKH = 0;
const TYPE_P2SH = 1;

// Hash size in bytes -> the size code in the low bits of the version byte.
const SIZE_CODES = new Map([[20, 0], [24, 1], [28, 2], [32, 3], [40, 4], [48, 5], [56, 6], [64, 7]]);

function polymod(values) {
    let c = 1n;
    for (const value of values) {
        const c0 = c >> 35n;
        c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(value);
        for (let i = 0; i < 5; i++) {
            if ((c0 >> BigInt(i)) & 1n) {
                c ^= GENERATOR[i];
            }
        }
    }

    return c ^ 1n;
}

/**
 * @param {string} prefix for example "bitcoincash" or "bchtest"
 * @param {number} type 0 for P2PKH, 1 for P2SH (the format allows 0..15)
 * @param {Uint8Array} hash
 * @returns {string} "prefix:payload", lowercase
 */
function encode(prefix, type, hash) {
    const sizeCode = SIZE_CODES.get(hash.length);
    if (sizeCode === undefined || !Number.isInteger(type) || type < 0 || type > 15) {
        throw new RangeError('unsupported CashAddr type or hash size');
    }
    const payload = convertBits([(type << 3) | sizeCode, ...hash], 8, 5);
    const prefixValues = [...prefix].map(c => c.charCodeAt(0) & 31);
    const mod = polymod([...prefixValues, 0, ...payload, 0, 0, 0, 0, 0, 0, 0, 0]);
    const checksum = [0, 1, 2, 3, 4, 5, 6, 7].map(i => Number((mod >> BigInt(5 * (7 - i))) & 31n));

    return `${prefix}:${[...payload, ...checksum].map(v => CHARSET[v]).join('')}`;
}

module.exports = {
    TYPE_P2PKH,
    TYPE_P2SH,
    encode,
};
