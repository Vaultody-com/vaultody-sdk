'use strict';

// Small BigInt helpers shared by the two curve modules.

/** a mod m, always in 0..m-1 (JavaScript's % keeps the sign of a). */
const mod = (a, m) => {
    const r = a % m;

    return r < 0n ? r + m : r;
};

/** base^exponent mod m, by square-and-multiply. */
function powMod(base, exponent, m) {
    let result = 1n;
    let b = mod(base, m);
    let e = exponent;
    while (e > 0n) {
        if (e & 1n) {
            result = (result * b) % m;
        }
        b = (b * b) % m;
        e >>= 1n;
    }

    return result;
}

/** The inverse of a modulo the prime m (Fermat's little theorem). a must not be 0 mod m. */
const invertMod = (a, m) => powMod(a, m - 2n, m);

/** Unsigned big-endian bytes to a BigInt. */
const fromBytesBE = bytes => (bytes.length === 0 ? 0n : BigInt(`0x${Buffer.from(bytes).toString('hex')}`));

/** Unsigned little-endian bytes to a BigInt. */
const fromBytesLE = bytes => fromBytesBE(Buffer.from(bytes).reverse());

/** A non-negative BigInt below 2^(8*length) to big-endian bytes. */
function toBytesBE(value, length) {
    const hex = value.toString(16).padStart(length * 2, '0');
    if (hex.length > length * 2) {
        throw new RangeError(`value does not fit in ${length} bytes`);
    }

    return Buffer.from(hex, 'hex');
}

/** A non-negative BigInt below 2^(8*length) to little-endian bytes. */
const toBytesLE = (value, length) => toBytesBE(value, length).reverse();

module.exports = {
    mod,
    powMod,
    invertMod,
    fromBytesBE,
    fromBytesLE,
    toBytesBE,
    toBytesLE,
};
