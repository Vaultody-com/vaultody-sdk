'use strict';

/**
 * Bech32 encoding of version 0 segregated-witness addresses, as BIP173 defines it
 * (github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). Only version 0 is needed: the native
 * SegWit addresses Vaultody issues (P2WPKH) are all version 0, and versions 1 and up use the different
 * Bech32m checksum from BIP350.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

// BIP173's checksum: a BCH code over 5-bit values, computed with the reference code's polymod.
function polymod(values) {
    let chk = 1;
    for (const value of values) {
        const top = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ value;
        for (let i = 0; i < 5; i++) {
            if ((top >>> i) & 1) {
                chk ^= GENERATOR[i];
            }
        }
    }

    return chk >>> 0;
}

const hrpExpand = hrp => [
    ...[...hrp].map(c => c.charCodeAt(0) >> 5),
    0,
    ...[...hrp].map(c => c.charCodeAt(0) & 31),
];

/** Regroups bits, for example 8-bit bytes into 5-bit values, padding the last group with zeros. */
function convertBits(data, fromBits, toBits) {
    let acc = 0;
    let bits = 0;
    const out = [];
    const maxValue = (1 << toBits) - 1;
    for (const value of data) {
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            out.push((acc >> bits) & maxValue);
        }
        acc &= (1 << bits) - 1;
    }
    if (bits > 0) {
        out.push((acc << (toBits - bits)) & maxValue);
    }

    return out;
}

/** Human-readable part plus 5-bit data to a Bech32 string (BIP173 checksum constant 1). */
function encode(hrp, data) {
    const values = [...hrpExpand(hrp), ...data];
    const mod = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1;
    const checksum = [0, 1, 2, 3, 4, 5].map(i => (mod >>> (5 * (5 - i))) & 31);

    return `${hrp}1${[...data, ...checksum].map(v => CHARSET[v]).join('')}`;
}

/** A version 0 witness program (20 or 32 bytes) to its lowercase address. */
function segwitV0Address(hrp, program) {
    if (program.length !== 20 && program.length !== 32) {
        throw new RangeError('a version 0 witness program is 20 or 32 bytes');
    }

    return encode(hrp, [0, ...convertBits(program, 8, 5)]);
}

module.exports = {
    CHARSET,
    polymod,
    hrpExpand,
    convertBits,
    encode,
    segwitV0Address,
};
