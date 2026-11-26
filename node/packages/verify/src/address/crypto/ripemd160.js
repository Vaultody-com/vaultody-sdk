'use strict';

/**
 * RIPEMD-160, used inside every Bitcoin-family and XRP address (hash160 = RIPEMD-160 of SHA-256).
 *
 * Node's crypto offers it whenever its OpenSSL build does, but OpenSSL 3 moved it to the "legacy"
 * provider for a while, and some builds still leave it out. This package therefore carries its own copy,
 * written from the algorithm description by Dobbertin, Bosselaers and Preneel ("RIPEMD-160: A
 * Strengthened Version of RIPEMD", 1996, and the reference page at homes.esat.kuleuven.be/~bosselae/
 * ripemd160.html), and uses Node's only when it is there. The tests run both against the published
 * test vectors.
 */

const crypto = require('node:crypto');

// Message word used by each of the 80 steps, left line then right line.
const R_LEFT = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const R_RIGHT = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
// Left-rotation amount of each step.
const S_LEFT = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const S_RIGHT = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
// Additive constant of each 16-step round.
const K_LEFT = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const K_RIGHT = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

// The five boolean functions; the right line runs them in reverse order.
function f(round, x, y, z) {
    switch (round) {
        case 0: return (x ^ y ^ z) >>> 0;
        case 1: return ((x & y) | (~x & z)) >>> 0;
        case 2: return ((x | ~y) ^ z) >>> 0;
        case 3: return ((x & z) | (y & ~z)) >>> 0;
        default: return (x ^ (y | ~z)) >>> 0;
    }
}

function compress(h, block) {
    const X = new Array(16);
    for (let i = 0; i < 16; i++) {
        X[i] = block.readUInt32LE(i * 4);
    }

    let [al, bl, cl, dl, el] = h;
    let [ar, br, cr, dr, er] = h;
    for (let j = 0; j < 80; j++) {
        const round = j >> 4;
        let t = rotl((al + f(round, bl, cl, dl) + X[R_LEFT[j]] + K_LEFT[round]) >>> 0, S_LEFT[j]);
        t = (t + el) >>> 0;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        t = rotl((ar + f(4 - round, br, cr, dr) + X[R_RIGHT[j]] + K_RIGHT[round]) >>> 0, S_RIGHT[j]);
        t = (t + er) >>> 0;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }

    const t = (h[1] + cl + dr) >>> 0;
    h[1] = (h[2] + dl + er) >>> 0;
    h[2] = (h[3] + el + ar) >>> 0;
    h[3] = (h[4] + al + br) >>> 0;
    h[4] = (h[0] + bl + cr) >>> 0;
    h[0] = t;
}

/** RIPEMD-160 in plain JavaScript. */
function ripemd160Vendored(data) {
    const input = Buffer.from(data);
    // Merkle-Damgard padding: 0x80, zeros to 56 mod 64, then the bit length as 64-bit little-endian.
    const padded = Buffer.alloc(Math.ceil((input.length + 9) / 64) * 64);
    input.copy(padded);
    padded[input.length] = 0x80;
    padded.writeBigUInt64LE(BigInt(input.length) * 8n, padded.length - 8);

    const h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    for (let offset = 0; offset < padded.length; offset += 64) {
        compress(h, padded.subarray(offset, offset + 64));
    }

    const out = Buffer.alloc(20);
    h.forEach((word, i) => out.writeUInt32LE(word, i * 4));

    return out;
}

function nodeHasRipemd160() {
    try {
        crypto.createHash('ripemd160').update('').digest();

        return true;
    } catch (e) {
        return false;
    }
}

const NODE_HAS_RIPEMD160 = nodeHasRipemd160();

const ripemd160Node = data => crypto.createHash('ripemd160').update(data).digest();

/** RIPEMD-160, from Node's crypto when it has it, otherwise the copy above. */
const ripemd160 = NODE_HAS_RIPEMD160 ? ripemd160Node : ripemd160Vendored;

module.exports = {
    ripemd160,
    ripemd160Vendored,
    NODE_HAS_RIPEMD160,
};
