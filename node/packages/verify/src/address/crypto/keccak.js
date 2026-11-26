'use strict';

/**
 * Keccak-256, the hash Ethereum and Tron addresses use, written for this package so it needs no
 * dependency.
 *
 * It is NOT the same as SHA3-256, which Node's crypto does offer: both run the Keccak-f[1600]
 * permutation, but NIST changed the padding when it standardised SHA-3 (domain byte 0x06 instead of the
 * original 0x01), so the outputs differ. Ethereum fixed its address format before that change.
 *
 * The permutation follows the Keccak reference (keccak.team, "The Keccak reference", version 3.0,
 * sections 1.2 and 3), with 64-bit lanes held in BigInts and the rotation offsets and round constants
 * from its tables. The sponge takes the padding byte as a parameter, so the tests can run it with the
 * SHA-3 padding and compare it with Node's own sha3-256 and sha3-512.
 */

const MASK64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offset of lane (x, y), stored at index x + 5 * y.
const ROTATIONS = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
].map(BigInt);

const rotl = (lane, n) => (n === 0n ? lane : ((lane << n) | (lane >> (64n - n))) & MASK64);

/** Keccak-f[1600] on 25 lanes, in place. */
function permute(state) {
    const c = new Array(5);
    const b = new Array(25);
    for (const roundConstant of ROUND_CONSTANTS) {
        // theta
        for (let x = 0; x < 5; x++) {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (let x = 0; x < 5; x++) {
            const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1n);
            for (let y = 0; y < 25; y += 5) {
                state[x + y] ^= d;
            }
        }
        // rho and pi: lane (x, y) moves to (y, 2x + 3y), rotated by its offset
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROTATIONS[x + 5 * y]);
            }
        }
        // chi
        for (let y = 0; y < 25; y += 5) {
            for (let x = 0; x < 5; x++) {
                state[x + y] = b[x + y] ^ (~b[((x + 1) % 5) + y] & MASK64 & b[((x + 2) % 5) + y]);
            }
        }
        // iota
        state[0] ^= roundConstant;
    }
}

function absorbBlock(state, block) {
    for (let i = 0; i < block.length / 8; i++) {
        state[i] ^= block.readBigUInt64LE(i * 8);
    }
    permute(state);
}

/**
 * The Keccak sponge with capacity 1600 - 8 * rate bits.
 *
 * @param {number} rate bytes absorbed per permutation (136 for Keccak-256 and SHA3-256)
 * @param {number} paddingByte the first padding byte: 0x01 for original Keccak, 0x06 for SHA-3
 * @param {Uint8Array} data
 * @param {number} outputLength bytes to squeeze out; at most `rate`
 * @returns {Buffer}
 */
function sponge(rate, paddingByte, data, outputLength) {
    const state = new Array(25).fill(0n);
    const input = Buffer.from(data);

    let offset = 0;
    for (; offset + rate <= input.length; offset += rate) {
        absorbBlock(state, input.subarray(offset, offset + rate));
    }
    // pad10*1: the padding byte right after the message, and 0x80 in the last byte of the block.
    const last = Buffer.alloc(rate);
    input.copy(last, 0, offset);
    last[input.length - offset] ^= paddingByte;
    last[rate - 1] ^= 0x80;
    absorbBlock(state, last);

    const out = Buffer.alloc(rate);
    for (let i = 0; i < rate / 8; i++) {
        out.writeBigUInt64LE(state[i], i * 8);
    }

    return out.subarray(0, outputLength);
}

/** Keccak-256 as Ethereum uses it. */
const keccak256 = data => sponge(136, 0x01, data, 32);

module.exports = {
    keccak256,
    sponge,
};
