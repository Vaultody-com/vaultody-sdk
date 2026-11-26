'use strict';

/**
 * Public-key derivation below a vault's extended public key, the same way the Vaultody server derives
 * every address: path m/{account}/{0 deposit | 1 change}/{index}, with no hardened steps.
 *
 * - ECDSA (secp256k1) keys use standard BIP32 public derivation (CKDpub), with the `hdkey` library's
 *   handling of an invalid child (see deriveEcdsaChild).
 * - EdDSA (ed25519) keys use Vaultody's own scheme from its xpub utilities library (deriveEddsaChild).
 *   BIP32 does not define derivation for ed25519 public keys.
 */

const crypto = require('node:crypto');

const base58 = require('./crypto/base58');
const secp256k1 = require('./crypto/secp256k1');
const ed25519 = require('./crypto/ed25519');
const { fromBytesBE } = require('./crypto/bigint');

// Indexes at or above 2^31 are hardened, which needs the private key.
const MAX_INDEX = 0x7fffffff;
const EXTENDED_KEY_BYTES = 78;

const ALGORITHMS = Object.freeze({ ECDSA: 'ECDSA', EDDSA: 'EDDSA' });

const hmac = (algorithm, key, data) => crypto.createHmac(algorithm, key).update(data).digest();

/**
 * Reads an extended public key: version (4) | depth (1) | parent fingerprint (4) | child number (4) |
 * chain code (32) | key data (33), Base58Check encoded.
 *
 * Only the chain code and the key are used. The server rewrites the version bytes to "xpub" before it
 * derives, and older vaults store keys at depth 1 with a parent fingerprint, so version, depth,
 * fingerprint and child number are all ignored here.
 *
 * @param {string} text
 * @param {'ECDSA'|'EDDSA'} algorithm
 * @returns {{ algorithm: string, chainCode: Buffer, key: Buffer, point: * }}
 */
function parseExtendedPublicKey(text, algorithm) {
    const bytes = typeof text === 'string' ? base58.decodeCheck(text) : null;
    if (bytes === null) {
        throw new Error('not a Base58Check string');
    }
    if (bytes.length !== EXTENDED_KEY_BYTES) {
        throw new Error(`an extended key is ${EXTENDED_KEY_BYTES} bytes, this one is ${bytes.length}`);
    }
    const chainCode = Buffer.from(bytes.subarray(13, 45));
    const keyData = Buffer.from(bytes.subarray(45));

    if (algorithm === ALGORITHMS.ECDSA) {
        // A compressed secp256k1 point: 02 or 03, then x.
        return { algorithm, chainCode, key: keyData, point: secp256k1.decompress(keyData) };
    }
    if (algorithm === ALGORITHMS.EDDSA) {
        // Vaultody stores an ed25519 key as 00 followed by the 32-byte encoded point.
        if (keyData[0] !== 0x00) {
            throw new Error('an EdDSA extended key holds 00 followed by the 32-byte public key');
        }
        const key = keyData.subarray(1);

        return { algorithm, chainCode, key, point: ed25519.decode(key) };
    }

    throw new Error(`unknown algorithm ${algorithm}`);
}

/**
 * BIP32 CKDpub: I = HMAC-SHA512(chainCode, serP(K) || ser32(index)), child K = parse256(I_L)*G + K,
 * child chain code = I_R.
 *
 * When I_L is not below the curve order, or the child is the point at infinity, BIP32 calls the index
 * invalid. The `hdkey` library the server uses then derives index + 1 in its place, and so on; the
 * address keeps the requested index in its path. This does the same, so both always land on the same
 * key. Past 2^31 - 1 the next index would be hardened, which `hdkey` refuses, and so does this.
 *
 * Each invalid case has a chance of about 2^-127, so it never happens in practice.
 *
 * @param {{ key: Buffer, point: *, chainCode: Buffer }} parent
 * @param {number} index 0..2^31-1
 * @param {Function} [hmacSha512] replaced only by tests, to force the invalid cases
 */
function deriveEcdsaChild(parent, index, hmacSha512 = (key, data) => hmac('sha512', key, data)) {
    for (let candidate = index; ; candidate++) {
        if (candidate > MAX_INDEX) {
            throw new Error('no valid non-hardened child at or after this index');
        }
        const indexBytes = Buffer.alloc(4);
        indexBytes.writeUInt32BE(candidate);
        const I = hmacSha512(parent.chainCode, Buffer.concat([parent.key, indexBytes]));
        const IL = fromBytesBE(I.subarray(0, 32));
        if (IL >= secp256k1.N) {
            continue;
        }
        const point = secp256k1.add(secp256k1.multiplyG(IL), parent.point);
        if (point === null) {
            continue;
        }

        return { key: secp256k1.compress(point), point, chainCode: Buffer.from(I.subarray(32)) };
    }
}

/**
 * Vaultody's ed25519 public derivation (as the server's xpub utilities derive):
 *
 *   k          = HMAC-SHA256(chainCode, 0x02 || key || index as 4 bytes LITTLE-endian),
 *                read as a BIG-endian integer and used unreduced
 *   child key  = encode(k * decode(key))
 *   chain code = HMAC-SHA256(chainCode, 0x03 || key || index as 4 bytes little-endian)
 *
 * The byte orders are as the server has them: the index is written little-endian, and the HMAC output
 * is read big-endian (as bn.js reads a Buffer).
 *
 * @param {{ key: Buffer, point: *, chainCode: Buffer }} parent
 * @param {number} index 0..2^31-1
 */
function deriveEddsaChild(parent, index) {
    if (index > MAX_INDEX) {
        throw new Error('hardened derivation is not possible from a public key');
    }
    const indexBytes = Buffer.alloc(4);
    indexBytes.writeUInt32LE(index);
    const k = fromBytesBE(hmac('sha256', parent.chainCode, Buffer.concat([Buffer.from([0x02]), parent.key, indexBytes])));
    const chainCode = hmac('sha256', parent.chainCode, Buffer.concat([Buffer.from([0x03]), parent.key, indexBytes]));
    const point = ed25519.multiply(k, parent.point);

    return { key: ed25519.encode(point), point, chainCode };
}

/**
 * One child step for either algorithm.
 *
 * @param {{ algorithm: string }} parent a parsed extended key or a node derived from one
 * @param {number} index
 */
function deriveChild(parent, index) {
    const child = parent.algorithm === ALGORITHMS.ECDSA ? deriveEcdsaChild(parent, index) : deriveEddsaChild(parent, index);

    return { algorithm: parent.algorithm, ...child };
}

/** Derives along a list of non-hardened indexes. */
const derivePath = (node, indexes) => indexes.reduce(deriveChild, node);

module.exports = {
    ALGORITHMS,
    MAX_INDEX,
    parseExtendedPublicKey,
    deriveEcdsaChild,
    deriveEddsaChild,
    deriveChild,
    derivePath,
};
