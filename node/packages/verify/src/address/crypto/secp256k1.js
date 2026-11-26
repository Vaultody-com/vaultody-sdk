'use strict';

/**
 * secp256k1 point arithmetic over BigInt, written for this package so it needs no dependency.
 *
 * It only ever handles public keys, so it does not need to run in constant time. The curve constants
 * are from SEC 2 version 2.0, section 2.4.1. Points are added and doubled in Jacobian coordinates
 * with the textbook formulas for a curve with a = 0 ("add-2007-bl" and "dbl-2009-l" in the
 * Explicit-Formulas Database, hyperelliptic.org/EFD), so a scalar multiplication needs only one
 * modular inverse, at the end.
 *
 * Affine points are { x, y } BigInts; null is the point at infinity.
 */

const { mod, powMod, invertMod, fromBytesBE, toBytesBE } = require('./bigint');

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const B = 7n;
const G = Object.freeze({
    x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
});

const fp = a => mod(a, P);

// Jacobian (X, Y, Z) stands for the affine point (X / Z^2, Y / Z^3); Z = 0 is infinity.
const INFINITY_J = Object.freeze([1n, 1n, 0n]);
const toJacobian = point => (point === null ? INFINITY_J : [point.x, point.y, 1n]);

function toAffine([X, Y, Z]) {
    if (Z === 0n) {
        return null;
    }
    const zInv = invertMod(Z, P);
    const zInv2 = fp(zInv * zInv);

    return { x: fp(X * zInv2), y: fp(Y * zInv2 * zInv) };
}

function doubleJ([X1, Y1, Z1]) {
    if (Z1 === 0n || Y1 === 0n) {
        return INFINITY_J;
    }
    const A = fp(X1 * X1);
    const Bq = fp(Y1 * Y1);
    const C = fp(Bq * Bq);
    const D = fp(2n * (fp((X1 + Bq) * (X1 + Bq)) - A - C));
    const E = fp(3n * A);
    const F = fp(E * E);
    const X3 = fp(F - 2n * D);
    const Y3 = fp(E * (D - X3) - 8n * C);
    const Z3 = fp(2n * Y1 * Z1);

    return [X3, Y3, Z3];
}

function addJ(p1, p2) {
    const [X1, Y1, Z1] = p1;
    const [X2, Y2, Z2] = p2;
    if (Z1 === 0n) {
        return p2;
    }
    if (Z2 === 0n) {
        return p1;
    }
    const Z1Z1 = fp(Z1 * Z1);
    const Z2Z2 = fp(Z2 * Z2);
    const U1 = fp(X1 * Z2Z2);
    const U2 = fp(X2 * Z1Z1);
    const S1 = fp(Y1 * Z2 * Z2Z2);
    const S2 = fp(Y2 * Z1 * Z1Z1);
    const H = fp(U2 - U1);
    const r = fp(2n * (S2 - S1));
    if (H === 0n) {
        // Same x: either the same point (double it) or opposite points (the sum is infinity).
        return r === 0n ? doubleJ(p1) : INFINITY_J;
    }
    const I = fp(4n * H * H);
    const J = fp(H * I);
    const V = fp(U1 * I);
    const X3 = fp(r * r - J - 2n * V);
    const Y3 = fp(r * (V - X3) - 2n * S1 * J);
    const Z3 = fp((fp((Z1 + Z2) * (Z1 + Z2)) - Z1Z1 - Z2Z2) * H);

    return [X3, Y3, Z3];
}

/** a + b for affine points (either may be null, the point at infinity). */
const add = (a, b) => toAffine(addJ(toJacobian(a), toJacobian(b)));

/** k * point by double-and-add, for any k >= 0. Returns null for the point at infinity. */
function multiply(k, point) {
    if (typeof k !== 'bigint' || k < 0n) {
        throw new RangeError('the scalar must be a non-negative BigInt');
    }
    const base = toJacobian(point);
    let result = INFINITY_J;
    for (let bit = BigInt(k.toString(2).length - 1); bit >= 0n; bit--) {
        result = doubleJ(result);
        if ((k >> bit) & 1n) {
            result = addJ(result, base);
        }
    }

    return toAffine(result);
}

const multiplyG = k => multiply(k, G);

/**
 * A 33-byte SEC 1 compressed point (02 or 03, then x) to an affine point. Refuses another prefix, an x
 * of p or more, and an x with no point on the curve, as libsecp256k1 does.
 */
function decompress(bytes) {
    if (!bytes || bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) {
        throw new Error('a compressed secp256k1 point is 33 bytes starting with 02 or 03');
    }
    const x = fromBytesBE(bytes.subarray(1));
    if (x >= P) {
        throw new Error('the point x coordinate is not below the field prime');
    }
    const ySquared = fp(x * x * x + B);
    // p = 3 mod 4, so a square root of c, when one exists, is c^((p + 1) / 4).
    let y = powMod(ySquared, (P + 1n) / 4n, P);
    if (fp(y * y) !== ySquared) {
        throw new Error('the point is not on the curve');
    }
    if ((y & 1n) !== BigInt(bytes[0] & 1)) {
        y = P - y;
    }

    return { x, y };
}

/** An affine point to its 33-byte SEC 1 compressed form. */
const compress = ({ x, y }) => Buffer.concat([Buffer.from([y & 1n ? 0x03 : 0x02]), toBytesBE(x, 32)]);

/** An affine point as x || y, 64 bytes, without the 04 prefix: the input Ethereum and Tron hash. */
const rawXY = ({ x, y }) => Buffer.concat([toBytesBE(x, 32), toBytesBE(y, 32)]);

module.exports = {
    P,
    N,
    G,
    add,
    multiply,
    multiplyG,
    decompress,
    compress,
    rawXY,
};
