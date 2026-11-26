'use strict';

/**
 * Ed25519 point decoding, encoding and scalar multiplication over BigInt, written for this package so
 * it needs no dependency. Only public keys pass through here, so nothing needs to run in constant time.
 *
 * Curve constants and the point formulas (extended coordinates, complete addition for a = -1) follow
 * RFC 8032, section 5.1.
 *
 * Decoding deliberately matches the `elliptic` library the Vaultody server derives addresses with,
 * rather than RFC 8032's stricter rules, so the two always agree on which keys are valid:
 *  - a y of p or more (only possible for 2^255 - 19 .. 2^255 - 1) is reduced modulo p, not refused;
 *  - x = 0 with the sign bit set is refused;
 *  - a y with no matching x on the curve is refused.
 * Scalar multiplication uses the full scalar as given, without reducing it modulo the group order,
 * again as `elliptic` does.
 *
 * Points are extended coordinates [X, Y, Z, T] with x = X/Z, y = Y/Z and x*y = T/Z.
 */

const { mod, powMod, invertMod, fromBytesLE, toBytesLE } = require('./bigint');

const P = (1n << 255n) - 19n;
// d = -121665 / 121666 mod p
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const D2 = (2n * D) % P;
// The order of the prime subgroup the base point generates.
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
// A square root of -1 modulo p: 2^((p - 1) / 4).
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const BASE = Object.freeze([
    15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    46316835694926478169428394003475163141307993866256225615783033603165251855960n,
    1n,
    (15112221349535400772501151409588531511454012693041857206046113283949847762202n
        * 46316835694926478169428394003475163141307993866256225615783033603165251855960n) % P,
]);
const IDENTITY = Object.freeze([0n, 1n, 1n, 0n]);

const fp = a => mod(a, P);

// RFC 8032 5.1.4, point addition. Complete: it also doubles, and handles the identity.
function add([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) {
    const A = fp((Y1 - X1) * (Y2 - X2));
    const Bv = fp((Y1 + X1) * (Y2 + X2));
    const C = fp(T1 * D2 * T2);
    const Dv = fp(Z1 * 2n * Z2);
    const E = Bv - A;
    const F = Dv - C;
    const G = Dv + C;
    const H = Bv + A;

    return [fp(E * F), fp(G * H), fp(F * G), fp(E * H)];
}

// RFC 8032 5.1.4, point doubling.
function double([X1, Y1, Z1]) {
    const A = fp(X1 * X1);
    const Bv = fp(Y1 * Y1);
    const C = fp(2n * Z1 * Z1);
    const H = A + Bv;
    const E = fp(H - (X1 + Y1) * (X1 + Y1));
    const G = A - Bv;
    const F = C + G;

    return [fp(E * F), fp(G * H), fp(F * G), fp(E * H)];
}

/** k * point by double-and-add, for any k >= 0, with k used as given (not reduced modulo L). */
function multiply(k, point) {
    if (typeof k !== 'bigint' || k < 0n) {
        throw new RangeError('the scalar must be a non-negative BigInt');
    }
    let result = IDENTITY;
    for (let bit = BigInt(k.toString(2).length - 1); bit >= 0n; bit--) {
        result = double(result);
        if ((k >> bit) & 1n) {
            result = add(result, point);
        }
    }

    return result;
}

/** 32 bytes to a curve point, with the same acceptance rules as `elliptic` (see the top of this file). */
function decode(bytes) {
    if (!bytes || bytes.length !== 32) {
        throw new Error('an Ed25519 point is 32 bytes');
    }
    const copy = Buffer.from(bytes);
    const xIsOdd = (copy[31] & 0x80) !== 0;
    copy[31] &= 0x7f;
    const y = fp(fromBytesLE(copy));

    const y2 = fp(y * y);
    // x^2 = (y^2 - 1) / (d y^2 + 1). The denominator is never 0, because -1/d is not a square mod p.
    const x2 = fp((y2 - 1n) * invertMod(fp(D * y2 + 1n), P));
    if (x2 === 0n) {
        if (xIsOdd) {
            throw new Error('invalid Ed25519 point: x is 0 but the sign bit is set');
        }

        return [0n, y, 1n, 0n];
    }

    // p = 5 mod 8: a candidate root is x2^((p + 3) / 8); if its square is -x2, multiply by sqrt(-1).
    let x = powMod(x2, (P + 3n) / 8n, P);
    if (fp(x * x) !== x2) {
        x = fp(x * SQRT_M1);
    }
    if (fp(x * x) !== x2) {
        throw new Error('invalid Ed25519 point: not on the curve');
    }
    if ((x & 1n) === 1n !== xIsOdd) {
        x = P - x;
    }

    return [x, y, 1n, fp(x * y)];
}

/** A point to its 32-byte encoding: y little-endian, with the parity of x in the top bit. */
function encode([X, Y, Z]) {
    const zInv = invertMod(Z, P);
    const x = fp(X * zInv);
    const y = fp(Y * zInv);
    const bytes = toBytesLE(y, 32);
    if (x & 1n) {
        bytes[31] |= 0x80;
    }

    return bytes;
}

module.exports = {
    P,
    L,
    BASE,
    IDENTITY,
    add,
    multiply,
    decode,
    encode,
};
