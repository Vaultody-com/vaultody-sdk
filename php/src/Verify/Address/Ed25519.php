<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Ed25519 point decoding, encoding and scalar multiplication, written for this package so it needs no
 * dependency (PHP's sodium extension has no function for a multiple of an arbitrary point). Only public
 * keys pass through here, so nothing needs to run in constant time.
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
 * Affine points are ['x' => 32 bytes, 'y' => 32 bytes], big-endian and below p. Extended points are
 * [X, Y, Z, T] field elements with x = X/Z, y = Y/Z and x*y = T/Z.
 */
final class Ed25519
{
    // d = -121665 / 121666 mod p, and 2d.
    private const D_HEX = '52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3';
    private const D2_HEX = '2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159';
    // A square root of -1 modulo p: 2^((p - 1) / 4).
    private const SQRT_M1_HEX = '2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0';
    // (p + 3) / 8: p = 5 mod 8, so x2^((p + 3) / 8) is a square root of x2 or of -x2.
    private const SQRT_EXPONENT_HEX = '0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe';

    public const BASE_X_HEX = '216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a';
    public const BASE_Y_HEX = '6666666666666666666666666666666666666666666666666666666666666658';

    /** @return array{x: string, y: string} */
    public static function base(): array
    {
        return ['x' => (string) hex2bin(self::BASE_X_HEX), 'y' => (string) hex2bin(self::BASE_Y_HEX)];
    }

    /**
     * 32 bytes to a curve point, with the same acceptance rules as `elliptic` (see the top of this file).
     *
     * @return array{x: string, y: string}
     * @throws KeyDerivationError
     */
    public static function decode(string $bytes): array
    {
        if (strlen($bytes) !== 32) {
            throw new KeyDerivationError('an Ed25519 point is 32 bytes');
        }
        $f = Field::ed25519();
        $xIsOdd = (ord($bytes[31]) & 0x80) !== 0;
        $littleEndian = substr($bytes, 0, 31) . chr(ord($bytes[31]) & 0x7f);
        // Any value below 2^255 is a valid representative; it is reduced modulo p where it is used.
        $y = $f->fromBytes(strrev($littleEndian));

        $y2 = $f->sqr($y);
        // x^2 = (y^2 - 1) / (d y^2 + 1). The denominator is never 0, because -1/d is not a square mod p.
        $numerator = $f->sub($y2, $f->one());
        $denominator = $f->add($f->mul(self::constant(self::D_HEX), $y2), $f->one());
        $x2 = $f->mul($numerator, $f->invert($denominator));
        if ($f->isZero($x2)) {
            if ($xIsOdd) {
                throw new KeyDerivationError('invalid Ed25519 point: x is 0 but the sign bit is set');
            }

            return ['x' => str_repeat("\0", 32), 'y' => $f->toBytes($y)];
        }

        $x = $f->pow($x2, (string) hex2bin(self::SQRT_EXPONENT_HEX));
        if (!$f->equals($f->sqr($x), $x2)) {
            $x = $f->mul($x, self::constant(self::SQRT_M1_HEX));
        }
        if (!$f->equals($f->sqr($x), $x2)) {
            throw new KeyDerivationError('invalid Ed25519 point: not on the curve');
        }
        if ($f->isOdd($x) !== $xIsOdd) {
            $x = $f->neg($x);
        }

        return ['x' => $f->toBytes($x), 'y' => $f->toBytes($y)];
    }

    /** A point to its 32-byte encoding: y little-endian, with the parity of x in the top bit. */
    public static function encode(array $point): string
    {
        $bytes = strrev($point['y']);
        if ((ord($point['x'][31]) & 1) === 1) {
            $bytes[31] = chr(ord($bytes[31]) | 0x80);
        }

        return $bytes;
    }

    /**
     * k * point by double-and-add, for any k given as big-endian bytes, used as given (not reduced
     * modulo the group order).
     *
     * @return array{x: string, y: string}
     */
    public static function multiply(string $scalar, array $point): array
    {
        $f = Field::ed25519();
        $x = $f->fromBytes($point['x']);
        $y = $f->fromBytes($point['y']);
        $base = [$x, $y, $f->one(), $f->mul($x, $y)];
        $result = [$f->zero(), $f->one(), $f->one(), $f->zero()];
        $started = false;
        $length = strlen($scalar);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($scalar[$i]);
            for ($bit = 7; $bit >= 0; $bit--) {
                // Doubling the identity gives the identity: skipping the leading zero bits changes nothing.
                if ($started) {
                    $result = self::double($result);
                }
                if ((($byte >> $bit) & 1) === 1) {
                    $result = self::add($result, $base);
                    $started = true;
                }
            }
        }

        return self::toAffine($result);
    }

    /**
     * a + b for affine points; for the tests.
     *
     * @return array{x: string, y: string}
     */
    public static function addPoints(array $a, array $b): array
    {
        $f = Field::ed25519();
        $toExtended = static function (array $p) use ($f): array {
            $x = $f->fromBytes($p['x']);
            $y = $f->fromBytes($p['y']);

            return [$x, $y, $f->one(), $f->mul($x, $y)];
        };

        return self::toAffine(self::add($toExtended($a), $toExtended($b)));
    }

    /** @return array{x: string, y: string} */
    private static function toAffine(array $point): array
    {
        $f = Field::ed25519();
        [$x, $y, $z] = $point;
        $zInv = $f->invert($z);

        return ['x' => $f->toBytes($f->mul($x, $zInv)), 'y' => $f->toBytes($f->mul($y, $zInv))];
    }

    // RFC 8032 5.1.4, point addition. Complete: it also doubles, and handles the identity.
    private static function add(array $p, array $q): array
    {
        $f = Field::ed25519();
        [$x1, $y1, $z1, $t1] = $p;
        [$x2, $y2, $z2, $t2] = $q;
        $a = $f->mul($f->sub($y1, $x1), $f->sub($y2, $x2));
        $b = $f->mul($f->add($y1, $x1), $f->add($y2, $x2));
        $c = $f->mul($f->mul($t1, self::constant(self::D2_HEX)), $t2);
        $d = $f->mulSmall($f->mul($z1, $z2), 2);
        $e = $f->sub($b, $a);
        $ff = $f->sub($d, $c);
        $g = $f->add($d, $c);
        $h = $f->add($b, $a);

        return [$f->mul($e, $ff), $f->mul($g, $h), $f->mul($ff, $g), $f->mul($e, $h)];
    }

    // RFC 8032 5.1.4, point doubling.
    private static function double(array $p): array
    {
        $f = Field::ed25519();
        [$x1, $y1, $z1] = $p;
        $a = $f->sqr($x1);
        $b = $f->sqr($y1);
        $c = $f->mulSmall($f->sqr($z1), 2);
        $h = $f->add($a, $b);
        $xy = $f->add($x1, $y1);
        $e = $f->sub($h, $f->sqr($xy));
        $g = $f->sub($a, $b);
        $ff = $f->add($c, $g);

        return [$f->mul($e, $ff), $f->mul($g, $h), $f->mul($ff, $g), $f->mul($e, $h)];
    }

    /** @return list<int> */
    private static function constant(string $hex): array
    {
        static $cache = [];

        return $cache[$hex] ??= Field::ed25519()->fromBytes((string) hex2bin($hex));
    }
}
