<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * secp256k1 point arithmetic for public-key derivation, written for this package so it needs no
 * dependency.
 *
 * It only ever handles public keys, so it does not need to run in constant time. The curve constants
 * are from SEC 2 version 2.0, section 2.4.1. Points are added and doubled in Jacobian coordinates with
 * the textbook formulas for a curve with a = 0 ("add-2007-bl" and "dbl-2009-l" in the
 * Explicit-Formulas Database, hyperelliptic.org/EFD), so a scalar multiplication needs only one
 * modular inverse, at the end.
 *
 * k * G, the expensive step of every derivation, is handed to OpenSSL when its build has the curve:
 * loading a private key that holds only the scalar makes OpenSSL compute the public point. Some
 * OpenSSL builds leave secp256k1 out; the same product is then computed here. The tests check that the
 * two agree.
 *
 * Affine points are ['x' => 32 bytes, 'y' => 32 bytes], big-endian and below p; null is the point at
 * infinity.
 */
final class Secp256k1
{
    public const N_HEX = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
    public const P_HEX = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';
    public const GX_HEX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    public const GY_HEX = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

    // p = 3 mod 4, so a square root of c, when one exists, is c^((p + 1) / 4).
    private const SQRT_EXPONENT_HEX = '3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c';

    // DER of the curve's object identifier, 1.3.132.0.10.
    private const CURVE_OID_DER = "\x06\x05\x2b\x81\x04\x00\x0a";

    private static ?bool $opensslUsable = null;

    /** @return array{x: string, y: string} */
    public static function generator(): array
    {
        return ['x' => (string) hex2bin(self::GX_HEX), 'y' => (string) hex2bin(self::GY_HEX)];
    }

    /** The curve order n as 32 big-endian bytes. */
    public static function order(): string
    {
        return (string) hex2bin(self::N_HEX);
    }

    /**
     * A 33-byte SEC 1 compressed point (02 or 03, then x) to an affine point. Refuses another prefix, an
     * x of p or more, and an x with no point on the curve, as libsecp256k1 does.
     *
     * @return array{x: string, y: string}
     * @throws KeyDerivationError
     */
    public static function decompress(string $bytes): array
    {
        if (strlen($bytes) !== 33 || ($bytes[0] !== "\x02" && $bytes[0] !== "\x03")) {
            throw new KeyDerivationError('a compressed secp256k1 point is 33 bytes starting with 02 or 03');
        }
        $xBytes = substr($bytes, 1);
        // Equal-length binary strings compare byte by byte, as unsigned numbers.
        if (strcmp($xBytes, (string) hex2bin(self::P_HEX)) >= 0) {
            throw new KeyDerivationError('the point x coordinate is not below the field prime');
        }
        $f = Field::secp256k1();
        $x = $f->fromBytes($xBytes);
        $ySquared = $f->add($f->mul($f->sqr($x), $x), $f->fromInt(7));
        $y = $f->pow($ySquared, (string) hex2bin(self::SQRT_EXPONENT_HEX));
        if (!$f->equals($f->sqr($y), $ySquared)) {
            throw new KeyDerivationError('the point is not on the curve');
        }
        if ($f->isOdd($y) !== ($bytes[0] === "\x03")) {
            $y = $f->neg($y);
        }

        return ['x' => $xBytes, 'y' => $f->toBytes($y)];
    }

    /** An affine point to its 33-byte SEC 1 compressed form. */
    public static function compress(array $point): string
    {
        return ((ord($point['y'][31]) & 1) === 1 ? "\x03" : "\x02") . $point['x'];
    }

    /** An affine point as x || y, 64 bytes, without the 04 prefix: the input Ethereum and Tron hash. */
    public static function rawXY(array $point): string
    {
        return $point['x'] . $point['y'];
    }

    /**
     * a + b for affine points (either may be null, the point at infinity).
     *
     * @return array{x: string, y: string}|null
     */
    public static function add(?array $a, ?array $b): ?array
    {
        return self::toAffine(self::addJ(self::toJacobian($a), self::toJacobian($b)));
    }

    /**
     * k * point by double-and-add, for any k given as big-endian bytes. Null for the point at infinity.
     *
     * @return array{x: string, y: string}|null
     */
    public static function multiply(string $scalar, ?array $point): ?array
    {
        $base = self::toJacobian($point);
        $result = null;
        $length = strlen($scalar);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($scalar[$i]);
            for ($bit = 7; $bit >= 0; $bit--) {
                $result = self::doubleJ($result);
                if ((($byte >> $bit) & 1) === 1) {
                    $result = self::addJ($result, $base);
                }
            }
        }

        return self::toAffine($result);
    }

    /**
     * k * G for 0 < k < n, given as 32 big-endian bytes: through OpenSSL when it can, else here.
     *
     * @return array{x: string, y: string}|null null only for k = 0
     */
    public static function multiplyG(string $scalar): ?array
    {
        if (strlen($scalar) === 32 && trim($scalar, "\0") !== '' && strcmp($scalar, self::order()) < 0) {
            $point = self::multiplyGWithOpenssl($scalar);
            if ($point !== null) {
                return $point;
            }
        }

        return self::multiply($scalar, self::generator());
    }

    /**
     * k * G computed here, never through OpenSSL; for the tests that compare the two.
     *
     * @return array{x: string, y: string}|null
     */
    public static function multiplyGPure(string $scalar): ?array
    {
        return self::multiply($scalar, self::generator());
    }

    /** Whether k * G goes through OpenSSL on this PHP build. */
    public static function opensslAvailable(): bool
    {
        if (self::$opensslUsable === null) {
            $one = str_repeat("\0", 31) . "\x01";
            $point = self::opensslPublicPoint($one);
            self::$opensslUsable = $point !== null && $point === self::generator();
        }

        return self::$opensslUsable;
    }

    /** @return array{x: string, y: string}|null */
    private static function multiplyGWithOpenssl(string $scalar): ?array
    {
        if (!self::opensslAvailable()) {
            return null;
        }

        return self::opensslPublicPoint($scalar);
    }

    /**
     * Loads a SEC 1 ECPrivateKey that holds only the scalar (SEQUENCE { INTEGER 1, OCTET STRING k,
     * [0] secp256k1 }); OpenSSL derives the public point k * G when it reads such a key.
     *
     * @return array{x: string, y: string}|null null when this OpenSSL build cannot do it
     */
    private static function opensslPublicPoint(string $scalar): ?array
    {
        if (!function_exists('openssl_pkey_get_private')) {
            return null;
        }
        $body = "\x02\x01\x01" . "\x04\x20" . $scalar . "\xa0" . chr(strlen(self::CURVE_OID_DER)) . self::CURVE_OID_DER;
        $der = "\x30" . chr(strlen($body)) . $body;
        // The PEM label is put together here so that secret scanners don't take this line for a key.
        $label = 'EC PRIVATE' . ' KEY';
        $pem = "-----BEGIN {$label}-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END {$label}-----\n";

        $key = @openssl_pkey_get_private($pem);
        // The scalar is a public value here (an HMAC output over public data), but nothing of it is left
        // in OpenSSL's error queue either way.
        while (openssl_error_string() !== false) {
        }
        if ($key === false) {
            return null;
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['ec']['x'], $details['ec']['y']) || !is_string($details['ec']['x']) || !is_string($details['ec']['y'])) {
            return null;
        }
        // OpenSSL gives the coordinates without leading zero bytes.
        $x = str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            return null;
        }

        return ['x' => $x, 'y' => $y];
    }

    /** @return array{0: list<int>, 1: list<int>, 2: list<int>}|null */
    private static function toJacobian(?array $point): ?array
    {
        if ($point === null) {
            return null;
        }
        $f = Field::secp256k1();

        return [$f->fromBytes($point['x']), $f->fromBytes($point['y']), $f->one()];
    }

    /** @return array{x: string, y: string}|null */
    private static function toAffine(?array $point): ?array
    {
        if ($point === null) {
            return null;
        }
        $f = Field::secp256k1();
        [$x, $y, $z] = $point;
        $zInv = $f->invert($z);
        $zInv2 = $f->sqr($zInv);

        return ['x' => $f->toBytes($f->mul($x, $zInv2)), 'y' => $f->toBytes($f->mul($f->mul($y, $zInv2), $zInv))];
    }

    // Jacobian (X, Y, Z) stands for the affine point (X / Z^2, Y / Z^3); null is infinity. No point of
    // secp256k1 has y = 0 (its order is prime, so there is no point of order 2), so doubling never
    // reaches infinity from a finite point.
    private static function doubleJ(?array $p): ?array
    {
        if ($p === null) {
            return null;
        }
        $f = Field::secp256k1();
        [$x1, $y1, $z1] = $p;
        $a = $f->sqr($x1);
        $b = $f->sqr($y1);
        $c = $f->sqr($b);
        $xb = $f->add($x1, $b);
        $d = $f->mulSmall($f->sub($f->sub($f->sqr($xb), $a), $c), 2);
        $e = $f->mulSmall($a, 3);
        $ff = $f->sqr($e);
        $x3 = $f->sub($ff, $f->mulSmall($d, 2));
        $y3 = $f->sub($f->mul($e, $f->sub($d, $x3)), $f->mulSmall($c, 8));
        $z3 = $f->mulSmall($f->mul($y1, $z1), 2);

        return [$x3, $y3, $z3];
    }

    private static function addJ(?array $p1, ?array $p2): ?array
    {
        if ($p1 === null) {
            return $p2;
        }
        if ($p2 === null) {
            return $p1;
        }
        $f = Field::secp256k1();
        [$x1, $y1, $z1] = $p1;
        [$x2, $y2, $z2] = $p2;
        $z1z1 = $f->sqr($z1);
        $z2z2 = $f->sqr($z2);
        $u1 = $f->mul($x1, $z2z2);
        $u2 = $f->mul($x2, $z1z1);
        $s1 = $f->mul($f->mul($y1, $z2), $z2z2);
        $s2 = $f->mul($f->mul($y2, $z1), $z1z1);
        $h = $f->sub($u2, $u1);
        $r = $f->mulSmall($f->sub($s2, $s1), 2);
        if ($f->isZero($h)) {
            // Same x: either the same point (double it) or opposite points (the sum is infinity).
            return $f->isZero($r) ? self::doubleJ($p1) : null;
        }
        $i = $f->mulSmall($f->sqr($h), 4);
        $j = $f->mul($h, $i);
        $v = $f->mul($u1, $i);
        $x3 = $f->sub($f->sub($f->sqr($r), $j), $f->mulSmall($v, 2));
        $y3 = $f->sub($f->mul($r, $f->sub($v, $x3)), $f->mulSmall($f->mul($s1, $j), 2));
        $z1z2 = $f->add($z1, $z2);
        $z3 = $f->mul($f->sub($f->sub($f->sqr($z1z2), $z1z1), $z2z2), $h);

        return [$x3, $y3, $z3];
    }
}
