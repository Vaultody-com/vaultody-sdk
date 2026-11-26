<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Arithmetic modulo the field prime of one of the two curves addresses are derived on, in plain PHP
 * integers: PHP has no big integers without the gmp or bcmath extensions, and this package uses only
 * extensions every PHP build ships.
 *
 * Both primes are just below a power of two, p = 2^bits - c with a small c:
 *  - secp256k1: 2^256 - 2^32 - 977;
 *  - ed25519:   2^255 - 19.
 * That makes reduction cheap: whatever lies above bit 264 is multiplied by 2^264 mod p, a small number,
 * and added back in ("folded").
 *
 * An element is a list of 11 limbs of 24 bits, least significant first, so a value below 2^264. Values
 * are kept only partly reduced (below 2^264, not below p) between operations, and made canonical (below
 * p) only where they are compared, tested or encoded. 24-bit limbs keep every intermediate sum inside
 * PHP's signed 64-bit integers: a product column is at most 11 * 2^48 < 2^52.
 *
 * Only public keys pass through here, so nothing needs to run in constant time.
 */
final class Field
{
    private const LIMBS = 11;
    private const LIMB_BITS = 24;
    private const MASK = 0xFFFFFF;
    // Number of folding rounds after which a value is certainly below 2^264; more means a bug.
    private const MAX_FOLDS = 8;

    private static ?self $secp256k1 = null;
    private static ?self $ed25519 = null;

    /** @var list<int> */
    private readonly array $one;
    /** @var list<int> */
    private readonly array $zero;
    /** @var list<int> */
    private readonly array $prime;
    private readonly string $inverseExponent;

    /**
     * @param int $bits p = 2^bits - $c
     * @param int $c
     * @param int $fold0 the low limb of 2^264 mod p
     * @param int $fold1 the next limb of 2^264 mod p
     */
    private function __construct(
        private readonly int $bits,
        private readonly int $c,
        private readonly int $fold0,
        private readonly int $fold1,
        string $primeHex,
        string $inverseExponentHex,
    ) {
        $this->zero = array_fill(0, self::LIMBS, 0);
        $one = $this->zero;
        $one[0] = 1;
        $this->one = $one;
        $this->prime = self::limbsOf((string) hex2bin($primeHex));
        $this->inverseExponent = (string) hex2bin($inverseExponentHex);
    }

    /** The field of secp256k1, p = 2^256 - 2^32 - 977. */
    public static function secp256k1(): self
    {
        // 2^264 mod p = 2^8 * (2^32 + 977) = 2^40 + 250112: limb 0 is 250112, limb 1 is 2^40 / 2^24.
        return self::$secp256k1 ??= new self(
            256,
            0x1000003D1,
            250112,
            65536,
            'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
            'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d',
        );
    }

    /** The field of ed25519, p = 2^255 - 19. */
    public static function ed25519(): self
    {
        // 2^264 mod p = 2^9 * 19 = 9728.
        return self::$ed25519 ??= new self(
            255,
            19,
            9728,
            0,
            '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
            '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb',
        );
    }

    /** @return list<int> */
    public function zero(): array
    {
        return $this->zero;
    }

    /** @return list<int> */
    public function one(): array
    {
        return $this->one;
    }

    /**
     * Big-endian bytes (at most 33) to an element. The value is taken as it is, not reduced: any value
     * below 2^264 stands for itself modulo p.
     *
     * @return list<int>
     */
    public function fromBytes(string $bytes): array
    {
        if (strlen($bytes) > 33) {
            throw new \LengthException('a field element is at most 33 bytes here');
        }

        return self::limbsOf($bytes);
    }

    /** An element as 32 big-endian bytes of its canonical value (below p). */
    public function toBytes(array $a): string
    {
        $limbs = $this->canonical($a);
        $bytes = '';
        for ($i = self::LIMBS - 1; $i >= 0; $i--) {
            $bytes .= chr(($limbs[$i] >> 16) & 0xFF) . chr(($limbs[$i] >> 8) & 0xFF) . chr($limbs[$i] & 0xFF);
        }

        // 11 limbs are 33 bytes; a canonical value fits in the low 32.
        return substr($bytes, 1);
    }

    /** @return list<int> */
    public function fromInt(int $value): array
    {
        if ($value < 0) {
            throw new \RangeError('only non-negative integers');
        }
        $limbs = $this->zero;
        for ($i = 0; $i < self::LIMBS && $value > 0; $i++) {
            $limbs[$i] = $value & self::MASK;
            $value >>= self::LIMB_BITS;
        }

        return $limbs;
    }

    /** @return list<int> */
    public function add(array $a, array $b): array
    {
        $t = [];
        for ($i = 0; $i < self::LIMBS; $i++) {
            $t[$i] = $a[$i] + $b[$i];
        }

        return $this->normalize($t);
    }

    /** @return list<int> */
    public function sub(array $a, array $b): array
    {
        $t = [];
        for ($i = 0; $i < self::LIMBS; $i++) {
            $t[$i] = $a[$i] - $b[$i];
        }

        return $this->normalize($t);
    }

    /** @return list<int> a * k for a small non-negative k (below 2^24) */
    public function mulSmall(array $a, int $k): array
    {
        $t = [];
        for ($i = 0; $i < self::LIMBS; $i++) {
            $t[$i] = $a[$i] * $k;
        }

        return $this->normalize($t);
    }

    /** @return list<int> */
    public function neg(array $a): array
    {
        return $this->sub($this->zero, $a);
    }

    /** @return list<int> */
    public function mul(array $a, array $b): array
    {
        $t = array_fill(0, 2 * self::LIMBS, 0);
        for ($i = 0; $i < self::LIMBS; $i++) {
            $ai = $a[$i];
            if ($ai === 0) {
                continue;
            }
            $t[$i] += $ai * $b[0];
            $t[$i + 1] += $ai * $b[1];
            $t[$i + 2] += $ai * $b[2];
            $t[$i + 3] += $ai * $b[3];
            $t[$i + 4] += $ai * $b[4];
            $t[$i + 5] += $ai * $b[5];
            $t[$i + 6] += $ai * $b[6];
            $t[$i + 7] += $ai * $b[7];
            $t[$i + 8] += $ai * $b[8];
            $t[$i + 9] += $ai * $b[9];
            $t[$i + 10] += $ai * $b[10];
        }

        return $this->normalize($t);
    }

    /** @return list<int> */
    public function sqr(array $a): array
    {
        return $this->mul($a, $a);
    }

    /**
     * a^e, with e given as big-endian bytes, by a 4-bit fixed window.
     *
     * @return list<int>
     */
    public function pow(array $a, string $exponent): array
    {
        $table = [$this->one, $a];
        for ($i = 2; $i < 16; $i++) {
            $table[$i] = $this->mul($table[$i - 1], $a);
        }

        $result = null;
        $length = strlen($exponent);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($exponent[$i]);
            foreach ([$byte >> 4, $byte & 0x0F] as $nibble) {
                if ($result === null) {
                    if ($nibble !== 0) {
                        $result = $table[$nibble];
                    }
                    continue;
                }
                $result = $this->sqr($this->sqr($this->sqr($this->sqr($result))));
                if ($nibble !== 0) {
                    $result = $this->mul($result, $table[$nibble]);
                }
            }
        }

        return $result ?? $this->one;
    }

    /**
     * The inverse of a non-zero element, by Fermat's little theorem: a^(p - 2).
     *
     * @return list<int>
     */
    public function invert(array $a): array
    {
        if ($this->isZero($a)) {
            throw new \DivisionByZeroError('zero has no inverse');
        }

        return $this->pow($a, $this->inverseExponent);
    }

    public function isZero(array $a): bool
    {
        return $this->canonical($a) === $this->zero;
    }

    public function equals(array $a, array $b): bool
    {
        return $this->canonical($a) === $this->canonical($b);
    }

    /** Whether the canonical value is odd: the "sign" both curves encode. */
    public function isOdd(array $a): bool
    {
        return ($this->canonical($a)[0] & 1) === 1;
    }

    /**
     * The one representative below p.
     *
     * @return list<int>
     */
    public function canonical(array $a): array
    {
        $t = $a;
        // The bits from position `bits` up are worth c each (2^bits = c mod p). Twice brings the value
        // below 2^bits; then it is at most one p too large.
        $topBit = $this->bits - self::LIMB_BITS * (self::LIMBS - 1);
        for ($round = 0; $round < 2; $round++) {
            $high = $t[self::LIMBS - 1] >> $topBit;
            $t[self::LIMBS - 1] &= (1 << $topBit) - 1;
            $t[0] += $high * $this->c;
            for ($i = 0; $i < self::LIMBS - 1; $i++) {
                $t[$i + 1] += $t[$i] >> self::LIMB_BITS;
                $t[$i] &= self::MASK;
            }
        }
        if ($this->compare($t, $this->prime) >= 0) {
            $borrow = 0;
            for ($i = 0; $i < self::LIMBS; $i++) {
                $v = $t[$i] - $this->prime[$i] - $borrow;
                $borrow = $v < 0 ? 1 : 0;
                $t[$i] = $v & self::MASK;
            }
        }

        return $t;
    }

    /**
     * Carries every limb into 24 bits and folds whatever lies at 2^264 and above back in, until the
     * value is below 2^264. Limbs may be negative on the way in (after a subtraction): the arithmetic
     * shift and mask then borrow from the next limb, and a negative total is brought back up by folding.
     *
     * @param array<int, int> $t
     * @return list<int>
     */
    private function normalize(array $t): array
    {
        $count = count($t);
        // Carry through every limb given, then fold each limb above the 11th down, highest first: a limb
        // at position k >= 11 is worth limb * 2^264 * 2^(24 (k - 11)), and 2^264 = fold1 * 2^24 + fold0.
        for ($i = 0; $i < $count - 1; $i++) {
            $t[$i + 1] += $t[$i] >> self::LIMB_BITS;
            $t[$i] &= self::MASK;
        }
        for ($k = $count - 1; $k >= self::LIMBS; $k--) {
            $v = $t[$k];
            if ($v === 0) {
                continue;
            }
            $t[$k - self::LIMBS] += $v * $this->fold0;
            $t[$k - self::LIMBS + 1] += $v * $this->fold1;
        }

        for ($round = 0; ; $round++) {
            if ($round === self::MAX_FOLDS) {
                throw new \LogicException('field reduction did not settle');
            }
            $carry = 0;
            for ($i = 0; $i < self::LIMBS; $i++) {
                $v = $t[$i] + $carry;
                $carry = $v >> self::LIMB_BITS;
                $t[$i] = $v & self::MASK;
            }
            if ($carry === 0) {
                break;
            }
            $t[0] += $carry * $this->fold0;
            $t[1] += $carry * $this->fold1;
        }

        $out = [];
        for ($i = 0; $i < self::LIMBS; $i++) {
            $out[] = $t[$i];
        }

        return $out;
    }

    private function compare(array $a, array $b): int
    {
        for ($i = self::LIMBS - 1; $i >= 0; $i--) {
            if ($a[$i] !== $b[$i]) {
                return $a[$i] < $b[$i] ? -1 : 1;
            }
        }

        return 0;
    }

    /** @return list<int> big-endian bytes (at most 33) as 11 limbs */
    private static function limbsOf(string $bytes): array
    {
        $padded = str_pad($bytes, 33, "\0", STR_PAD_LEFT);
        $limbs = [];
        for ($i = 0; $i < self::LIMBS; $i++) {
            // Limb 0 is the last three bytes, limb 10 the first three.
            $offset = 30 - 3 * $i;
            $limbs[] = (ord($padded[$offset]) << 16) | (ord($padded[$offset + 1]) << 8) | ord($padded[$offset + 2]);
        }

        return $limbs;
    }
}
