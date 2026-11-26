<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Keccak-256, the hash Ethereum and Tron addresses use, written for this package so it needs no
 * dependency.
 *
 * It is NOT the same as SHA3-256, which PHP's hash extension does offer: both run the Keccak-f[1600]
 * permutation, but NIST changed the padding when it standardised SHA-3 (domain byte 0x06 instead of the
 * original 0x01), so the outputs differ. Ethereum fixed its address format before that change.
 *
 * The permutation follows the Keccak reference (keccak.team, "The Keccak reference", version 3.0,
 * sections 1.2 and 3), with the rotation offsets and round constants from its tables. A lane is one PHP
 * integer: 64 bits, read as signed, which changes nothing for XOR, AND and NOT; rotations mask off the
 * bits an arithmetic right shift copies in. The sponge takes the padding byte as a parameter, so the
 * tests can run it with the SHA-3 padding and compare it with PHP's own sha3-256 and sha3-512.
 */
final class Keccak
{
    private const ROUND_CONSTANTS_HEX = [
        '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000',
        '000000000000808b', '0000000080000001', '8000000080008081', '8000000000008009',
        '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
        '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003',
        '8000000000008002', '8000000000000080', '000000000000800a', '800000008000000a',
        '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
    ];

    // Rotation offset of lane (x, y), stored at index x + 5 * y.
    private const ROTATIONS = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];

    /** Keccak-256 as Ethereum uses it. */
    public static function keccak256(string $data): string
    {
        return self::sponge(136, 0x01, $data, 32);
    }

    /**
     * The Keccak sponge with capacity 1600 - 8 * rate bits.
     *
     * @param int $rate bytes absorbed per permutation (136 for Keccak-256 and SHA3-256)
     * @param int $paddingByte the first padding byte: 0x01 for original Keccak, 0x06 for SHA-3
     * @param int $outputLength bytes to squeeze out; at most $rate
     */
    public static function sponge(int $rate, int $paddingByte, string $data, int $outputLength): string
    {
        if ($rate <= 0 || $rate % 8 !== 0 || $rate >= 200 || $outputLength > $rate) {
            throw new \InvalidArgumentException('unsupported Keccak parameters');
        }
        $state = array_fill(0, 25, 0);
        $length = strlen($data);

        $offset = 0;
        for (; $offset + $rate <= $length; $offset += $rate) {
            self::absorbBlock($state, substr($data, $offset, $rate));
        }
        // pad10*1: the padding byte right after the message, and 0x80 in the last byte of the block.
        $last = str_pad(substr($data, $offset), $rate, "\0");
        $tail = $length - $offset;
        $last[$tail] = chr(ord($last[$tail]) ^ $paddingByte);
        $last[$rate - 1] = chr(ord($last[$rate - 1]) ^ 0x80);
        self::absorbBlock($state, $last);

        $out = '';
        for ($i = 0; $i < intdiv($rate, 8); $i++) {
            $out .= pack('P', $state[$i]);
        }

        return substr($out, 0, $outputLength);
    }

    /** @param list<int> $state */
    private static function absorbBlock(array &$state, string $block): void
    {
        $lanes = array_values((array) unpack('P*', $block));
        foreach ($lanes as $i => $lane) {
            $state[$i] ^= $lane;
        }
        self::permute($state);
    }

    private static function rotl(int $lane, int $n): int
    {
        if ($n === 0) {
            return $lane;
        }

        // ~(-1 << n) keeps the low n bits, without the overflow that (1 << n) - 1 has for n = 63.
        return ($lane << $n) | (($lane >> (64 - $n)) & ~(-1 << $n));
    }

    /**
     * Keccak-f[1600] on 25 lanes, in place.
     *
     * @param list<int> $state
     */
    private static function permute(array &$state): void
    {
        static $roundConstants = null;
        $roundConstants ??= array_map(
            static fn (string $hex): int => (int) unpack('J', (string) hex2bin($hex))[1],
            self::ROUND_CONSTANTS_HEX,
        );

        $c = [0, 0, 0, 0, 0];
        $b = array_fill(0, 25, 0);
        foreach ($roundConstants as $roundConstant) {
            // theta
            for ($x = 0; $x < 5; $x++) {
                $c[$x] = $state[$x] ^ $state[$x + 5] ^ $state[$x + 10] ^ $state[$x + 15] ^ $state[$x + 20];
            }
            for ($x = 0; $x < 5; $x++) {
                $d = $c[($x + 4) % 5] ^ self::rotl($c[($x + 1) % 5], 1);
                for ($y = 0; $y < 25; $y += 5) {
                    $state[$x + $y] ^= $d;
                }
            }
            // rho and pi: lane (x, y) moves to (y, 2x + 3y), rotated by its offset
            for ($x = 0; $x < 5; $x++) {
                for ($y = 0; $y < 5; $y++) {
                    $b[$y + 5 * ((2 * $x + 3 * $y) % 5)] = self::rotl($state[$x + 5 * $y], self::ROTATIONS[$x + 5 * $y]);
                }
            }
            // chi
            for ($y = 0; $y < 25; $y += 5) {
                for ($x = 0; $x < 5; $x++) {
                    $state[$x + $y] = $b[$x + $y] ^ (~$b[(($x + 1) % 5) + $y] & $b[(($x + 2) % 5) + $y]);
                }
            }
            // iota
            $state[0] ^= $roundConstant;
        }
    }
}
