<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Bech32 encoding of version 0 segregated-witness addresses, as BIP173 defines it
 * (github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). Only version 0 is needed: the native SegWit
 * addresses Vaultody issues (P2WPKH) are all version 0, and versions 1 and up use the different Bech32m
 * checksum from BIP350.
 */
final class Bech32
{
    public const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    private const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    /**
     * BIP173's checksum: a BCH code over 5-bit values, computed with the reference code's polymod.
     *
     * @param list<int> $values
     */
    public static function polymod(array $values): int
    {
        $chk = 1;
        foreach ($values as $value) {
            $top = $chk >> 25;
            $chk = (($chk & 0x1ffffff) << 5) ^ $value;
            for ($i = 0; $i < 5; $i++) {
                if ((($top >> $i) & 1) === 1) {
                    $chk ^= self::GENERATOR[$i];
                }
            }
        }

        return $chk;
    }

    /** @return list<int> */
    public static function hrpExpand(string $hrp): array
    {
        $high = [];
        $low = [];
        foreach (str_split($hrp) as $char) {
            $high[] = ord($char) >> 5;
            $low[] = ord($char) & 31;
        }

        return [...$high, 0, ...$low];
    }

    /**
     * Regroups bits, for example 8-bit bytes into 5-bit values, padding the last group with zeros.
     *
     * @param list<int> $data
     * @return list<int>
     */
    public static function convertBits(array $data, int $fromBits, int $toBits): array
    {
        $acc = 0;
        $bits = 0;
        $out = [];
        $maxValue = (1 << $toBits) - 1;
        foreach ($data as $value) {
            $acc = ($acc << $fromBits) | $value;
            $bits += $fromBits;
            while ($bits >= $toBits) {
                $bits -= $toBits;
                $out[] = ($acc >> $bits) & $maxValue;
            }
            $acc &= (1 << $bits) - 1;
        }
        if ($bits > 0) {
            $out[] = ($acc << ($toBits - $bits)) & $maxValue;
        }

        return $out;
    }

    /**
     * Human-readable part plus 5-bit data to a Bech32 string (BIP173 checksum constant 1).
     *
     * @param list<int> $data
     */
    public static function encode(string $hrp, array $data): string
    {
        $mod = self::polymod([...self::hrpExpand($hrp), ...$data, 0, 0, 0, 0, 0, 0]) ^ 1;
        $text = $hrp . '1';
        foreach ($data as $value) {
            $text .= self::CHARSET[$value];
        }
        for ($i = 0; $i < 6; $i++) {
            $text .= self::CHARSET[($mod >> (5 * (5 - $i))) & 31];
        }

        return $text;
    }

    /** A version 0 witness program (20 or 32 bytes) to its lowercase address. */
    public static function segwitV0Address(string $hrp, string $program): string
    {
        if (strlen($program) !== 20 && strlen($program) !== 32) {
            throw new \LengthException('a version 0 witness program is 20 or 32 bytes');
        }

        return self::encode($hrp, [0, ...self::convertBits(array_values(unpack('C*', $program) ?: []), 8, 5)]);
    }
}
