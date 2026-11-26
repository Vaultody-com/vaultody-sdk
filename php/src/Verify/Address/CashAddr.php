<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * CashAddr, the Bitcoin Cash address format, as its specification defines it
 * (github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md). It uses the Bech32 character
 * set with a 40-bit checksum over the prefix and the payload. The payload is a version byte (type in the
 * high bits, hash size in the low three) followed by the hash. A 40-bit value fits a PHP integer.
 */
final class CashAddr
{
    public const TYPE_P2PKH = 0;
    public const TYPE_P2SH = 1;

    private const GENERATOR = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];

    // Hash size in bytes -> the size code in the low bits of the version byte.
    private const SIZE_CODES = [20 => 0, 24 => 1, 28 => 2, 32 => 3, 40 => 4, 48 => 5, 56 => 6, 64 => 7];

    /** @param list<int> $values */
    private static function polymod(array $values): int
    {
        $c = 1;
        foreach ($values as $value) {
            $c0 = $c >> 35;
            $c = (($c & 0x07ffffffff) << 5) ^ $value;
            for ($i = 0; $i < 5; $i++) {
                if ((($c0 >> $i) & 1) === 1) {
                    $c ^= self::GENERATOR[$i];
                }
            }
        }

        return $c ^ 1;
    }

    /**
     * @param string $prefix for example "bitcoincash" or "bchtest"
     * @param int $type 0 for P2PKH, 1 for P2SH (the format allows 0..15)
     * @return string "prefix:payload", lowercase
     */
    public static function encode(string $prefix, int $type, string $hash): string
    {
        $sizeCode = self::SIZE_CODES[strlen($hash)] ?? null;
        if ($sizeCode === null || $type < 0 || $type > 15) {
            throw new \InvalidArgumentException('unsupported CashAddr type or hash size');
        }
        $payload = Bech32::convertBits([($type << 3) | $sizeCode, ...array_values(unpack('C*', $hash) ?: [])], 8, 5);
        $prefixValues = array_map(static fn (string $char): int => ord($char) & 31, str_split($prefix));
        $mod = self::polymod([...$prefixValues, 0, ...$payload, 0, 0, 0, 0, 0, 0, 0, 0]);

        $text = $prefix . ':';
        foreach ($payload as $value) {
            $text .= Bech32::CHARSET[$value];
        }
        for ($i = 0; $i < 8; $i++) {
            $text .= Bech32::CHARSET[($mod >> (5 * (7 - $i))) & 31];
        }

        return $text;
    }
}
