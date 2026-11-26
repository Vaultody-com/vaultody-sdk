<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Base58 and Base58Check, as Bitcoin defines them (the reference is base58.cpp in Bitcoin Core): the
 * bytes read as one big-endian number written in base 58, each leading zero byte written as the
 * alphabet's first character. Base58Check appends the first 4 bytes of SHA-256(SHA-256(payload)).
 *
 * XRP uses the same scheme with its own alphabet, which starts with "r".
 *
 * The conversion runs digit by digit over byte arrays, as base58.cpp does, so it needs no big integers.
 */
final class Base58
{
    public const BITCOIN_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    public const RIPPLE_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

    /** Bytes to Base58 text. */
    public static function encode(string $bytes, string $alphabet = self::BITCOIN_ALPHABET): string
    {
        $length = strlen($bytes);
        $zeros = 0;
        while ($zeros < $length && $bytes[$zeros] === "\0") {
            $zeros++;
        }

        // Base-58 digits, least significant first.
        $digits = [];
        for ($i = $zeros; $i < $length; $i++) {
            $carry = ord($bytes[$i]);
            foreach ($digits as $j => $digit) {
                $carry += $digit << 8;
                $digits[$j] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
            while ($carry > 0) {
                $digits[] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
        }

        $text = str_repeat($alphabet[0], $zeros);
        for ($j = count($digits) - 1; $j >= 0; $j--) {
            $text .= $alphabet[$digits[$j]];
        }

        return $text;
    }

    /** Base58 text to bytes, or null when it holds a character outside the alphabet. */
    public static function decode(string $text, string $alphabet = self::BITCOIN_ALPHABET): ?string
    {
        $length = strlen($text);
        $zeros = 0;
        while ($zeros < $length && $text[$zeros] === $alphabet[0]) {
            $zeros++;
        }

        // Bytes, least significant first.
        $bytes = [];
        for ($i = $zeros; $i < $length; $i++) {
            $value = strpos($alphabet, $text[$i]);
            if ($value === false) {
                return null;
            }
            $carry = $value;
            foreach ($bytes as $j => $byte) {
                $carry += $byte * 58;
                $bytes[$j] = $carry & 0xFF;
                $carry >>= 8;
            }
            while ($carry > 0) {
                $bytes[] = $carry & 0xFF;
                $carry >>= 8;
            }
        }

        $out = str_repeat("\0", $zeros);
        for ($j = count($bytes) - 1; $j >= 0; $j--) {
            $out .= chr($bytes[$j]);
        }

        return $out;
    }

    /** Payload to Base58Check text. */
    public static function encodeCheck(string $payload, string $alphabet = self::BITCOIN_ALPHABET): string
    {
        return self::encode($payload . self::checksum($payload), $alphabet);
    }

    /** Base58Check text to its payload, or null when it is not Base58 or its checksum does not match. */
    public static function decodeCheck(string $text, string $alphabet = self::BITCOIN_ALPHABET): ?string
    {
        $bytes = self::decode($text, $alphabet);
        if ($bytes === null || strlen($bytes) < 4) {
            return null;
        }
        $payload = substr($bytes, 0, -4);

        return hash_equals(self::checksum($payload), substr($bytes, -4)) ? $payload : null;
    }

    private static function checksum(string $payload): string
    {
        return substr(hash('sha256', hash('sha256', $payload, true), true), 0, 4);
    }
}
