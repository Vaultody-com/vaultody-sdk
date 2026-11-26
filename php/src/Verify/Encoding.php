<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * The strict readings every verifier of the SDK applies, so that one header value means the same thing in
 * every language and to the gateway.
 *
 * @internal
 */
final class Encoding
{
    // 2^53 - 1: the largest integer JavaScript holds exactly. Larger decimals are refused everywhere, so a
    // value the Node verifier would round is not accepted here either.
    private const MAX_SAFE_INTEGER = 9007199254740991;

    /**
     * Standard base64 with padding, accepted only in the one form an encoder prints: decoding and encoding
     * again must give the same text. That refuses whitespace, the URL-safe alphabet, missing padding and
     * leftover bits, any of which would let several header values decode to the same bytes.
     *
     * @return string|null the bytes, or null when the text is not canonical base64
     */
    public static function strictBase64(mixed $text): ?string
    {
        if (!is_string($text) || $text === '') {
            return null;
        }
        $bytes = base64_decode($text, true);

        return $bytes !== false && base64_encode($bytes) === $text ? $bytes : null;
    }

    /**
     * Unix seconds in canonical decimal: no sign, no leading zero, no fraction or exponent, ASCII digits
     * only, at most 2^53 - 1.
     */
    public static function strictSeconds(mixed $text): ?int
    {
        if (!is_string($text) || preg_match('/^(0|[1-9][0-9]*)$/D', $text) !== 1 || strlen($text) > 16) {
            return null;
        }
        $value = (int) $text;

        return $value <= self::MAX_SAFE_INTEGER ? $value : null;
    }

    /**
     * The raw bytes of a body. A PHP string already is the bytes; null is no body. Anything else, in
     * particular an already decoded JSON array, is refused: a signature covers the exact bytes on the wire,
     * and encoding decoded JSON again rarely gives the same bytes back.
     */
    public static function bytes(mixed $value, string $name): string
    {
        if ($value === null) {
            return '';
        }
        if (!is_string($value)) {
            throw new \InvalidArgumentException($name . ' must be the raw body bytes as a string; verify before decoding JSON');
        }

        return $value;
    }

    /**
     * Every value given for one header, matched case-insensitively. Headers are name => value or
     * name => list of values, as the transport collects them.
     *
     * @param array<array-key, mixed> $headers
     * @return list<mixed>
     */
    public static function headerValues(array $headers, string $name): array
    {
        $values = [];
        foreach ($headers as $key => $value) {
            if (!is_string($key) || strtolower($key) !== $name) {
                continue;
            }
            foreach (is_array($value) ? $value : [$value] as $one) {
                if ($one !== null) {
                    $values[] = $one;
                }
            }
        }

        return $values;
    }

    /**
     * Empties OpenSSL's error queue, which PHP keeps for the whole process: an error left there by one
     * call would otherwise surface in an unrelated later one.
     */
    public static function clearOpensslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // drained
        }
    }
}
