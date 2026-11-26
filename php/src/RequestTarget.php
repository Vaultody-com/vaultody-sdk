<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

use Vaultody\Sdk\Exception\ParameterError;

/**
 * The request target (path and query) of a call, built so it is exactly what goes on the request line and
 * what is signed (test-vectors/path-encoding-v1.json). Everything outside the RFC 3986 unreserved set is
 * percent-encoded here, so the HTTP client has nothing left to normalise.
 */
final class RequestTarget
{
    // 2^53 - 1: integers are refused beyond what every SDK language holds exactly.
    private const MAX_SAFE_INTEGER = 9007199254740991;

    /** Every UTF-8 byte outside the unreserved set (A-Z a-z 0-9 - . _ ~) as %XX in uppercase hex, "/" included. */
    public static function percentEncode(string $text): string
    {
        return rawurlencode($text);
    }

    private static function isUtf8(string $text): bool
    {
        return preg_match('//u', $text) === 1;
    }

    private static function isSafeInteger(mixed $value): bool
    {
        return is_int($value) && $value <= self::MAX_SAFE_INTEGER && $value >= -self::MAX_SAFE_INTEGER;
    }

    private static function pathValue(string $name, mixed $value): string
    {
        if ($value === null) {
            throw new ParameterError('missing_path_param', $name . ' is required');
        }
        if (is_string($value)) {
            $text = $value;
        } elseif (self::isSafeInteger($value)) {
            $text = (string) $value;
        } else {
            throw new ParameterError('invalid_path_param', $name . ' must be a string or an integer');
        }
        // An empty segment, or a dot segment a URL would remove, changes the path that is signed.
        if ($text === '' || $text === '.' || $text === '..' || !self::isUtf8($text)) {
            throw new ParameterError('invalid_path_param', $name . ' must be a non-empty UTF-8 value other than "." and ".."');
        }

        return self::percentEncode($text);
    }

    private static function queryValue(string $name, mixed $value): string
    {
        if (is_string($value)) {
            if (!self::isUtf8($value)) {
                throw new ParameterError('invalid_query_param', $name . ' is not valid UTF-8');
            }

            return self::percentEncode($value);
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (self::isSafeInteger($value)) {
            return (string) $value;
        }

        throw new ParameterError('invalid_query_param', $name . ' must be a string, an integer or a boolean');
    }

    /**
     * @param string $template the operation path, such as "/vaults/{vaultId}/utxos"
     * @param array<string, mixed> $pathParams name => string or integer
     * @param list<array{string, mixed}> $query name/value pairs in the order to send; a null value leaves the pair out
     * @return string path and query, such as "/vaults/abc/utxos?limit=10"
     * @throws ParameterError missing_path_param, invalid_path_param or invalid_query_param
     */
    public static function build(string $template, array $pathParams, array $query = []): string
    {
        $path = (string) preg_replace_callback('/\{([A-Za-z0-9_]+)\}/', static fn (array $match): string => self::pathValue($match[1], $pathParams[$match[1]] ?? null), $template);
        $pairs = [];
        foreach ($query as [$name, $value]) {
            if ($value === null) {
                continue;
            }
            if (!self::isUtf8($name)) {
                throw new ParameterError('invalid_query_param', 'a query parameter name is not valid UTF-8');
            }
            $pairs[] = self::percentEncode($name) . '=' . self::queryValue($name, $value);
        }

        return $pairs === [] ? $path : $path . '?' . implode('&', $pairs);
    }
}
