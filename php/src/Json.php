<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

/**
 * JSON as the SDK reads it: big integers stay strings (amounts and ids are never rounded), and a JSON object
 * is told apart from a JSON array while the shape of an answer is checked, which PHP's associative decoding
 * can't do for an empty one.
 *
 * @internal
 */
final class Json
{
    /** The decoded value with objects as stdClass, or null when the text is not JSON. */
    public static function decode(string $text): mixed
    {
        try {
            return json_decode($text, false, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            return null;
        }
    }

    /** stdClass objects, at any depth, as associative arrays. */
    public static function toArray(mixed $value): mixed
    {
        if ($value instanceof \stdClass) {
            $value = get_object_vars($value);
        }
        if (is_array($value)) {
            foreach ($value as $key => $item) {
                $value[$key] = self::toArray($item);
            }
        }

        return $value;
    }

    /** UTF-8 JSON of a request body: slashes and Unicode as they are, no BOM. */
    public static function encode(mixed $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }
}
