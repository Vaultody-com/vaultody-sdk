<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * The little DER reading the key formats need: a tag, a length and the contents, strictly (definite
 * lengths in their shortest form only). Not a general ASN.1 parser.
 *
 * @internal
 */
final class Der
{
    public const SEQUENCE = 0x30;
    public const INTEGER = 0x02;
    public const BIT_STRING = 0x03;
    public const OCTET_STRING = 0x04;
    public const OID = 0x06;

    /**
     * Reads one element at $offset and moves $offset past it.
     *
     * @return array{int, string} the tag and the contents
     * @throws \UnexpectedValueException malformed DER
     */
    public static function read(string $der, int &$offset): array
    {
        $length = strlen($der);
        if ($offset + 2 > $length) {
            throw new \UnexpectedValueException('truncated DER');
        }
        $tag = ord($der[$offset]);
        $size = ord($der[$offset + 1]);
        $offset += 2;
        if ($size & 0x80) {
            $count = $size & 0x7f;
            if ($count === 0 || $count > 3 || $offset + $count > $length) {
                throw new \UnexpectedValueException('unsupported DER length');
            }
            $size = 0;
            for ($i = 0; $i < $count; $i++) {
                $size = ($size << 8) | ord($der[$offset + $i]);
            }
            $offset += $count;
            if ($size < 0x80 || ($count > 1 && $size < (1 << (8 * ($count - 1))))) {
                throw new \UnexpectedValueException('DER length not in its shortest form');
            }
        }
        if ($offset + $size > $length) {
            throw new \UnexpectedValueException('truncated DER');
        }
        $contents = substr($der, $offset, $size);
        $offset += $size;

        return [$tag, $contents];
    }

    /**
     * Reads a whole element of the given tag that must fill $der exactly.
     *
     * @throws \UnexpectedValueException
     */
    public static function only(string $der, int $tag): string
    {
        $offset = 0;
        [$found, $contents] = self::read($der, $offset);
        if ($found !== $tag || $offset !== strlen($der)) {
            throw new \UnexpectedValueException('unexpected DER structure');
        }

        return $contents;
    }

    /**
     * The elements of a SEQUENCE's contents, in order.
     *
     * @return list<array{int, string}>
     * @throws \UnexpectedValueException
     */
    public static function elements(string $contents): array
    {
        $offset = 0;
        $elements = [];
        while ($offset < strlen($contents)) {
            $elements[] = self::read($contents, $offset);
        }

        return $elements;
    }

    /** A DER element from a tag and its contents. */
    public static function encode(int $tag, string $contents): string
    {
        $size = strlen($contents);
        if ($size < 0x80) {
            return chr($tag) . chr($size) . $contents;
        }
        $bytes = ltrim(pack('N', $size), "\0");

        return chr($tag) . chr(0x80 | strlen($bytes)) . $bytes . $contents;
    }
}
