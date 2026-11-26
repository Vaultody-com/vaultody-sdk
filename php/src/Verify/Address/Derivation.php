<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Public-key derivation below a vault's extended public key, the same way the Vaultody server derives
 * every address: path m/{account}/{0 deposit | 1 change}/{index}, with no hardened steps.
 *
 * - ECDSA (secp256k1) keys use standard BIP32 public derivation (CKDpub), with the `hdkey` library's
 *   handling of an invalid child (see deriveEcdsaChild).
 * - EdDSA (ed25519) keys use Vaultody's own scheme from its xpub utilities library (deriveEddsaChild).
 *   BIP32 does not define derivation for ed25519 public keys.
 */
final class Derivation
{
    // Indexes at or above 2^31 are hardened, which needs the private key.
    public const MAX_INDEX = 0x7fffffff;

    /** One child step for either algorithm. */
    public static function deriveChild(DerivedNode $parent, int $index): DerivedNode
    {
        return $parent->algorithm === Chains::ECDSA
            ? self::deriveEcdsaChild($parent, $index)
            : self::deriveEddsaChild($parent, $index);
    }

    /**
     * Derives along a list of non-hardened indexes.
     *
     * @param list<int> $indexes
     */
    public static function derivePath(DerivedNode $node, array $indexes): DerivedNode
    {
        foreach ($indexes as $index) {
            $node = self::deriveChild($node, $index);
        }

        return $node;
    }

    /**
     * BIP32 CKDpub: I = HMAC-SHA512(chainCode, serP(K) || ser32(index)), child K = parse256(I_L)*G + K,
     * child chain code = I_R.
     *
     * When I_L is not below the curve order, or the child is the point at infinity, BIP32 calls the index
     * invalid. The `hdkey` library the server uses then derives index + 1 in its place, and so on; the
     * address keeps the requested index in its path. This does the same, so both always land on the same
     * key. Past 2^31 - 1 the next index would be hardened, which `hdkey` refuses, and so does this.
     *
     * Each invalid case has a chance of about 2^-127, so it never happens in practice.
     *
     * @param (callable(string, string): string)|null $hmacSha512 replaced only by tests, to force the
     *        invalid cases: gets the key and the data, returns the 64-byte MAC
     * @throws KeyDerivationError past the last non-hardened index
     */
    public static function deriveEcdsaChild(DerivedNode $parent, int $index, ?callable $hmacSha512 = null): DerivedNode
    {
        if ($index < 0) {
            throw new KeyDerivationError('a child index is not negative');
        }
        $hmacSha512 ??= static fn (string $key, string $data): string => hash_hmac('sha512', $data, $key, true);
        $order = Secp256k1::order();

        for ($candidate = $index; ; $candidate++) {
            if ($candidate > self::MAX_INDEX) {
                throw new KeyDerivationError('no valid non-hardened child at or after this index');
            }
            $i = $hmacSha512($parent->chainCode, $parent->key . pack('N', $candidate));
            $il = substr($i, 0, 32);
            // Equal-length binary strings compare byte by byte, as unsigned numbers.
            if (strcmp($il, $order) >= 0) {
                continue;
            }
            // I_L = 0 adds nothing (0 * G is the point at infinity), as in the reference.
            $tweak = trim($il, "\0") === '' ? null : Secp256k1::multiplyG($il);
            $point = Secp256k1::add($tweak, $parent->point);
            if ($point === null) {
                continue;
            }

            return new DerivedNode(Chains::ECDSA, Secp256k1::compress($point), $point, substr($i, 32, 32));
        }
    }

    /**
     * Vaultody's ed25519 public derivation (as the server's xpub utilities derive):
     *
     *   k          = HMAC-SHA256(chainCode, 0x02 || key || index as 4 bytes LITTLE-endian),
     *                read as a BIG-endian integer and used unreduced
     *   child key  = encode(k * decode(key))
     *   chain code = HMAC-SHA256(chainCode, 0x03 || key || index as 4 bytes little-endian)
     *
     * The byte orders are as the server has them: the index is written little-endian, and the HMAC output
     * is read big-endian (as bn.js reads a Buffer).
     *
     * @throws KeyDerivationError for an index above 2^31 - 1
     */
    public static function deriveEddsaChild(DerivedNode $parent, int $index): DerivedNode
    {
        if ($index < 0 || $index > self::MAX_INDEX) {
            throw new KeyDerivationError('hardened derivation is not possible from a public key');
        }
        $indexBytes = pack('V', $index);
        $k = hash_hmac('sha256', "\x02" . $parent->key . $indexBytes, $parent->chainCode, true);
        $chainCode = hash_hmac('sha256', "\x03" . $parent->key . $indexBytes, $parent->chainCode, true);
        $point = Ed25519::multiply($k, $parent->point);

        return new DerivedNode(Chains::EDDSA, Ed25519::encode($point), $point, $chainCode);
    }
}
