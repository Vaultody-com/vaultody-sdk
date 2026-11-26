<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Reads an extended public key: version (4) | depth (1) | parent fingerprint (4) | child number (4) |
 * chain code (32) | key data (33), Base58Check encoded.
 *
 * Only the chain code and the key are used. The server rewrites the version bytes to "xpub" before it
 * derives, and older vaults store keys at depth 1 with a parent fingerprint, so version, depth,
 * fingerprint and child number are all ignored here.
 */
final class ExtendedPublicKey
{
    private const EXTENDED_KEY_BYTES = 78;

    /**
     * @param string $algorithm Chains::ECDSA or Chains::EDDSA
     * @throws KeyDerivationError when the text is not an extended key of that algorithm
     */
    public static function parse(string $text, string $algorithm): DerivedNode
    {
        $bytes = Base58::decodeCheck($text);
        if ($bytes === null) {
            throw new KeyDerivationError('not a Base58Check string');
        }
        if (strlen($bytes) !== self::EXTENDED_KEY_BYTES) {
            throw new KeyDerivationError(sprintf('an extended key is %d bytes, this one is %d', self::EXTENDED_KEY_BYTES, strlen($bytes)));
        }
        $chainCode = substr($bytes, 13, 32);
        $keyData = substr($bytes, 45);

        if ($algorithm === Chains::ECDSA) {
            // A compressed secp256k1 point: 02 or 03, then x.
            return new DerivedNode($algorithm, $keyData, Secp256k1::decompress($keyData), $chainCode);
        }
        if ($algorithm === Chains::EDDSA) {
            // Vaultody stores an ed25519 key as 00 followed by the 32-byte encoded point.
            if ($keyData[0] !== "\0") {
                throw new KeyDerivationError('an EdDSA extended key holds 00 followed by the 32-byte public key');
            }
            $key = substr($keyData, 1);

            return new DerivedNode($algorithm, $key, Ed25519::decode($key), $chainCode);
        }

        throw new KeyDerivationError('unknown algorithm');
    }
}
