<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * One key in the derivation tree below a vault's extended public key: the public key as the server
 * stores it (33-byte compressed for ECDSA, 32 bytes for EdDSA), the same key as an affine point, and the
 * chain code its children are derived with.
 */
final class DerivedNode
{
    /**
     * @param string $algorithm Chains::ECDSA or Chains::EDDSA
     * @param string $key the public key bytes
     * @param array{x: string, y: string} $point the key as a curve point, coordinates as 32 big-endian bytes
     * @param string $chainCode 32 bytes
     */
    public function __construct(
        public readonly string $algorithm,
        public readonly string $key,
        public readonly array $point,
        public readonly string $chainCode,
    ) {
    }

    /** Keeps the chain code out of var_dump and print_r: with the key it derives every address. */
    public function __debugInfo(): array
    {
        return ['algorithm' => $this->algorithm, 'key' => bin2hex($this->key)];
    }
}
