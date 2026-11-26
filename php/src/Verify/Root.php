<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * One trusted root: its id (the lowercase hex SHA-256 of its SubjectPublicKeyInfo DER) and the key that
 * checks certificates.
 */
final class Root
{
    public function __construct(
        public readonly string $rootId,
        public readonly \OpenSSLAsymmetricKey $key,
    ) {
    }
}
