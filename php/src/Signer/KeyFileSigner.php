<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Signer;

use Vaultody\Sdk\Verify\SigningKey;

/**
 * Signs with a private key read from a PEM file or text (PKCS#8 or SEC1, Ed25519 or P-256, unencrypted). The
 * key is held in this object for the life of the process; use a CallableSigner with a KMS to avoid that.
 */
final class KeyFileSigner implements RequestSigner
{
    private function __construct(private readonly SigningKey $key)
    {
    }

    /** @throws \Vaultody\Sdk\Verify\SigningKeyError|\Vaultody\Sdk\Verify\UsageError */
    public static function fromFile(string $path): self
    {
        return new self(SigningKey::readFile($path, 'private'));
    }

    /** @throws \Vaultody\Sdk\Verify\SigningKeyError */
    public static function fromPem(#[\SensitiveParameter] string $pem): self
    {
        return new self(SigningKey::read($pem, 'private'));
    }

    public function algorithm(): string
    {
        return $this->key->algorithm;
    }

    public function publicKeyPem(): string
    {
        return $this->key->publicKeyPem();
    }

    public function fingerprint(): string
    {
        return $this->key->fingerprint;
    }

    public function sign(string $message): string
    {
        return $this->key->sign($message);
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['algorithm' => $this->key->algorithm, 'fingerprint' => $this->key->fingerprint];
    }
}
