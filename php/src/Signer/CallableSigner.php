<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Signer;

/**
 * A signer whose private key lives elsewhere: $sign receives the message and returns the signature. For
 * P-256 the callable signs SHA-256 of the message (most KMS APIs take that digest: AWS KMS with
 * MessageType DIGEST, GCP KMS, Vault Transit with prehashed=true) unless $digestOnly is false, and may
 * return DER or P1363. For Ed25519 it signs the message itself and returns 64 bytes.
 */
final class CallableSigner implements RequestSigner
{
    /** @var callable(string): string */
    private $sign;

    /**
     * @param 'ed25519'|'p-256' $algorithm
     * @param callable(string): string $sign
     * @param bool $digestOnly P-256 only: pass SHA-256(message) instead of the message
     */
    public function __construct(
        private readonly string $algorithm,
        private readonly string $publicKeyPem,
        callable $sign,
        private readonly bool $digestOnly = true,
    ) {
        $this->sign = $sign;
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function publicKeyPem(): string
    {
        return $this->publicKeyPem;
    }

    public function sign(string $message): string
    {
        $input = $this->algorithm === 'p-256' && $this->digestOnly ? hash('sha256', $message, true) : $message;

        return ($this->sign)($input);
    }
}
