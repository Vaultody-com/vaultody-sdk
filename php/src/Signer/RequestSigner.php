<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Signer;

/**
 * What signs x-api-keypair-sign: a key file, or anything that holds the private key elsewhere (a KMS, an
 * HSM, HashiCorp Vault), so it never has to sit in this process's memory.
 *
 * The SDK computes x-api-keypair-id from publicKeyPem() itself, converts a P-256 signature given as IEEE
 * P1363 (r || s, 64 bytes) to DER, checks the length of an Ed25519 one, and by default verifies every
 * signature against the public key before sending, so a wrong key fails here and not as a storm of 401s.
 */
interface RequestSigner
{
    /** 'ed25519' or 'p-256' */
    public function algorithm(): string;

    /** The public key in SPKI PEM ("BEGIN PUBLIC KEY"), as registered on the API key. */
    public function publicKeyPem(): string;

    /**
     * Signs the key-pair request string. Ed25519: the raw 64-byte signature. P-256: ECDSA over SHA-256 of
     * the message, as DER or as P1363 r || s.
     */
    public function sign(string $message): string;
}
