<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * A key that can't be used. $code says why; the message adds a sentence for people and never holds key
 * material.
 */
final class SigningKeyError extends \RuntimeException
{
    /** Not one readable Ed25519 or P-256 key in PEM. */
    public const INVALID = 'invalid_key';
    /** A private key where only a public key belongs. */
    public const PRIVATE = 'private_key';
    /** A public key where the private key is needed (to sign). */
    public const PUBLIC = 'public_key';
    /** A key of another type or curve, such as RSA or P-384. */
    public const UNSUPPORTED_ALGORITHM = 'unsupported_algorithm';
    /** A private key protected by a passphrase. */
    public const ENCRYPTED = 'encrypted_key';

    /** @var string one of the constants above (PHP's own $code, widened to the string code callers branch on) */
    public $code;

    public function __construct(string $code, string $message)
    {
        parent::__construct($message);
        $this->code = $code;
    }
}
