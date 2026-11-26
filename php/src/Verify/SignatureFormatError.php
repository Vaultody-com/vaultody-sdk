<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/** A signature in a form that can't be converted (see Keys::p1363ToDer). $code says why. */
final class SignatureFormatError extends \RuntimeException
{
    public const INVALID_LENGTH = 'invalid_length';
    public const ZERO_INTEGER = 'zero_integer';

    /** @var string */
    public $code;

    public function __construct(string $code, string $message)
    {
        parent::__construct($message);
        $this->code = $code;
    }
}
