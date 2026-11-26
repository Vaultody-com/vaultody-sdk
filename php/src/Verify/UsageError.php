<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * A wrong argument, file or setting: the caller must change how it asks. $code is set where callers need
 * one, such as 'invalid_api_secret'. The message never holds a secret.
 */
final class UsageError extends \InvalidArgumentException
{
    /** @var string|null */
    public $code;

    public function __construct(string $message, ?string $code = null)
    {
        parent::__construct($message);
        $this->code = $code;
    }
}
