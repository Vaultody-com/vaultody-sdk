<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/** The API answered something other than a verdict on the key: a server error, a rate limit, an unknown shape. */
final class UnexpectedResponseError extends \RuntimeException
{
    /** @var string|null the API's error code, if it gave one */
    public $code;

    public function __construct(string $message, public readonly ?int $status = null, public readonly ?string $requestId = null, ?string $code = null)
    {
        parent::__construct($message);
        $this->code = $code;
    }
}
