<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/** A network failure. $sent is false only when the request certainly never left; otherwise 'unknown'. */
final class TransportError extends VaultodyError
{
    public function __construct(string $message, public readonly false|string $sent, public readonly ?int $curlErrno = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
