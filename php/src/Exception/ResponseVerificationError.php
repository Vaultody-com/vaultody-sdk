<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * A response failed its signature check (missing, invalid, expired, unknown_root, request_unbound,
 * unsupported_version). Its body was not parsed and nothing in it reached the caller; it is never retried.
 * For a write, something answered the request, so treat its outcome as unknown: check it with
 * getTransactionRequestDetails or the dashboard before sending it again.
 */
final class ResponseVerificationError extends VaultodyError
{
    public function __construct(public readonly string $reason, string $message, public readonly ?int $status = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
