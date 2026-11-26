<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * A webhook delivery's X-Signature does not check out (missing, malformed, mismatch). Treat the body as
 * untrusted and do not act on it.
 */
final class WebhookSignatureError extends VaultodyError
{
    public function __construct(public readonly string $reason, string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
