<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/** A webhook delivery's signature does not check out. Treat the body as untrusted; $reason says why. */
final class WebhookSignatureError extends \RuntimeException
{
    /** No X-Signature header, or an empty one. */
    public const MISSING = 'missing';
    /** Not 64 lowercase hex characters. */
    public const MALFORMED = 'malformed';
    /** Well formed, but no configured secret produces it over this body. */
    public const MISMATCH = 'mismatch';

    public function __construct(public readonly string $reason, string $detail)
    {
        parent::__construct(sprintf('Vaultody webhook signature check failed (%s): %s', $reason, $detail));
    }
}
