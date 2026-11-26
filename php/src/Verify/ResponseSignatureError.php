<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * A response failed verification. Callers branch on $reason, which is the same string in every language
 * the SDK ships in; the message adds detail for logs and is not meant to be matched on.
 */
final class ResponseSignatureError extends \RuntimeException
{
    /** A signature header is absent or empty: the response was not signed, or the signature was stripped. */
    public const MISSING = 'missing';
    /** Malformed headers or certificate, or a signature that does not match the request and response. */
    public const INVALID = 'invalid';
    /** The response timestamp is outside the certificate's window, or this machine's clock is past it. */
    public const EXPIRED = 'expired';
    /** The certificate names a root key that is not trusted. */
    public const UNKNOWN_ROOT = 'unknown_root';
    /** Genuine, but the gateway did not read the request body, so the response is not tied to it. */
    public const REQUEST_UNBOUND = 'request_unbound';
    /** A signature format this version does not understand. */
    public const UNSUPPORTED_VERSION = 'unsupported_version';

    public const REASONS = [
        self::MISSING,
        self::INVALID,
        self::EXPIRED,
        self::UNKNOWN_ROOT,
        self::REQUEST_UNBOUND,
        self::UNSUPPORTED_VERSION,
    ];

    public function __construct(public readonly string $reason, string $detail)
    {
        parent::__construct(sprintf('Vaultody response signature check failed (%s): %s', $reason, $detail));
    }
}
