<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * A write may or may not have been carried out: it was sent, and its outcome could not be learned. Check
 * with getTransactionRequestDetails or the dashboard before sending it again: sending it again as a new
 * request could create a second transfer.
 */
final class RequestOutcomeUnknownError extends VaultodyError
{
    public function __construct(
        /** the request was received and is still running (409 duplicate_api_request_in_progress) */
        public readonly bool $inProgress = false,
        /** the x-api-nonce and x-api-timestamp the request was signed with */
        public readonly ?string $nonce = null,
        public readonly ?string $timestamp = null,
        public readonly ?string $requestId = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($inProgress
            ? 'the request was received and is still being processed; its outcome is not known yet'
            : 'the request may or may not have been carried out; its outcome is not known', 0, $previous);
    }
}
