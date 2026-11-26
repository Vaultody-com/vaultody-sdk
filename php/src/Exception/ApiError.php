<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * An answer the SDK can't return as a result: an error status, or a success it can't read
 * (test-vectors/envelope-errors-v1.json).
 */
class ApiError extends VaultodyError
{
    /** @var string|null the API's error code (PHP's own $code, widened to the string callers branch on) */
    public $code;

    /** Only the two conflicts the docs say to retry at once: collisions with no side effect. */
    public readonly bool $retryable;

    public function __construct(
        public readonly int $status,
        ?string $code,
        ?string $message,
        public readonly ?string $requestId,
        public readonly ?string $apiVersion,
        public readonly bool $replayed,
        /** error.details as the API gave it; hasDetails says whether it gave any */
        public readonly mixed $details = null,
        public readonly bool $hasDetails = false,
        ?\Throwable $previous = null,
    ) {
        // The API's own message when it gave one, as written for people; never branch on it.
        parent::__construct($message ?? sprintf('Vaultody API answered %d%s', $status, $code !== null ? ' ' . $code : ''), 0, $previous);
        $this->code = $code;
        $this->retryable = $code === 'address_derivation_conflict' || $code === 'vault_accounts_creation_failed';
    }
}
