<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** An internal transfer of a blockchain transaction. */
final class InternalTransfer extends Model
{
    /**
     * @param ?string $fromAddress The address that sent the internal transfer.
     * @param ?string $operationId The ID of the operation inside the transaction.
     * @param ?string $operationType The type of the operation, for example `CALL`.
     * @param ?string $previousTxHash The hash of the transaction recorded on the blockchain immediately before this one.
     * @param ?int $timestamp When the internal transfer was recorded on the blockchain, as a Unix timestamp in seconds.
     * @param ?string $toAddress The address that received the internal transfer.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $fromAddress = null,
        public readonly ?string $operationId = null,
        public readonly ?string $operationType = null,
        public readonly ?string $previousTxHash = null,
        public readonly ?int $timestamp = null,
        public readonly ?string $toAddress = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
