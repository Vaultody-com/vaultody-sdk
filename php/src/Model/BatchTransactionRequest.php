<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The transaction request created by createBatchTransactionRequest. */
final class BatchTransactionRequest extends Model
{
    protected const LISTS = [
        'recipients' => TransferRecipient::class,
    ];

    /**
     * @param ?string $amountUnit The unit of the transaction amount, for example ETH.
     * @param ?string $feePayer The fee payer.
     * @param ?string $feePriority How fast the transaction should confirm: `slow`, `standard` or `fast`.
     * @param ?string $note A free-text note that describes the transaction request, for your own records.
     * @param list<TransferRecipient> $recipients The transfers in the batch, one entry per recipient, each with its own asset and amount.
     * @param ?TransferSender $senders The sender of the transaction.
     * @param ?string $totalTransactionAmountInUsd The total value of all transfers in the batch, in USD.
     * @param ?string $transactionRequestId The ID of the new transaction request.
     * @param ?string $transactionRequestStatus The status of the transaction request.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amountUnit = null,
        public readonly ?string $feePayer = null,
        public readonly ?string $feePriority = null,
        public readonly ?string $note = null,
        public readonly array $recipients = [],
        public readonly ?TransferSender $senders = null,
        public readonly ?string $totalTransactionAmountInUsd = null,
        public readonly ?string $transactionRequestId = null,
        public readonly ?string $transactionRequestStatus = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
