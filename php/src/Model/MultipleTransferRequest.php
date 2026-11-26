<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The transaction request created by createMultipleTransfer. */
final class MultipleTransferRequest extends Model
{
    protected const LISTS = [
        'recipients' => TransferRecipient::class,
    ];

    /**
     * @param ?string $amountUnit The unit of the amounts, for example BTC.
     * @param ?string $feePriority How fast the transaction should confirm: `slow`, `standard` or `fast`.
     * @param ?bool $gross Whether the amounts include the fee (the recipients receive less); the value used.
     * @param ?string $maxFee The highest fee you accept for the transaction.
     * @param ?string $note A free-text note that describes the transaction request, for your own records.
     * @param ?string $prepareStrategy How Vaultody selects the UTXOs to spend: `optimize-size` keeps the transaction small, which keeps the fee low; `minimize-dust` favours spending small outputs, so fewer of them are left behind.
     * @param list<TransferRecipient> $recipients The recipients of the transaction, each with its own address and amount.
     * @param ?string $totalTransactionAmount The total amount the transaction sends to all recipients.
     * @param ?string $transactionRequestId The ID of the new transaction request.
     * @param ?string $transactionRequestStatus The status of the transaction request.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amountUnit = null,
        public readonly ?string $feePriority = null,
        public readonly ?bool $gross = null,
        public readonly ?string $maxFee = null,
        public readonly ?string $note = null,
        public readonly ?string $prepareStrategy = null,
        public readonly array $recipients = [],
        public readonly ?string $totalTransactionAmount = null,
        public readonly ?string $transactionRequestId = null,
        public readonly ?string $transactionRequestStatus = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
