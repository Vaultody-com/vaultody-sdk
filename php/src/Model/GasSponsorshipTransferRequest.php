<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The transaction request created by gasSponsorshipTransfer. */
final class GasSponsorshipTransferRequest extends Model
{
    protected const LISTS = [
        'recipients' => TransferRecipient::class,
    ];

    /**
     * @param ?string $amountUnit The unit of the amount, for example ETH or USDT.
     * @param ?string $feePayer The address that pays the network fee instead of `fromAddress`.
     * @param ?string $feePriority How fast the transaction should confirm: `slow`, `standard` or `fast`.
     * @param ?string $maxFee The highest fee you accept for the transaction.
     * @param ?string $note A free-text note that describes the transaction request, for your own records.
     * @param list<TransferRecipient> $recipients The recipient of the transaction, as a list with one entry.
     * @param ?TransferSender $senders The sender of the transaction.
     * @param ?string $totalTransactionAmount The total amount the transaction sends.
     * @param ?string $transactionRequestId The ID of the new transaction request.
     * @param ?string $transactionRequestStatus The status of the transaction request.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amountUnit = null,
        public readonly ?string $feePayer = null,
        public readonly ?string $feePriority = null,
        public readonly ?string $maxFee = null,
        public readonly ?string $note = null,
        public readonly array $recipients = [],
        public readonly ?TransferSender $senders = null,
        public readonly ?string $totalTransactionAmount = null,
        public readonly ?string $transactionRequestId = null,
        public readonly ?string $transactionRequestStatus = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
