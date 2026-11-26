<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The transaction request created by createUtxoTransfer. */
final class UtxoTransferRequest extends Model
{
    protected const LISTS = [
        'recipients' => TransferRecipient::class,
        'senders' => UtxoSender::class,
    ];

    /**
     * @param ?string $amountUnit The unit of the amounts, for example BTC.
     * @param ?string $feePriority How fast the transaction should confirm: `slow`, `standard` or `fast`.
     * @param ?string $note A short free-text description of the transaction request, at most 250 characters.
     * @param list<TransferRecipient> $recipients The recipients of the transfer: 1 to 150, each with an address and an amount.
     * @param list<UtxoSender> $senders In the request, the UTXOs to spend: 1 to 150, from one or more Vault Accounts of the same Vault.
     * @param ?string $totalTransactionAmount The total amount sent to the recipients, without the change and the fee.
     * @param ?string $transactionRequestId The ID of the new transaction request.
     * @param ?string $transactionRequestStatus The status of the transaction request.
     * @param ?string $transactionType The kind of transaction.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amountUnit = null,
        public readonly ?string $feePriority = null,
        public readonly ?string $note = null,
        public readonly array $recipients = [],
        public readonly array $senders = [],
        public readonly ?string $totalTransactionAmount = null,
        public readonly ?string $transactionRequestId = null,
        public readonly ?string $transactionRequestStatus = null,
        public readonly ?string $transactionType = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
