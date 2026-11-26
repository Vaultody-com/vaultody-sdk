<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The transaction request created by createTronContractInteractionRequest. */
final class TronContractInteractionRequest extends Model
{
    protected const LISTS = [
        'recipients' => TransferRecipient::class,
    ];

    /**
     * @param ?string $amountUnit The token's symbol.
     * @param ?string $assetId The ID of the TRC-20 token.
     * @param ?ContractInteractionData $contractInteractionData Details of the contract interaction.
     * @param ?string $feePayer The address that pays the TRX energy and bandwidth fee.
     * @param ?string $maxFee The highest TRX fee accepted for the transaction, as set in the request.
     * @param ?string $method The contract method to call.
     * @param ?string $note A free-text note that describes the transaction request, at most 250 characters.
     * @param list<TransferRecipient> $recipients The destination, as a list with one entry.
     * @param ?TransferSender $senders The source of the transaction: the token holder.
     * @param ?string $totalTransactionAmount The token amount of the transaction; 0 for `approve`.
     * @param ?string $transactionRequestId The ID of the new transaction request.
     * @param ?string $transactionRequestStatus The status of the transaction request.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amountUnit = null,
        public readonly ?string $assetId = null,
        public readonly ?ContractInteractionData $contractInteractionData = null,
        public readonly ?string $feePayer = null,
        public readonly ?string $maxFee = null,
        public readonly ?string $method = null,
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
