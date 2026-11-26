<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** One transaction request and its status (getTransactionRequestDetails). */
final class TransactionRequestDetails extends Model
{
    protected const LISTS = [
        'recipients' => TransferRecipient::class,
    ];

    /**
     * @param ?string $amountUnit The unit of the amount, for example XRP or USDT.
     * @param ?string $blockchain The blockchain of the transaction, for example `ethereum` or `xrp`.
     * @param ?string $feePriority The fee priority of the request: `slow`, `standard` or `fast`.
     * @param ?string $network The network of the blockchain: `mainnet`, or a test network such as `testnet`, `sepolia` or `nile`.
     * @param ?string $note The free-text note given when the request was created.
     * @param list<TransferRecipient> $recipients The recipients and the amount each receives.
     * @param ?TransferSender $senders The sender of the transaction.
     * @param ?string $totalTransactionAmount The total amount the request sends to all recipients.
     * @param ?string $transactionId The ID of the transaction on the blockchain (the transaction hash on account-based blockchains).
     * @param ?string $transactionRequestStatus Where the request stands, for example `await-approval`, `pending-signing`, `broadcasted`, `mined`, `failed` or `rejected`.
     * @param ?string $transactionType The kind of transfer: `coin` for the blockchain's native coin, `token` for a token.
     * @param ?string $vaultAccountId The ID of the Vault Account that sends the funds.
     * @param ?string $vaultId The ID of the Vault that sends the funds.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amountUnit = null,
        public readonly ?string $blockchain = null,
        public readonly ?string $feePriority = null,
        public readonly ?string $network = null,
        public readonly ?string $note = null,
        public readonly array $recipients = [],
        public readonly ?TransferSender $senders = null,
        public readonly ?string $totalTransactionAmount = null,
        public readonly ?string $transactionId = null,
        public readonly ?string $transactionRequestStatus = null,
        public readonly ?string $transactionType = null,
        public readonly ?string $vaultAccountId = null,
        public readonly ?string $vaultId = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
