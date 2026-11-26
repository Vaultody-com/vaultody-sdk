<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A blockchain transaction of a Vault or a Vault Account, as the transaction lists answer it. */
final class Transaction extends Model
{
    protected const LISTS = [
        'recipients' => TransactionParty::class,
        'senders' => TransactionParty::class,
    ];

    /**
     * @param ?string $blockchain The blockchain the transaction is on, for example `bitcoin`, `ethereum` or `tron`.
     * @param ?int $createdTimestamp When Vaultody recorded the transaction, as a Unix timestamp in seconds.
     * @param ?string $direction The direction of the transaction for this Vault: `incoming` or `outgoing`.
     * @param ?bool $hasTokenTransfer Whether the transaction transfers any tokens.
     * @param ?string $id The transaction's ID in Vaultody.
     * @param ?bool $isInternal Whether the transaction includes internal transactions.
     * @param ?string $minedInBlockHeight The height of the block the transaction was mined in.
     * @param ?string $network The network the transaction is on: `mainnet`, or a test network such as `sepolia` or `nile`.
     * @param list<TransactionParty> $recipients Every address that receives assets in the transaction.
     * @param list<TransactionParty> $senders Every address that sends assets in the transaction.
     * @param ?string $status The status of the transaction, for example `confirmed`.
     * @param ?TransactionFee $transactionFee The network fee paid for the transaction.
     * @param ?string $transactionId The transaction's hash on the blockchain.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $blockchain = null,
        public readonly ?int $createdTimestamp = null,
        public readonly ?string $direction = null,
        public readonly ?bool $hasTokenTransfer = null,
        public readonly ?string $id = null,
        public readonly ?bool $isInternal = null,
        public readonly ?string $minedInBlockHeight = null,
        public readonly ?string $network = null,
        public readonly array $recipients = [],
        public readonly array $senders = [],
        public readonly ?string $status = null,
        public readonly ?TransactionFee $transactionFee = null,
        public readonly ?string $transactionId = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
