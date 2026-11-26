<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** One blockchain transaction of a Vault (getTransactionDetails). */
final class TransactionDetails extends Model
{
    protected const LISTS = [
        'internalTransfers' => InternalTransfer::class,
        'recipients' => TransactionParty::class,
        'senders' => TransactionParty::class,
        'tokensTransfers' => TokenTransfer::class,
    ];

    /**
     * @param ?int $dateTime When the transaction was created, as a Unix timestamp in seconds.
     * @param ?string $direction The direction of the transaction for the Vault: `incoming`, `outgoing`, `client-internal`, `vault-internal` or `internal`.
     * @param list<InternalTransfer> $internalTransfers The internal transfers inside the transaction: value moved by contract calls rather than by the transaction itself.
     * @param ?string $minedInBlockHeight The height of the block in which the transaction was first mined.
     * @param ?string $network The network of the transaction, for example `mainnet`, `testnet`, `sepolia` or `nile`.
     * @param list<TransactionParty> $recipients The addresses that received funds in the transaction.
     * @param list<TransactionParty> $senders The addresses that sent funds in the transaction.
     * @param ?string $status The status of the transaction on the blockchain, for example `confirmed` or `failed`.
     * @param list<TokenTransfer> $tokensTransfers The token transfers in the transaction.
     * @param ?TransactionFee $transactionFee The fee paid for the transaction.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?int $dateTime = null,
        public readonly ?string $direction = null,
        public readonly array $internalTransfers = [],
        public readonly ?string $minedInBlockHeight = null,
        public readonly ?string $network = null,
        public readonly array $recipients = [],
        public readonly array $senders = [],
        public readonly ?string $status = null,
        public readonly array $tokensTransfers = [],
        public readonly ?TransactionFee $transactionFee = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
