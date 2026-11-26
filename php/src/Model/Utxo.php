<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** An unspent (or spent) transaction output of a Vault (listUtxos). */
final class Utxo extends Model
{
    /**
     * @param ?string $address The address that received the UTXO.
     * @param ?string $assetId The ID of the asset of the UTXO.
     * @param ?int $createdTimestamp When the UTXO was created or confirmed, as a Unix timestamp in milliseconds.
     * @param ?string $index The position of the output within that transaction.
     * @param ?bool $isSpent Whether the UTXO has been spent (`true`) or is still unspent (`false`).
     * @param ?string $transactionId The hash of the blockchain transaction that created the UTXO.
     * @param ?string $utxoId The ID of the UTXO in Vaultody.
     * @param ?UtxoValue $value The value of the UTXO.
     * @param ?string $vaultAccountId The ID of the Vault Account that owns the UTXO.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?string $assetId = null,
        public readonly ?int $createdTimestamp = null,
        public readonly ?string $index = null,
        public readonly ?bool $isSpent = null,
        public readonly ?string $transactionId = null,
        public readonly ?string $utxoId = null,
        public readonly ?UtxoValue $value = null,
        public readonly ?string $vaultAccountId = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
