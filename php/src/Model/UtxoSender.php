<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A UTXO a UTXO transfer spends. */
final class UtxoSender extends Model
{
    /**
     * @param ?string $address The address that holds the UTXO.
     * @param ?string $addressLabel The label of that address, if it has one.
     * @param ?string $amount The amount the UTXO holds, in the coin's own unit.
     * @param ?string $amountUnit The unit of the amount, for example BTC.
     * @param ?string $assetId The ID of the asset the UTXO holds.
     * @param ?string $utxoId The UTXO's ID, as List UTXOs returns it.
     * @param ?string $vaultAccountId The ID of the Vault Account that owns the UTXO.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?string $addressLabel = null,
        public readonly ?string $amount = null,
        public readonly ?string $amountUnit = null,
        public readonly ?string $assetId = null,
        public readonly ?string $utxoId = null,
        public readonly ?string $vaultAccountId = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
