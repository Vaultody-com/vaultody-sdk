<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A sender or a recipient of a blockchain transaction. */
final class TransactionParty extends Model
{
    /**
     * @param ?string $address The address.
     * @param ?string $addressType The type of the address, for example `deposit`.
     * @param ?string $amount The amount the address sends or receives.
     * @param ?string $amountUnit The symbol of the asset, for example `ETH` or `BTC`.
     * @param string|bool|null $isVaultAddress Whether the address belongs to this Vault.
     * @param ?string $label The label of the address.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?string $addressType = null,
        public readonly ?string $amount = null,
        public readonly ?string $amountUnit = null,
        public readonly string|bool|null $isVaultAddress = null,
        public readonly ?string $label = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
