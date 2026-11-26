<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** An address of a Vault Account, with its balances (listAddressesByVaultAccountId). */
final class VaultAddress extends Model
{
    protected const LISTS = [
        'balances' => AddressAssetBalance::class,
    ];

    /**
     * @param ?string $address The address on the blockchain.
     * @param ?string $addressId The address's ID in Vaultody.
     * @param ?string $addressIndex The derivation index of the address within the Vault Account.
     * @param list<AddressAssetBalance> $balances The balance of each asset added to the address.
     * @param ?string $blockchain The blockchain of the address, for example `bitcoin`, `ethereum` or `tron`.
     * @param ?int $createdTimestamp When the address was created, as a Unix timestamp in seconds.
     * @param ?string $label The name given to the address when it was created.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?string $addressId = null,
        public readonly ?string $addressIndex = null,
        public readonly array $balances = [],
        public readonly ?string $blockchain = null,
        public readonly ?int $createdTimestamp = null,
        public readonly ?string $label = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
