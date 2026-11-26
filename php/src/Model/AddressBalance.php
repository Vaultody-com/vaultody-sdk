<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The balance of one asset at an address (getAddressBalance). */
final class AddressBalance extends Model
{
    /**
     * @param ?AssetData $assetData The amounts of the asset on the address, and how the asset is defined on the blockchain.
     * @param ?string $assetId The asset's ID in Vaultody.
     * @param ?string $assetUnit The asset's symbol, for example `ETH` or `USDC`.
     * @param ?string $blockchain The blockchain the balance belongs to, for example `ethereum` or `tron`.
     * @param ?string $exchangeRateUnit The current exchange rate of one unit of the asset.
     * @param ?string $type `COIN` for the blockchain's native coin, `TOKEN` for a token issued by a smart contract.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?AssetData $assetData = null,
        public readonly ?string $assetId = null,
        public readonly ?string $assetUnit = null,
        public readonly ?string $blockchain = null,
        public readonly ?string $exchangeRateUnit = null,
        public readonly ?string $type = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
