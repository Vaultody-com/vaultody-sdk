<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** One asset held in a Vault (listAssetsByVault). */
final class VaultAsset extends Model
{
    /**
     * @param ?AssetData $assetData The asset's amounts in the Vault and, for a token, its contract details.
     * @param ?string $assetId The asset's ID in Vaultody.
     * @param ?string $assetUnit The asset's symbol, for example `BTC`, `ETH` or `USDT`.
     * @param ?string $blockchain The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
     * @param ?string $exchangeRateUnit The asset's current exchange rate to USD.
     * @param ?string $network The network the asset lives on: `mainnet`, or a test network such as `sepolia` or `nile`.
     * @param ?string $type `COIN` for a blockchain's native coin, `TOKEN` for a token issued by a smart contract.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?AssetData $assetData = null,
        public readonly ?string $assetId = null,
        public readonly ?string $assetUnit = null,
        public readonly ?string $blockchain = null,
        public readonly ?string $exchangeRateUnit = null,
        public readonly ?string $network = null,
        public readonly ?string $type = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
