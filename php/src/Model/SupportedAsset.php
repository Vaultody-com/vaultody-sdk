<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** An asset the platform supports (listSupportedAssets). */
final class SupportedAsset extends Model
{
    /**
     * @param ?string $active Whether Vaultody currently supports the asset.
     * @param ?string $assetId The asset's ID in Vaultody.
     * @param ?string $assetName The asset's name.
     * @param ?string $assetType `COIN` for a blockchain's native coin, `TOKEN` for a token issued by a smart contract.
     * @param ?string $assetUnit The asset's symbol, for example `BTC`, `ETH` or `USDC`.
     * @param ?string $blockchain The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
     * @param ?string $contractAddress The token's smart contract address.
     * @param ?string $contractType The token standard, for example `ERC-20`, `BEP-20` or `TRC-20`.
     * @param ?string $decimals The number of decimal places the asset uses.
     * @param ?string $network The network the asset lives on: `mainnet`, or a test network such as `sepolia` or `nile`.
     * @param ?AssetPrice $price The asset's current price.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $active = null,
        public readonly ?string $assetId = null,
        public readonly ?string $assetName = null,
        public readonly ?string $assetType = null,
        public readonly ?string $assetUnit = null,
        public readonly ?string $blockchain = null,
        public readonly ?string $contractAddress = null,
        public readonly ?string $contractType = null,
        public readonly ?string $decimals = null,
        public readonly ?string $network = null,
        public readonly ?AssetPrice $price = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
