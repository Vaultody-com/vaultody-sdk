<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** One asset a Vault Account holds (listAssetsByVaultAccountId). */
final class VaultAccountAsset extends Model
{
    /**
     * @param ?string $assetId The asset's ID in Vaultody.
     * @param ?string $assetUnit The asset's symbol, for example `BTC`, `ETH` or `USDT`.
     * @param ?string $availableAmount The amount of the asset the Vault Account can send now: its balance minus the amount reserved for outgoing transaction requests that are not yet mined.
     * @param ?string $blockchain The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
     * @param ?string $exchangeRateToUsd The asset's current exchange rate to USD.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $assetId = null,
        public readonly ?string $assetUnit = null,
        public readonly ?string $availableAmount = null,
        public readonly ?string $blockchain = null,
        public readonly ?string $exchangeRateToUsd = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
