<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The balance of one asset in a Vault Account. */
final class VaultAccountBalance extends Model
{
    /**
     * @param ?string $assetId The asset's ID in Vaultody.
     * @param ?string $assetName The asset's name, for example `Ethereum` or `Bitcoin`.
     * @param ?string $assetUnit The asset's symbol, for example `ETH` or `BTC`.
     * @param ?string $blockchain The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
     * @param ?string $exchangeRateUnit The currency of the exchange rate.
     * @param ?string $latestExchangeRateToUSD The asset's latest exchange rate to USD.
     * @param ?string $totalAmount The total amount of the asset in the Vault Account.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $assetId = null,
        public readonly ?string $assetName = null,
        public readonly ?string $assetUnit = null,
        public readonly ?string $blockchain = null,
        public readonly ?string $exchangeRateUnit = null,
        public readonly ?string $latestExchangeRateToUSD = null,
        public readonly ?string $totalAmount = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
