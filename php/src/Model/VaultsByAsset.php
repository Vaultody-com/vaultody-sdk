<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** How much of one asset each Vault holds (listVaultsByAssetId). */
final class VaultsByAsset extends Model
{
    protected const LISTS = [
        'vaults' => VaultHolding::class,
    ];

    /**
     * @param ?string $exchangeRateUnit The asset's current exchange rate to USD.
     * @param list<VaultHolding> $vaults One entry per Vault, with the amount of the asset that Vault holds.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $exchangeRateUnit = null,
        public readonly array $vaults = [],
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
