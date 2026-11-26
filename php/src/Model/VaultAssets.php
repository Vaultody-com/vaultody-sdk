<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The assets held in one Vault (listAssetsByVault). */
final class VaultAssets extends Model
{
    protected const LISTS = [
        'assets' => VaultAsset::class,
    ];

    /**
     * @param list<VaultAsset> $assets One entry per asset held in the Vault.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly array $assets = [],
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
