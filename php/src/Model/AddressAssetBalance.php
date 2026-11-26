<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The balance of one asset at an address of a Vault Account. */
final class AddressAssetBalance extends Model
{
    /**
     * @param ?string $amount The balance of the asset on this address, in the asset's own unit.
     * @param ?string $assetId The asset's ID in Vaultody.
     * @param ?string $assetUnit The asset's symbol, for example `BTC`, `ETH` or `USDT`.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amount = null,
        public readonly ?string $assetId = null,
        public readonly ?string $assetUnit = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
