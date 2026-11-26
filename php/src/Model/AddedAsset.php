<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The asset added to a Vault Account (addAssetToVaultAccount). */
final class AddedAsset extends Model
{
    /**
     * @param ?string $address The address the asset was added to.
     * @param ?string $assetUnit The symbol of the added asset, for example `ETH`, `BTC` or `USDT`.
     * @param ?string $balance The current balance of the asset at the address.
     * @param ?string $contractAddress The token's smart contract address, when the asset is a token.
     * @param ?string $decimals The number of decimal places the asset uses.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?string $assetUnit = null,
        public readonly ?string $balance = null,
        public readonly ?string $contractAddress = null,
        public readonly ?string $decimals = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
