<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The amounts and contract of an asset in a Vault or at an address. */
final class AssetData extends Model
{
    /**
     * @param ?string $allocatedAmount The amount of the asset reserved for outgoing transaction requests that are not yet mined.
     * @param ?string $availableAmount The amount of the asset that can be sent now: the total minus the allocated amount.
     * @param ?string $contractAddress The token's smart contract address.
     * @param ?string $standard The token standard, for example `ERC-20` or `TRC-20`.
     * @param ?string $totalAmount The total amount of the asset in the Vault.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $allocatedAmount = null,
        public readonly ?string $availableAmount = null,
        public readonly ?string $contractAddress = null,
        public readonly ?string $standard = null,
        public readonly ?string $totalAmount = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
