<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** TRX staking and resources of one Tron address (tronResourceOverview). */
final class TronResourceOverview extends Model
{
    /**
     * @param ?string $address The Tron address to get the overview of.
     * @param ?TronBalance $balance The address's TRX, split by what it can be used for.
     * @param ?TronFrozenResources $frozenResources The TRX staked for each kind of resource.
     * @param ?string $network The Tron network: `mainnet`, or the `nile` test network.
     * @param ?TronResources $resources The bandwidth and energy the address has, and how much of it is used.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?TronBalance $balance = null,
        public readonly ?TronFrozenResources $frozenResources = null,
        public readonly ?string $network = null,
        public readonly ?TronResources $resources = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
