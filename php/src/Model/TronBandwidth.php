<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The bandwidth of a Tron address. */
final class TronBandwidth extends Model
{
    /**
     * @param ?string $acquiredDelegated The TRX equivalent of the bandwidth other addresses delegate to this address.
     * @param ?int $available The bandwidth the address can use now: the free daily allowance, plus bandwidth from its own staked TRX and from delegations.
     * @param ?string $delegated The TRX equivalent of the bandwidth this address delegates to other addresses.
     * @param ?int $freeLimit The free bandwidth the Tron network gives every address each day.
     * @param ?int $freeUsed How much of the free bandwidth has been used.
     * @param ?int $limit The total bandwidth obtained by staking.
     * @param ?int $used How much of the bandwidth obtained by staking has been used.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $acquiredDelegated = null,
        public readonly ?int $available = null,
        public readonly ?string $delegated = null,
        public readonly ?int $freeLimit = null,
        public readonly ?int $freeUsed = null,
        public readonly ?int $limit = null,
        public readonly ?int $used = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
