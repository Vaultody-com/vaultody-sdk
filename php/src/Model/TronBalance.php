<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The TRX balance of a Tron address. */
final class TronBalance extends Model
{
    /**
     * @param ?string $available TRX that is not staked or delegated and can be sent.
     * @param ?string $availableFrozen TRX staked by the address for its own resources, not counting what is delegated to other addresses.
     * @param ?string $delegated TRX staked by the address to provide resources to other addresses.
     * @param ?string $total The total TRX balance: `available`, `availableFrozen`, `delegated` and `withdrawableAmount` together.
     * @param ?string $unit The unit of the amounts.
     * @param ?string $withdrawableAmount TRX that has been unstaked and has passed the mandatory waiting period (14 days under Tron's Stake 2.0), so it can be withdrawn back to the available balance.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $available = null,
        public readonly ?string $availableFrozen = null,
        public readonly ?string $delegated = null,
        public readonly ?string $total = null,
        public readonly ?string $unit = null,
        public readonly ?string $withdrawableAmount = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
