<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The energy of a Tron address. */
final class TronEnergy extends Model
{
    /**
     * @param ?string $acquiredDelegated The TRX equivalent of the energy other addresses delegate to this address.
     * @param ?int $available The energy the address can use now, from its own staked TRX and from delegations.
     * @param ?string $delegated The TRX equivalent of the energy this address delegates to other addresses.
     * @param ?int $limit The total energy obtained by staking.
     * @param ?int $used How much energy has been used.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $acquiredDelegated = null,
        public readonly ?int $available = null,
        public readonly ?string $delegated = null,
        public readonly ?int $limit = null,
        public readonly ?int $used = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
