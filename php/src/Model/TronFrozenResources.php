<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The TRX a Tron address has staked, per resource. */
final class TronFrozenResources extends Model
{
    /**
     * @param ?string $bandwidth TRX staked for bandwidth.
     * @param ?string $energy TRX staked for energy.
     * @param ?string $tronPower TRX staked for Tron Power, used for voting.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $bandwidth = null,
        public readonly ?string $energy = null,
        public readonly ?string $tronPower = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
