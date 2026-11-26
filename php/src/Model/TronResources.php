<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The bandwidth and energy of a Tron address. */
final class TronResources extends Model
{
    /**
     * @param ?TronBandwidth $bandwidth The address's bandwidth.
     * @param ?TronEnergy $energy The address's energy.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?TronBandwidth $bandwidth = null,
        public readonly ?TronEnergy $energy = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
