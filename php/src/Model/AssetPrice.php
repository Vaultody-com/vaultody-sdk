<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The price of a supported asset. */
final class AssetPrice extends Model
{
    /**
     * @param ?string $amount The price of one unit of the asset.
     * @param ?int $calculationTimestamp When the price was calculated, as a Unix timestamp in seconds.
     * @param ?string $unit The currency of the price.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amount = null,
        public readonly ?int $calculationTimestamp = null,
        public readonly ?string $unit = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
