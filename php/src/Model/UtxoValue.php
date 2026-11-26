<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The value of a UTXO. */
final class UtxoValue extends Model
{
    /**
     * @param ?string $amount The amount the UTXO holds.
     * @param ?string $assetUnit The unit of the amount, for example BTC or LTC.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amount = null,
        public readonly ?string $assetUnit = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
