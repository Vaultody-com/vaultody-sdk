<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** Where a Tron staking operation sends TRX or resources. */
final class TronResourceDestination extends Model
{
    /**
     * @param ?string $address The address that receives the resources.
     * @param ?string $amount The amount of TRX in the operation.
     * @param ?string $amountUnit The unit of the amount.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?string $amount = null,
        public readonly ?string $amountUnit = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
