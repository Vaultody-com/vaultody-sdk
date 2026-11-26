<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The fee a blockchain transaction paid. */
final class TransactionFee extends Model
{
    /**
     * @param ?string $amount The fee amount.
     * @param ?string $amountUnit The symbol of the asset the fee is paid in.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $amount = null,
        public readonly ?string $amountUnit = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
