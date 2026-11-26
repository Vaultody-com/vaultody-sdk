<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** An approximate fee for a planned transaction (estimateTransactionFeeByAssetId). */
final class FeeEstimate extends Model
{
    /**
     * @param ?string $errorMessage Why the transaction would fail, for example `INSUFFICIENT_FUNDS`.
     * @param ?string $feeInNative The estimated fee, in the blockchain's native coin.
     * @param ?bool $insufficientBalance Tron only: true when the sender's own TRX does not cover the estimated fee; absent otherwise.
     * @param ?string $maxAmount For UTXO-based transfers: the most the Vault Account can send.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $errorMessage = null,
        public readonly ?string $feeInNative = null,
        public readonly ?bool $insufficientBalance = null,
        public readonly ?string $maxAmount = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
