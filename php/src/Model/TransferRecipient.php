<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A recipient of a transaction request; each operation fills the fields it documents. */
final class TransferRecipient extends Model
{
    /**
     * @param ?string $address The recipient's address.
     * @param ?int $addressTag Set only when the recipient is an XRP X-address: the destination tag encoded in it, which identifies the recipient behind a shared address.
     * @param ?string $amount The amount the recipient receives.
     * @param ?string $amountUnit The unit of the amount the recipient receives, for example ETH, TRX or USDT.
     * @param ?string $assetId The ID of the asset sent to the recipient.
     * @param ?string $classicAddress Set only when the recipient is an XRP X-address: the classic address behind it.
     * @param ?string $convertedAmountToUSD The amount the recipient receives, converted to USD.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?int $addressTag = null,
        public readonly ?string $amount = null,
        public readonly ?string $amountUnit = null,
        public readonly ?string $assetId = null,
        public readonly ?string $classicAddress = null,
        public readonly ?string $convertedAmountToUSD = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
