<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A deposit address just generated (generateDepositAddress). */
final class DepositAddress extends Model
{
    /**
     * @param ?string $address The new deposit address.
     * @param ?int $createdTimestamp When the address was created, as a Unix timestamp in seconds.
     * @param ?string $label A name for the address, so you can tell it apart in the Dashboard and in API responses.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?int $createdTimestamp = null,
        public readonly ?string $label = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
