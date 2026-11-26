<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** Whether an address is valid on a blockchain and network (validateAddress). */
final class AddressValidation extends Model
{
    /**
     * @param ?string $address The address to check.
     * @param ?bool $isValid `true` when the address is valid on the blockchain and network, otherwise `false`.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?bool $isValid = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
