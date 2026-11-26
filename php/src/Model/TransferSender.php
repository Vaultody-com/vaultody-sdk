<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** The sending address of a transaction request. */
final class TransferSender extends Model
{
    /**
     * @param ?string $address The sender's address.
     * @param ?int $addressTag Set only when the sender is an XRP X-address: the source tag encoded in it.
     * @param ?string $classicAddress Set only when the sender is an XRP X-address: the classic address behind it.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $address = null,
        public readonly ?int $addressTag = null,
        public readonly ?string $classicAddress = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
