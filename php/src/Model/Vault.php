<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A Vault, as listVaults answers it. */
final class Vault extends Model
{
    /**
     * @param ?bool $backuped Whether the Vault has been backed up.
     * @param ?int $changeAddressesCount How many change addresses the Vault has.
     * @param ?string $color The color the Vault is shown in, as a hex code.
     * @param ?int $createdTimestamp When the Vault was created, as a Unix timestamp in seconds.
     * @param ?int $depositAddressesCount How many deposit addresses the Vault has.
     * @param ?string $id The Vault's ID.
     * @param ?string $name The name given to the Vault in the Dashboard.
     * @param ?string $type The type of the Vault: `test` or `main`.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?bool $backuped = null,
        public readonly ?int $changeAddressesCount = null,
        public readonly ?string $color = null,
        public readonly ?int $createdTimestamp = null,
        public readonly ?int $depositAddressesCount = null,
        public readonly ?string $id = null,
        public readonly ?string $name = null,
        public readonly ?string $type = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
