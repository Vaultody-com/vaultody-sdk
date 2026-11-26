<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A Vault Account (create, get, list and update). */
final class VaultAccount extends Model
{
    protected const LISTS = [
        'balances' => VaultAccountBalance::class,
    ];

    /**
     * @param ?string $addressesCount How many addresses the Vault Account has.
     * @param list<VaultAccountBalance> $balances One entry per asset in the Vault Account, with the amount it holds.
     * @param ?int $createdAt When the Vault Account was created, as a Unix timestamp in seconds.
     * @param string|int|null $index The Vault Account's sequential number within its Vault.
     * @param ?bool $isFavoriteInDashboard Whether the Vault Account is marked as a favorite in the Dashboard.
     * @param ?bool $isHiddenInDashboard Whether the Vault Account is hidden in the Dashboard.
     * @param ?string $vaultAccountColour The color the Vault Account is shown in, as a hex code.
     * @param ?string $vaultAccountId The Vault Account's ID.
     * @param ?string $vaultAccountName The name of the Vault Account.
     * @param ?string $vaultId The ID of the Vault the Vault Account belongs to.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $addressesCount = null,
        public readonly array $balances = [],
        public readonly ?int $createdAt = null,
        public readonly string|int|null $index = null,
        public readonly ?bool $isFavoriteInDashboard = null,
        public readonly ?bool $isHiddenInDashboard = null,
        public readonly ?string $vaultAccountColour = null,
        public readonly ?string $vaultAccountId = null,
        public readonly ?string $vaultAccountName = null,
        public readonly ?string $vaultId = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
