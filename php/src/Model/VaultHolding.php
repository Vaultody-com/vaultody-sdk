<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** One Vault's holding of the asset (listVaultsByAssetId). */
final class VaultHolding extends Model
{
    /**
     * @param ?string $allocatedAmount The amount of the asset reserved for outgoing transaction requests that are not yet mined.
     * @param ?string $availableAmount The amount of the asset that can be sent now: the total minus the allocated amount.
     * @param ?string $totalAmount The total amount of the asset in the Vault.
     * @param ?string $vaultColor The color the Vault is shown in, as a hex code.
     * @param ?string $vaultId The Vault's ID.
     * @param ?string $vaultName The name given to the Vault in the Dashboard.
     * @param ?string $vaultType The type of the Vault.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $allocatedAmount = null,
        public readonly ?string $availableAmount = null,
        public readonly ?string $totalAmount = null,
        public readonly ?string $vaultColor = null,
        public readonly ?string $vaultId = null,
        public readonly ?string $vaultName = null,
        public readonly ?string $vaultType = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
