<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Api;

use Vaultody\Sdk\Attribute\Operation;
use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Model\Page;
use Vaultody\Sdk\Model\Transaction;
use Vaultody\Sdk\Model\Vault;
use Vaultody\Sdk\Model\VaultAssets;
use Vaultody\Sdk\Model\VaultsByAsset;

/**
 * Vaults: `$vaultody->vaults`.
 *
 * Every method takes its parameters in one flat array (path, query and body fields by their documented
 * names) and call options in a second one: `context`, a string of your own the API returns unchanged.
 * Params are checked against the documented contract before anything is sent: a param with a documented
 * list of values (blockchain, network, feePriority, ...) takes exactly one of them, as Operations::ALL
 * lists them for this operation; anything else is a ParameterError.
 */
final class Vaults extends Group
{
    /**
     * Returns your Vaults of one type, test or main, one page at a time.
     *
     * The answer carries each Vault's xpubs, which are compared with the pinned ones (an xpub that changed
     * raises VaultKeyChangedError and refuses the answer) and pinned on first sight, so the client needs a
     * pin store (vaultKeysFile or vaultKeyStore).
     *
     * @param array{networkType: 'main'|'test', limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<Vault>
     * @throws ConfigurationError no pin store; nothing is sent
     * @throws VaultodyError
     */
    #[Operation('listVaults')]
    public function listVaults(array $params, array $options = []): Page
    {
        return $this->page('listVaults', Vault::class, $params, $options);
    }

    /**
     * Returns how much of one asset each of your Vaults holds, with the asset's current exchange rate.
     *
     * @param array{assetId: string, blockchain: string, networkType: 'main'|'test'} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('listVaultsByAssetId')]
    public function listVaultsByAssetId(array $params, array $options = []): VaultsByAsset
    {
        return $this->item('listVaultsByAssetId', VaultsByAsset::class, $params, $options);
    }

    /**
     * Returns the assets held in one Vault, whatever their blockchain or network.
     *
     * @param array{vaultId: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('listAssetsByVault')]
    public function listAssetsByVault(array $params, array $options = []): VaultAssets
    {
        return $this->item('listAssetsByVault', VaultAssets::class, $params, $options);
    }

    /**
     * Returns the blockchain transactions of a Vault, one page at a time.
     *
     * @param array{vaultId: string, limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<Transaction>
     * @throws VaultodyError
     */
    #[Operation('listTransactionsByVault')]
    public function listTransactionsByVault(array $params, array $options = []): Page
    {
        return $this->page('listTransactionsByVault', Transaction::class, $params, $options);
    }
}
