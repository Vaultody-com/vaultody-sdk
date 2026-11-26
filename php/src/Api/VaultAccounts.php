<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Api;

use Vaultody\Sdk\Attribute\Operation;
use Vaultody\Sdk\Exception\AddressVerificationError;
use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\RequestOutcomeUnknownError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Model\AddedAsset;
use Vaultody\Sdk\Model\Page;
use Vaultody\Sdk\Model\Transaction;
use Vaultody\Sdk\Model\VaultAccount;
use Vaultody\Sdk\Model\VaultAccountAsset;

/**
 * Vault Accounts: `$vaultody->vaultAccounts`.
 *
 * Every method takes its parameters in one flat array (path, query and body fields by their documented
 * names) and call options in a second one: `context`, a string of your own the API returns unchanged.
 * Params are checked against the documented contract before anything is sent: a param with a documented
 * list of values (blockchain, network, feePriority, ...) takes exactly one of them, as Operations::ALL
 * lists them for this operation; anything else is a ParameterError.
 * The writes (create, update, add asset) are never sent twice by a retry: when their outcome can't be
 * learned they throw RequestOutcomeUnknownError.
 */
final class VaultAccounts extends Group
{
    /**
     * Creates a new Vault Account within a Vault.
     *
     * @param array{vaultId: string, name: string, color: string, isHiddenInDashboard: bool} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the request may have run; look before creating it again
     * @throws VaultodyError
     */
    #[Operation('createVaultAccount')]
    public function createVaultAccount(array $params, array $options = []): VaultAccount
    {
        return $this->item('createVaultAccount', VaultAccount::class, $params, $options);
    }

    /**
     * Returns all Vault Accounts in a Vault, one page at a time.
     *
     * @param array{vaultId: string, isHidden?: bool, isHideEmpty?: bool, limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<VaultAccount>
     * @throws VaultodyError
     */
    #[Operation('listVaultAccounts')]
    public function listVaultAccounts(array $params, array $options = []): Page
    {
        return $this->page('listVaultAccounts', VaultAccount::class, $params, $options);
    }

    /**
     * Returns the details of one Vault Account.
     *
     * @param array{vaultId: string, vaultAccountId: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('getVaultAccountById')]
    public function getVaultAccountById(array $params, array $options = []): VaultAccount
    {
        return $this->item('getVaultAccountById', VaultAccount::class, $params, $options);
    }

    /**
     * Changes the name, color and Dashboard settings of an existing Vault Account.
     *
     * @param array{vaultId: string, vaultAccountId: string, name?: string, color?: string, isHiddenInDashboard?: bool, isFavoriteInDashboard?: bool} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the change may have been made
     * @throws VaultodyError
     */
    #[Operation('updateVaultAccount')]
    public function updateVaultAccount(array $params, array $options = []): VaultAccount
    {
        return $this->item('updateVaultAccount', VaultAccount::class, $params, $options);
    }

    /**
     * Adds an asset to a Vault Account, at an address it already holds (`address`) or at a new one
     * (`label`).
     *
     * The answer's address must be the one sent, and is checked against the vault's pinned xpub before it
     * is returned, so the client needs a pin store (vaultKeysFile or vaultKeyStore).
     *
     * @param array{vaultId: string, vaultAccountId: string, assetId: string, address?: string, label?: string} $params
     * @param array{context?: string} $options
     * @throws ConfigurationError no pin store; nothing is sent
     * @throws AddressVerificationError the address does not derive from the vault's xpub; the answer is refused
     * @throws RequestOutcomeUnknownError the asset may have been added
     * @throws VaultodyError
     */
    #[Operation('addAssetToVaultAccount')]
    public function addAssetToVaultAccount(array $params, array $options = []): AddedAsset
    {
        return $this->item('addAssetToVaultAccount', AddedAsset::class, $params, $options);
    }

    /**
     * Returns the assets a Vault Account holds, with the available amount and USD exchange rate of each,
     * one page at a time.
     *
     * @param array{vaultId: string, vaultAccountId: string, assetUnit?: string, limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<VaultAccountAsset>
     * @throws VaultodyError
     */
    #[Operation('listAssetsByVaultAccountId')]
    public function listAssetsByVaultAccountId(array $params, array $options = []): Page
    {
        return $this->page('listAssetsByVaultAccountId', VaultAccountAsset::class, $params, $options);
    }

    /**
     * Returns the blockchain transactions of one Vault Account, one page at a time.
     *
     * @param array{vaultId: string, vaultAccountId: string, limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<Transaction>
     * @throws VaultodyError
     */
    #[Operation('listTransactionsByVaultAccount')]
    public function listTransactionsByVaultAccount(array $params, array $options = []): Page
    {
        return $this->page('listTransactionsByVaultAccount', Transaction::class, $params, $options);
    }
}
