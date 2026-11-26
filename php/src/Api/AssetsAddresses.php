<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Api;

use Vaultody\Sdk\Attribute\Operation;
use Vaultody\Sdk\Exception\AddressVerificationError;
use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\PaginationError;
use Vaultody\Sdk\Exception\RequestOutcomeUnknownError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Model\AddressBalance;
use Vaultody\Sdk\Model\AddressValidation;
use Vaultody\Sdk\Model\DepositAddress;
use Vaultody\Sdk\Model\Page;
use Vaultody\Sdk\Model\SupportedAsset;
use Vaultody\Sdk\Model\TronResourceOperation;
use Vaultody\Sdk\Model\TronResourceOverview;
use Vaultody\Sdk\Model\VaultAddress;
use Vaultody\Sdk\Model\XrpClassicAddress;
use Vaultody\Sdk\Model\XrpXAddress;

/**
 * Assets and addresses: `$vaultody->assetsAddresses`.
 *
 * Every method takes its parameters in one flat array (path, query and body fields by their documented
 * names) and call options in a second one: `context`, a string of your own the API returns unchanged.
 * Params are checked against the documented contract before anything is sent: a param with a documented
 * list of values (blockchain, network, feePriority, ...) takes exactly one of them, as Operations::ALL
 * lists them for this operation; anything else is a ParameterError.
 * The addresses of a Vault that these methods return are checked against the vault's pinned xpub before
 * they reach you; the status of each check is in the result's meta->addressChecks.
 */
final class AssetsAddresses extends Group
{
    /**
     * Generates an additional receiving/deposit address for a Vault Account on the given blockchain and
     * network.
     *
     * The address is checked against the vault's pinned xpub before it is returned, so the client needs a
     * pin store (vaultKeysFile or vaultKeyStore).
     *
     * @param array{vaultId: string, blockchain: string, network: string, vaultAccountId: string, label: string} $params
     * @param array{context?: string} $options
     * @throws ConfigurationError no pin store; nothing is sent
     * @throws AddressVerificationError the address does not derive from the vault's xpub; the answer is refused
     * @throws RequestOutcomeUnknownError the address may have been generated
     * @throws VaultodyError
     */
    #[Operation('generateDepositAddress')]
    public function generateDepositAddress(array $params, array $options = []): DepositAddress
    {
        return $this->item('generateDepositAddress', DepositAddress::class, $params, $options);
    }

    /**
     * Retrieves the asset balances of one address within a Vault, one page at a time.
     *
     * The docs don't name the field that continues this list, so the SDK does not fetch the next page on
     * its own: iterating past a page that has more throws PaginationError cannot_continue. Ask for the
     * next page with startingAfter.
     *
     * @param array{vaultId: string, address: string, blockchain?: string, assetUnit?: string, limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<AddressBalance>
     * @throws PaginationError
     * @throws VaultodyError
     */
    #[Operation('getAddressBalance')]
    public function getAddressBalance(array $params, array $options = []): Page
    {
        return $this->page('getAddressBalance', AddressBalance::class, $params, $options);
    }

    /**
     * Retrieves the addresses of a Vault Account within a Vault, with their balances, one page at a time.
     *
     * Every address on a page is checked against the vault's pinned xpub; one that does not derive from
     * it refuses the whole page. The client needs a pin store (vaultKeysFile or vaultKeyStore).
     *
     * @param array{vaultId: string, vaultAccountId: string, assetId?: string, blockchain?: string, limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<VaultAddress>
     * @throws ConfigurationError no pin store; nothing is sent
     * @throws AddressVerificationError
     * @throws VaultodyError
     */
    #[Operation('listAddressesByVaultAccountId')]
    public function listAddressesByVaultAccountId(array $params, array $options = []): Page
    {
        return $this->page('listAddressesByVaultAccountId', VaultAddress::class, $params, $options);
    }

    /**
     * Retrieves the assets supported by the platform, one page at a time.
     *
     * @param array{assetUnit?: string, blockchain?: string, networkType?: 'main'|'test', limit?: int, startingAfter?: string} $params
     * @param array{context?: string} $options
     * @return Page<SupportedAsset>
     * @throws VaultodyError
     */
    #[Operation('listSupportedAssets')]
    public function listSupportedAssets(array $params = [], array $options = []): Page
    {
        return $this->page('listSupportedAssets', SupportedAsset::class, $params, $options);
    }

    /**
     * Checks whether an address is valid on the given blockchain and network.
     *
     * @param array{blockchain: string, network: string, address: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('validateAddress')]
    public function validateAddress(array $params, array $options = []): AddressValidation
    {
        return $this->item('validateAddress', AddressValidation::class, $params, $options);
    }

    /**
     * Encodes an XRP classic address and a tag into an X-address.
     *
     * @param array{network: 'mainnet'|'testnet', classicAddress: string, addressTag: string} $params
     *        addressTag is the destination tag, a whole number, given as a string
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('encodeXrpAddress')]
    public function encodeXrpAddress(array $params, array $options = []): XrpXAddress
    {
        return $this->item('encodeXrpAddress', XrpXAddress::class, $params, $options);
    }

    /**
     * Decodes an X-address into its XRP classic address and tag.
     *
     * @param array{network: 'mainnet'|'testnet', xAddress: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('decodeXrpAddress')]
    public function decodeXrpAddress(array $params, array $options = []): XrpClassicAddress
    {
        return $this->item('decodeXrpAddress', XrpClassicAddress::class, $params, $options);
    }

    /**
     * Retrieves an overview of TRX staking and resource allocation for one Tron address.
     *
     * @param array{vaultId: string, blockchain: 'tron', network: 'mainnet'|'nile', address: string} $params
     * @param array{context?: string} $options
     * @throws VaultodyError
     */
    #[Operation('tronResourceOverview')]
    public function tronResourceOverview(array $params, array $options = []): TronResourceOverview
    {
        return $this->item('tronResourceOverview', TronResourceOverview::class, $params, $options);
    }

    /**
     * Manages TRX staking for one Tron address in a Vault: freeze, unfreeze and withdraw TRX, and delegate
     * bandwidth or energy to other addresses.
     *
     * @param array{vaultId: string, blockchain: 'tron', network: 'mainnet'|'nile', fromAddress: string,
     *        type: 'freeze'|'unfreeze'|'withdraw-resource'|'delegate'|'undelegate', resource: 'bandwidth'|'energy',
     *        amount?: string, toAddress?: string, lock?: string, lockPeriod?: string, note?: string} $params
     * @param array{context?: string} $options
     * @throws RequestOutcomeUnknownError the operation may have been requested; look before asking again
     * @throws VaultodyError
     */
    #[Operation('tronResourceManagement')]
    public function tronResourceManagement(array $params, array $options = []): TronResourceOperation
    {
        return $this->item('tronResourceManagement', TronResourceOperation::class, $params, $options);
    }
}
