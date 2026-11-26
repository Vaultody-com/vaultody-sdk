'use strict';

/**
 * Assets and addresses: deposit addresses (checked against the vault xpub), balances, the supported assets, address
 * validation, XRP address encoding, and Tron resources.
 *
 * The `assetsAddresses` namespace of the client: `vaultody.assetsAddresses.<operationId>(params, options)`. Each
 * method takes its fields in one flat `params` object (path, query and body together), checks them against the API
 * reference before anything is sent, and goes through the client's whole pipeline: signed, verified, retried by its
 * class.
 */

const { bindOperations } = require('./common');

/** @typedef {import('./common').Blockchain} Blockchain */
/** @typedef {import('./common').Network} Network */
/** @typedef {import('./common').NetworkType} NetworkType */
/** @typedef {import('./common').CallOptions} CallOptions */

/**
 * @typedef {Object} DecodeXrpAddressParams The params of decodeXrpAddress: Decode XRP Address.
 * @property {'mainnet'|'testnet'} network The XRP network the X-address is for: `mainnet` or `testnet`.
 * @property {string} xAddress The X-address to decode. It starts with `X` on `mainnet` and with `T` on `testnet`.
 */

/**
 * @typedef {Object} DecodeXrpAddressResult data.item of decodeXrpAddress.
 * @property {string} [classicAddress] The classic XRP address inside the X-address. It starts with `r`.
 * @property {string} [tag] The destination tag inside the X-address.
 */

/**
 * @typedef {Object} EncodeXrpAddressParams The params of encodeXrpAddress: Encode XRP Address.
 * @property {string} addressTag The destination tag to encode with the address: a whole number.
 * @property {string} classicAddress The classic XRP address to encode. It starts with `r`.
 * @property {'mainnet'|'testnet'} network The XRP network the X-address is for: `mainnet` or `testnet`.
 */

/**
 * @typedef {Object} EncodeXrpAddressResult data.item of encodeXrpAddress.
 * @property {string} [xAddress] The X-address that holds both the classic address and the tag.
 */

/**
 * @typedef {Object} GenerateDepositAddressParams The params of generateDepositAddress: Generate Deposit Address.
 * @property {Blockchain} blockchain The blockchain to generate the address on, for example `ethereum`, `bitcoin` or `tron`.
 * @property {string} label A name for the address, so you can tell it apart in the Dashboard and in API responses. 3 to 100 characters.
 * @property {Network} network The network of the blockchain: `mainnet`, or a test network such as `sepolia`, `testnet` or `nile`.
 * @property {string} vaultAccountId The ID of the Vault Account that receives the new address.
 * @property {string} vaultId The ID of the Vault that holds the Vault Account.
 */

/**
 * @typedef {Object} GenerateDepositAddressResult data.item of generateDepositAddress.
 * @property {string} [address] The new deposit address.
 * @property {number} [createdTimestamp] When the address was created, as a Unix timestamp in seconds.
 * @property {string} [label] A name for the address, so you can tell it apart in the Dashboard and in API responses. 3 to 100 characters.
 */

/**
 * @typedef {Object} GetAddressBalanceParams The params of getAddressBalance: Get Address Balance.
 * @property {string} address The address to read the balances of.
 * @property {string} [assetUnit] The asset's symbol, for example `ETH` or `USDC`. As a query parameter, it returns only this asset.
 * @property {Blockchain} [blockchain] The blockchain the balance belongs to, for example `ethereum` or `tron`. As a query parameter, it returns only balances on this blockchain; leave it out to get every blockchain the address is used on.
 * @property {number} [limit] How many balances to return on one page.
 * @property {string} [startingAfter] The ID of the last item on the previous page. The next page starts after it; leave it out for the first page.
 * @property {string} vaultId The ID of the Vault that holds the address.
 */

/**
 * @typedef {Object} GetAddressBalanceAssetData The amounts of the asset on the address, and how the asset is defined on the blockchain.
 * @property {string} [allocatedAmount] The amount reserved for transactions that are still pending, so it cannot be sent right now.
 * @property {string} [availableAmount] The amount that is free to send now.
 * @property {string} [contractAddress] The token's smart contract address. Applies only when `type` is `TOKEN`.
 * @property {string} [standard] The standard the asset is built on, for example `ERC-20` on Ethereum, `TRC-20` on Tron or `SPL` on Solana.
 * @property {string} [totalAmount] The total amount of the asset on the address: the available amount plus the allocated amount.
 */

/**
 * @typedef {Object} GetAddressBalanceResult One item of a page of getAddressBalance.
 * @property {GetAddressBalanceAssetData} [assetData] The amounts of the asset on the address, and how the asset is defined on the blockchain.
 * @property {string} [assetId] The asset's ID in Vaultody.
 * @property {string} [assetUnit] The asset's symbol, for example `ETH` or `USDC`. As a query parameter, it returns only this asset.
 * @property {string} [blockchain] The blockchain the balance belongs to, for example `ethereum` or `tron`. As a query parameter, it returns only balances on this blockchain; leave it out to get every blockchain the address is used on.
 * @property {string} [exchangeRateUnit] The current exchange rate of one unit of the asset.
 * @property {string} [type] `COIN` for the blockchain's native coin, `TOKEN` for a token issued by a smart contract.
 */

/**
 * @typedef {Object} ListAddressesByVaultAccountIdParams The params of listAddressesByVaultAccountId: List Addresses by Vault Account ID.
 * @property {string} [assetId] Returns only addresses this asset has been added to. Take the ID from [List Supported Assets](/api/assets-addresses/list-supported-assets).
 * @property {Blockchain} [blockchain] The blockchain of the address, for example `bitcoin`, `ethereum` or `tron`. As a query parameter, it returns only addresses on this blockchain.
 * @property {number} [limit] How many addresses to return on one page.
 * @property {string} [startingAfter] The `addressId` of the last address on the previous page. The next page starts after it; leave it out for the first page.
 * @property {string} vaultAccountId The ID of the Vault Account whose addresses to list.
 * @property {string} vaultId The ID of the Vault that holds the Vault Account.
 */

/**
 * @typedef {Object} ListAddressesByVaultAccountIdBalance
 * @property {string} [amount] The balance of the asset on this address, in the asset's own unit.
 * @property {string} [assetId] The asset's ID in Vaultody.
 * @property {string} [assetUnit] The asset's symbol, for example `BTC`, `ETH` or `USDT`.
 */

/**
 * @typedef {Object} ListAddressesByVaultAccountIdResult One item of a page of listAddressesByVaultAccountId.
 * @property {string} [address] The address on the blockchain.
 * @property {string} [addressId] The address's ID in Vaultody. Pass it as `startingAfter` to get the next page.
 * @property {string} [addressIndex] The derivation index of the address within the Vault Account. The first address on a blockchain has index `0`.
 * @property {Array<ListAddressesByVaultAccountIdBalance>} [balances] The balance of each asset added to the address.
 * @property {string} [blockchain] The blockchain of the address, for example `bitcoin`, `ethereum` or `tron`. As a query parameter, it returns only addresses on this blockchain.
 * @property {number} [createdTimestamp] When the address was created, as a Unix timestamp in seconds.
 * @property {string} [label] The name given to the address when it was created.
 */

/**
 * @typedef {Object} ListSupportedAssetsParams The params of listSupportedAssets: List Supported Assets.
 * @property {string} [assetUnit] The asset's symbol, for example `BTC`, `ETH` or `USDC`. As a query parameter, it returns only assets with this symbol.
 * @property {Blockchain} [blockchain] The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`. As a query parameter, it returns only assets on this blockchain.
 * @property {number} [limit] How many assets to return on one page.
 * @property {NetworkType} [networkType] Returns only assets on main networks (`main`) or only on test networks (`test`).
 * @property {string} [startingAfter] The `assetId` of the last asset on the previous page. The next page starts after it; leave it out for the first page.
 */

/**
 * @typedef {Object} ListSupportedAssetsPrice The asset's current price.
 * @property {string} [amount] The price of one unit of the asset.
 * @property {number} [calculationTimestamp] When the price was calculated, as a Unix timestamp in seconds.
 * @property {string} [unit] The currency of the price.
 */

/**
 * @typedef {Object} ListSupportedAssetsResult One item of a page of listSupportedAssets.
 * @property {string} [active] Whether Vaultody currently supports the asset. The list returns supported assets only.
 * @property {string} [assetId] The asset's ID in Vaultody. Pass it to the calls that add, send or estimate an asset.
 * @property {string} [assetName] The asset's name.
 * @property {string} [assetType] `COIN` for a blockchain's native coin, `TOKEN` for a token issued by a smart contract.
 * @property {string} [assetUnit] The asset's symbol, for example `BTC`, `ETH` or `USDC`. As a query parameter, it returns only assets with this symbol.
 * @property {string} [blockchain] The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`. As a query parameter, it returns only assets on this blockchain.
 * @property {string} [contractAddress] The token's smart contract address. Applies to tokens only.
 * @property {string} [contractType] The token standard, for example `ERC-20`, `BEP-20` or `TRC-20`. Applies to tokens only.
 * @property {string} [decimals] The number of decimal places the asset uses.
 * @property {string} [network] The network the asset lives on: `mainnet`, or a test network such as `sepolia` or `nile`.
 * @property {ListSupportedAssetsPrice} [price] The asset's current price.
 */

/**
 * @typedef {Object} TronResourceManagementParams The params of tronResourceManagement: Tron Resource Management.
 * @property {string} [amount] How much TRX to freeze, unfreeze, delegate or undelegate. Leave it out for `withdraw-resource`.
 * @property {'tron'} blockchain The blockchain of the address. Always `tron`.
 * @property {string} fromAddress The Tron address in the Vault that stakes, unstakes, withdraws or delegates the TRX.
 * @property {string} [lock] For `delegate`: `true` locks the delegation so it cannot be cancelled during `lockPeriod`; `false` leaves it cancellable at any time.
 * @property {string} [lockPeriod] For a locked delegation, how long it stays locked, in Tron blocks of 3 seconds: 28800 is one day. At most 864000 (30 days), and at least what remains of the previous lock on the same resource.
 * @property {'mainnet'|'nile'} network The Tron network: `mainnet`, or the `nile` test network.
 * @property {string} [note] A note of your own about the transaction.
 * @property {'bandwidth'|'energy'} resource The resource to stake for or delegate: `bandwidth` or `energy`.
 * @property {string} [toAddress] For `delegate` and `undelegate`: the Tron address that receives the resources, or that they are taken back from.
 * @property {'freeze'|'unfreeze'|'withdraw-resource'|'delegate'|'undelegate'} type The staking operation: `freeze`, `unfreeze`, `withdraw-resource`, `delegate` or `undelegate`.
 * @property {string} vaultId The ID of the Vault that holds `fromAddress`.
 */

/**
 * @typedef {Object} TronResourceManagementDestination
 * @property {string} [address] The address that receives the resources.
 * @property {string} [amount] The amount of TRX in the operation.
 * @property {string} [amountUnit] The unit of the amount.
 */

/**
 * @typedef {Object} TronResourceManagementSource The address the operation is made from.
 * @property {string} [address] The address the operation is made from: `fromAddress`.
 */

/**
 * @typedef {Object} TronResourceManagementResult data.item of tronResourceManagement.
 * @property {string} [blockchain] The blockchain of the address. Always `tron`.
 * @property {Array<TronResourceManagementDestination>} [destination] Where the resources go.
 * @property {string} [id] The ID of the transaction request.
 * @property {string} [network] The Tron network: `mainnet`, or the `nile` test network.
 * @property {string} [resource] The resource to stake for or delegate: `bandwidth` or `energy`.
 * @property {TronResourceManagementSource} [source] The address the operation is made from.
 * @property {string} [status] The status of the transaction request, for example `created`, or `await-approval-l2` while it waits for a second-level approval.
 * @property {string} [type] The staking operation: `freeze`, `unfreeze`, `withdraw-resource`, `delegate` or `undelegate`.
 * @property {string} [vaultId] The ID of the Vault that holds `fromAddress`.
 */

/**
 * @typedef {Object} TronResourceOverviewParams The params of tronResourceOverview: Tron Resource Overview.
 * @property {string} address The Tron address to get the overview of.
 * @property {'tron'} blockchain The blockchain of the address. Always `tron`.
 * @property {'mainnet'|'nile'} network The Tron network: `mainnet`, or the `nile` test network.
 * @property {string} vaultId The ID of the Vault that holds the address.
 */

/**
 * @typedef {Object} TronResourceOverviewBalance The address's TRX, split by what it can be used for.
 * @property {string} [available] TRX that is not staked or delegated and can be sent.
 * @property {string} [availableFrozen] TRX staked by the address for its own resources, not counting what is delegated to other addresses.
 * @property {string} [delegated] TRX staked by the address to provide resources to other addresses.
 * @property {string} [total] The total TRX balance: `available`, `availableFrozen`, `delegated` and `withdrawableAmount` together.
 * @property {string} [unit] The unit of the amounts.
 * @property {string} [withdrawableAmount] 0), so it can be withdrawn back to the available balance.
 */

/**
 * @typedef {Object} TronResourceOverviewFrozenResources The TRX staked for each kind of resource.
 * @property {string} [bandwidth] TRX staked for bandwidth.
 * @property {string} [energy] TRX staked for energy.
 * @property {string} [tronPower] TRX staked for Tron Power, used for voting.
 */

/**
 * @typedef {Object} TronResourceOverviewBandwidth The address's bandwidth.
 * @property {string} [acquiredDelegated] The TRX equivalent of the bandwidth other addresses delegate to this address.
 * @property {number} [available] The bandwidth the address can use now: the free daily allowance, plus bandwidth from its own staked TRX and from delegations.
 * @property {string} [delegated] The TRX equivalent of the bandwidth this address delegates to other addresses.
 * @property {number} [freeLimit] The free bandwidth the Tron network gives every address each day.
 * @property {number} [freeUsed] How much of the free bandwidth has been used.
 * @property {number} [limit] The total bandwidth obtained by staking.
 * @property {number} [used] How much of the bandwidth obtained by staking has been used.
 */

/**
 * @typedef {Object} TronResourceOverviewEnergy The address's energy.
 * @property {string} [acquiredDelegated] The TRX equivalent of the energy other addresses delegate to this address.
 * @property {number} [available] The energy the address can use now, from its own staked TRX and from delegations.
 * @property {string} [delegated] The TRX equivalent of the energy this address delegates to other addresses.
 * @property {number} [limit] The total energy obtained by staking.
 * @property {number} [used] How much energy has been used.
 */

/**
 * @typedef {Object} TronResourceOverviewResources The bandwidth and energy the address has, and how much of it is used.
 * @property {TronResourceOverviewBandwidth} [bandwidth] The address's bandwidth.
 * @property {TronResourceOverviewEnergy} [energy] The address's energy.
 */

/**
 * @typedef {Object} TronResourceOverviewResult data.item of tronResourceOverview.
 * @property {string} [address] The Tron address to get the overview of.
 * @property {TronResourceOverviewBalance} [balance] The address's TRX, split by what it can be used for.
 * @property {TronResourceOverviewFrozenResources} [frozenResources] The TRX staked for each kind of resource.
 * @property {string} [network] The Tron network: `mainnet`, or the `nile` test network.
 * @property {TronResourceOverviewResources} [resources] The bandwidth and energy the address has, and how much of it is used.
 */

/**
 * @typedef {Object} ValidateAddressParams The params of validateAddress: Validate Address.
 * @property {string} address The address to check.
 * @property {Blockchain} blockchain The blockchain to check the address against, for example `bitcoin`, `ethereum` or `tron`.
 * @property {Network} network The network of the blockchain: `mainnet`, or a test network such as `testnet`, `sepolia` or `nile`.
 */

/**
 * @typedef {Object} ValidateAddressResult data.item of validateAddress.
 * @property {string} [address] The address to check.
 * @property {boolean} [isValid] `true` when the address is valid on the blockchain and network, otherwise `false`.
 */

class AssetsAddresses {
    #invoke;

    /** @param {function(string, Object, Object): Promise<Object>} invoke the client's call */
    constructor(invoke) {
        this.#invoke = invoke;
    }

    /**
     * Generate Deposit Address: `POST /vaults/{vaultId}/{blockchain}/{network}/addresses`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {GenerateDepositAddressParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<GenerateDepositAddressResult>>}
     */
    generateDepositAddress(params, options) {
        return this.#invoke('generateDepositAddress', params, options);
    }

    /**
     * Get Address Balance: `GET /vaults/{vaultId}/addresses/{address}/balance`.
     *
     * A list, but not paged automatically: the API reference does not say which item field continues it, so
     * iterating throws PaginationError (cursor_unknown). Pass `startingAfter` yourself.
     *
     * @param {GetAddressBalanceParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<GetAddressBalanceResult>}
     */
    getAddressBalance(params, options) {
        return this.#invoke('getAddressBalance', params, options);
    }

    /**
     * List Addresses by Vault Account ID: `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `addressId`).
     *
     * @param {ListAddressesByVaultAccountIdParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListAddressesByVaultAccountIdResult>}
     */
    listAddressesByVaultAccountId(params, options) {
        return this.#invoke('listAddressesByVaultAccountId', params, options);
    }

    /**
     * List Supported Assets: `GET /supported-assets`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `assetId`).
     *
     * @param {ListSupportedAssetsParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListSupportedAssetsResult>}
     */
    listSupportedAssets(params, options) {
        return this.#invoke('listSupportedAssets', params, options);
    }

    /**
     * Validate Address: `POST /info/{blockchain}/{network}/addresses/validate`.
     *
     * Changes nothing, so it is retried like a read.
     *
     * @param {ValidateAddressParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<ValidateAddressResult>>}
     */
    validateAddress(params, options) {
        return this.#invoke('validateAddress', params, options);
    }

    /**
     * Encode XRP Address: `GET /utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}`.
     *
     * @param {EncodeXrpAddressParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<EncodeXrpAddressResult>>}
     */
    encodeXrpAddress(params, options) {
        return this.#invoke('encodeXrpAddress', params, options);
    }

    /**
     * Decode XRP Address: `GET /utils/xrp/{network}/addresses/decode/{xAddress}`.
     *
     * @param {DecodeXrpAddressParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<DecodeXrpAddressResult>>}
     */
    decodeXrpAddress(params, options) {
        return this.#invoke('decodeXrpAddress', params, options);
    }

    /**
     * Tron Resource Overview: `GET /vaults/{vaultId}/{blockchain}/{network}/{address}/overview`.
     *
     * @param {TronResourceOverviewParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<TronResourceOverviewResult>>}
     */
    tronResourceOverview(params, options) {
        return this.#invoke('tronResourceOverview', params, options);
    }

    /**
     * Tron Resource Management: `POST /vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {TronResourceManagementParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<TronResourceManagementResult>>}
     */
    tronResourceManagement(params, options) {
        return this.#invoke('tronResourceManagement', params, options);
    }
}

module.exports = {
    AssetsAddresses: bindOperations(AssetsAddresses),
};
