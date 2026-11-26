'use strict';

/**
 * Vaults: list the Vaults, the assets of a Vault, the Vaults that hold an asset, and the transactions of a Vault.
 *
 * The `vaults` namespace of the client: `vaultody.vaults.<operationId>(params, options)`. Each method takes its
 * fields in one flat `params` object (path, query and body together), checks them against the API reference before
 * anything is sent, and goes through the client's whole pipeline: signed, verified, retried by its class.
 */

const { bindOperations } = require('./common');

/** @typedef {import('./common').Blockchain} Blockchain */
/** @typedef {import('./common').NetworkType} NetworkType */
/** @typedef {import('./common').CallOptions} CallOptions */

/**
 * @typedef {Object} ListAssetsByVaultParams The params of listAssetsByVault: List Assets by Vault.
 * @property {string} vaultId The ID of the Vault whose assets to return.
 */

/**
 * @typedef {Object} ListAssetsByVaultAssetData The asset's amounts in the Vault and, for a token, its contract details.
 * @property {string} [allocatedAmount] The amount of the asset reserved for outgoing transaction requests that are not yet mined.
 * @property {string} [availableAmount] The amount of the asset that can be sent now: the total minus the allocated amount.
 * @property {string} [contractAddress] The token's smart contract address. Empty for coins.
 * @property {string} [standard] The token standard, for example `ERC-20` or `TRC-20`. Empty for coins.
 * @property {string} [totalAmount] The total amount of the asset in the Vault.
 */

/**
 * @typedef {Object} ListAssetsByVaultAsset
 * @property {ListAssetsByVaultAssetData} [assetData] The asset's amounts in the Vault and, for a token, its contract details.
 * @property {string} [assetId] The asset's ID in Vaultody.
 * @property {string} [assetUnit] The asset's symbol, for example `BTC`, `ETH` or `USDT`.
 * @property {string} [blockchain] The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {string} [exchangeRateUnit] The asset's current exchange rate to USD.
 * @property {string} [network] The network the asset lives on: `mainnet`, or a test network such as `sepolia` or `nile`.
 * @property {string} [type] `COIN` for a blockchain's native coin, `TOKEN` for a token issued by a smart contract.
 */

/**
 * @typedef {Object} ListAssetsByVaultResult data.item of listAssetsByVault.
 * @property {Array<ListAssetsByVaultAsset>} [assets] One entry per asset held in the Vault.
 */

/**
 * @typedef {Object} ListTransactionsByVaultParams The params of listTransactionsByVault: List Transactions by Vault.
 * @property {number} [limit] How many transactions to return on one page.
 * @property {string} [startingAfter] The `id` of the last transaction on the previous page. The next page starts after it; leave it out for the first page.
 * @property {string} vaultId The specific Vault ID.
 */

/**
 * @typedef {Object} ListTransactionsByVaultRecipient
 * @property {string} [address] The recipient's address.
 * @property {string} [addressType] The type of the address, for example `deposit`.
 * @property {string} [amount] The amount the address receives.
 * @property {string} [amountUnit] The symbol of the asset received, for example `ETH` or `BTC`.
 * @property {string} [isVaultAddress] Whether the address belongs to this Vault.
 * @property {string} [label] The label of the address.
 */

/**
 * @typedef {Object} ListTransactionsByVaultSender
 * @property {string} [address] The sender's address.
 * @property {string} [addressType] The type of the address, for example `deposit`.
 * @property {string} [amount] The amount the address sends.
 * @property {string} [amountUnit] The symbol of the asset sent, for example `ETH` or `BTC`.
 * @property {string} [isVaultAddress] Whether the address belongs to this Vault.
 * @property {string} [label] The label of the address.
 */

/**
 * @typedef {Object} ListTransactionsByVaultTransactionFee The network fee paid for the transaction.
 * @property {string} [amount] The fee amount.
 * @property {string} [amountUnit] The symbol of the asset the fee is paid in.
 */

/**
 * @typedef {Object} ListTransactionsByVaultResult One item of a page of listTransactionsByVault.
 * @property {string} [blockchain] The blockchain the transaction is on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {number} [createdTimestamp] When Vaultody recorded the transaction, as a Unix timestamp in seconds.
 * @property {string} [direction] The direction of the transaction for this Vault: `incoming` or `outgoing`.
 * @property {boolean} [hasTokenTransfer] Whether the transaction transfers any tokens.
 * @property {string} [id] The transaction's ID in Vaultody. Pass it as `startingAfter` to get the next page.
 * @property {boolean} [isInternal] Whether the transaction includes internal transactions.
 * @property {string} [minedInBlockHeight] The height of the block the transaction was mined in.
 * @property {string} [network] The network the transaction is on: `mainnet`, or a test network such as `sepolia` or `nile`.
 * @property {Array<ListTransactionsByVaultRecipient>} [recipients] Every address that receives assets in the transaction.
 * @property {Array<ListTransactionsByVaultSender>} [senders] Every address that sends assets in the transaction.
 * @property {string} [status] The status of the transaction, for example `confirmed`.
 * @property {ListTransactionsByVaultTransactionFee} [transactionFee] The network fee paid for the transaction.
 * @property {string} [transactionId] The transaction's hash on the blockchain.
 */

/**
 * @typedef {Object} ListVaultsByAssetIdParams The params of listVaultsByAssetId: List Vaults by Asset ID.
 * @property {string} assetId The asset's ID in Vaultody, from List Supported Assets.
 * @property {Blockchain} blockchain The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {NetworkType} networkType Which Vaults to look in: `test` for Vaults on test networks, `main` for Vaults on main networks.
 */

/**
 * @typedef {Object} ListVaultsByAssetIdVault
 * @property {string} [allocatedAmount] The amount of the asset reserved for outgoing transaction requests that are not yet mined.
 * @property {string} [availableAmount] The amount of the asset that can be sent now: the total minus the allocated amount.
 * @property {string} [totalAmount] The total amount of the asset in the Vault.
 * @property {string} [vaultColor] The color the Vault is shown in, as a hex code.
 * @property {string} [vaultId] The Vault's ID.
 * @property {string} [vaultName] The name given to the Vault in the Dashboard.
 * @property {string} [vaultType] The type of the Vault. Always `default`.
 */

/**
 * @typedef {Object} ListVaultsByAssetIdResult data.item of listVaultsByAssetId.
 * @property {string} [exchangeRateUnit] The asset's current exchange rate to USD.
 * @property {Array<ListVaultsByAssetIdVault>} [vaults] One entry per Vault, with the amount of the asset that Vault holds.
 */

/**
 * @typedef {Object} ListVaultsParams The params of listVaults: List Vaults.
 * @property {number} [limit] How many Vaults to return on one page.
 * @property {NetworkType} networkType Which Vaults to return: `test` for Vaults on test networks, `main` for Vaults on main networks.
 * @property {string} [startingAfter] The `id` of the last Vault on the previous page. The next page starts after it; leave it out for the first page.
 */

/**
 * @typedef {Object} ListVaultsResult One item of a page of listVaults.
 * @property {boolean} [backuped] Whether the Vault has been backed up.
 * @property {number} [changeAddressesCount] How many change addresses the Vault has. Change addresses receive the remainder of UTXO transactions.
 * @property {string} [color] The color the Vault is shown in, as a hex code.
 * @property {number} [createdTimestamp] When the Vault was created, as a Unix timestamp in seconds.
 * @property {number} [depositAddressesCount] How many deposit addresses the Vault has.
 * @property {string} [id] The Vault's ID. Pass it as `vaultId` to the calls that work on this Vault.
 * @property {string} [name] The name given to the Vault in the Dashboard.
 * @property {string} [type] The type of the Vault: `test` or `main`.
 */

class Vaults {
    #invoke;

    /** @param {function(string, Object, Object): Promise<Object>} invoke the client's call */
    constructor(invoke) {
        this.#invoke = invoke;
    }

    /**
     * List Vaults: `GET /vaults/{networkType}`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `id`).
     *
     * @param {ListVaultsParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListVaultsResult>}
     */
    listVaults(params, options) {
        return this.#invoke('listVaults', params, options);
    }

    /**
     * List Vaults by Asset ID: `GET /assets/{assetId}/{blockchain}/vaults/{networkType}`.
     *
     * @param {ListVaultsByAssetIdParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<ListVaultsByAssetIdResult>>}
     */
    listVaultsByAssetId(params, options) {
        return this.#invoke('listVaultsByAssetId', params, options);
    }

    /**
     * List Assets by Vault: `GET /vaults/{vaultId}/assets`.
     *
     * @param {ListAssetsByVaultParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<ListAssetsByVaultResult>>}
     */
    listAssetsByVault(params, options) {
        return this.#invoke('listAssetsByVault', params, options);
    }

    /**
     * List Transactions by Vault: `GET /vaults/{vaultId}/transactions`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `id`).
     *
     * @param {ListTransactionsByVaultParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListTransactionsByVaultResult>}
     */
    listTransactionsByVault(params, options) {
        return this.#invoke('listTransactionsByVault', params, options);
    }
}

module.exports = {
    Vaults: bindOperations(Vaults),
};
