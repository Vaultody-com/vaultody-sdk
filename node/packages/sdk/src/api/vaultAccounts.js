'use strict';

/**
 * Vault Accounts: create, read, update and list the accounts of a Vault, add assets to them, and list their assets
 * and transactions.
 *
 * The `vaultAccounts` namespace of the client: `vaultody.vaultAccounts.<operationId>(params, options)`. Each method
 * takes its fields in one flat `params` object (path, query and body together), checks them against the API
 * reference before anything is sent, and goes through the client's whole pipeline: signed, verified, retried by its
 * class.
 */

const { bindOperations } = require('./common');

/** @typedef {import('./common').CallOptions} CallOptions */

/**
 * @typedef {Object} AddAssetToVaultAccountParams The params of addAssetToVaultAccount: Add Asset to Vault Account.
 * @property {string} [address] In the request, an address the Vault Account already holds, to which the asset will be added; required when `label` is not provided. In the response, the address the asset was added to, newly derived when you passed `label`.
 * @property {string} assetId Unique identifier of the asset to be added. Retrieve it from List Supported Assets.
 * @property {string} [label] The label for the deposit address. Required when `address` is not provided: in that case Vaultody derives a new deposit address for the asset's blockchain and network and returns it in the response.
 * @property {string} vaultAccountId The ID of the Vault Account to add the asset to.
 * @property {string} vaultId The ID of the Vault that holds the Vault Account.
 */

/**
 * @typedef {Object} AddAssetToVaultAccountResult data.item of addAssetToVaultAccount.
 * @property {string} [address] In the request, an address the Vault Account already holds, to which the asset will be added; required when `label` is not provided. In the response, the address the asset was added to, newly derived when you passed `label`.
 * @property {string} [assetUnit] The symbol of the added asset, for example `ETH`, `BTC` or `USDT`.
 * @property {string} [balance] The current balance of the asset at the address.
 * @property {string} [contractAddress] The token's smart contract address, when the asset is a token.
 * @property {string} [decimals] The number of decimal places the asset uses.
 */

/**
 * @typedef {Object} CreateVaultAccountParams The params of createVaultAccount: Create Vault Account.
 * @property {string} color The color the Vault Account is shown in, as a valid hex code.
 * @property {boolean} isHiddenInDashboard Whether the Vault Account is hidden in the Dashboard.
 * @property {string} name The name of the Vault Account, for example the user it belongs to.
 * @property {string} vaultId The ID of the Vault the Vault Account belongs to.
 */

/**
 * @typedef {Object} CreateVaultAccountBalance
 * @property {string} [assetId] The asset's ID in Vaultody.
 * @property {string} [assetName] The asset's name, for example `Ethereum` or `Bitcoin`.
 * @property {string} [assetUnit] The asset's symbol, for example `ETH` or `BTC`.
 * @property {string} [blockchain] The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {string} [exchangeRateUnit] The currency of the exchange rate.
 * @property {string} [latestExchangeRateToUSD] The asset's latest exchange rate to USD.
 * @property {string} [totalAmount] The total amount of the asset in the Vault Account.
 */

/**
 * @typedef {Object} CreateVaultAccountResult data.item of createVaultAccount.
 * @property {string} [addressesCount] How many addresses the Vault Account has.
 * @property {Array<CreateVaultAccountBalance>} [balances] One entry per asset in the Vault Account, with the amount it holds.
 * @property {number} [createdAt] When the Vault Account was created, as a Unix timestamp in seconds.
 * @property {string} [index] The Vault Account's sequential number within its Vault.
 * @property {boolean} [isHiddenInDashboard] Whether the Vault Account is hidden in the Dashboard.
 * @property {string} [vaultAccountColour] The color the Vault Account is shown in, as a hex code.
 * @property {string} [vaultAccountId] The ID of the new Vault Account. Save it: the calls for this Vault Account take it in their path.
 * @property {string} [vaultAccountName] The name of the Vault Account.
 * @property {string} [vaultId] The ID of the Vault the Vault Account belongs to.
 */

/**
 * @typedef {Object} GetVaultAccountByIdParams The params of getVaultAccountById: Get Vault Account by ID.
 * @property {string} vaultAccountId The ID of the Vault Account.
 * @property {string} vaultId The ID of the Vault the Vault Account belongs to.
 */

/**
 * @typedef {Object} GetVaultAccountByIdBalance
 * @property {string} [assetId] The asset's ID in Vaultody.
 * @property {string} [assetName] The asset's name, for example `Ethereum` or `Bitcoin`.
 * @property {string} [assetUnit] The asset's symbol, for example `ETH` or `BTC`.
 * @property {string} [blockchain] The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {string} [exchangeRateUnit] The currency of the exchange rate.
 * @property {string} [latestExchangeRateToUSD] The asset's latest exchange rate to USD.
 * @property {string} [totalAmount] The total amount of the asset in the Vault Account.
 */

/**
 * @typedef {Object} GetVaultAccountByIdResult data.item of getVaultAccountById.
 * @property {string} [addressesCount] How many addresses the Vault Account has.
 * @property {Array<GetVaultAccountByIdBalance>} [balances] One entry per asset in the Vault Account, with the amount it holds.
 * @property {number} [createdAt] When the Vault Account was created, as a Unix timestamp in seconds.
 * @property {string} [index] The Vault Account's sequential number within its Vault.
 * @property {boolean} [isFavoriteInDashboard] Whether the Vault Account is marked as a favorite in the Dashboard.
 * @property {boolean} [isHiddenInDashboard] Whether the Vault Account is hidden in the Dashboard.
 * @property {string} [vaultAccountColour] The color the Vault Account is shown in, as a hex code.
 * @property {string} [vaultAccountId] The ID of the Vault Account.
 * @property {string} [vaultAccountName] The name of the Vault Account.
 * @property {string} [vaultId] The ID of the Vault the Vault Account belongs to.
 */

/**
 * @typedef {Object} ListAssetsByVaultAccountIdParams The params of listAssetsByVaultAccountId: List Assets by Vault Account ID.
 * @property {string} [assetUnit] The asset's symbol, for example `BTC`, `ETH` or `USDT`. As a query parameter, it returns only assets with this symbol (not case-sensitive).
 * @property {number} [limit] How many assets to return on one page.
 * @property {string} [startingAfter] The `assetId` of the last asset on the previous page. The next page starts after it; leave it out for the first page.
 * @property {string} vaultAccountId The ID of the Vault Account whose assets to return.
 * @property {string} vaultId The ID of the Vault the Vault Account belongs to.
 */

/**
 * @typedef {Object} ListAssetsByVaultAccountIdResult One item of a page of listAssetsByVaultAccountId.
 * @property {string} [assetId] The asset's ID in Vaultody.
 * @property {string} [assetUnit] The asset's symbol, for example `BTC`, `ETH` or `USDT`. As a query parameter, it returns only assets with this symbol (not case-sensitive).
 * @property {string} [availableAmount] The amount of the asset the Vault Account can send now: its balance minus the amount reserved for outgoing transaction requests that are not yet mined.
 * @property {string} [blockchain] The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {string} [exchangeRateToUsd] The asset's current exchange rate to USD.
 */

/**
 * @typedef {Object} ListTransactionsByVaultAccountParams The params of listTransactionsByVaultAccount: List Transactions by Vault Account.
 * @property {number} [limit] How many transactions to return on one page.
 * @property {string} [startingAfter] The `id` of the last transaction on the previous page. The next page starts after it; leave it out for the first page.
 * @property {string} vaultAccountId The ID of the Vault Account whose transactions to return.
 * @property {string} vaultId The ID of the Vault that holds the Vault Account.
 */

/**
 * @typedef {Object} ListTransactionsByVaultAccountRecipient
 * @property {string} [address] The recipient's address.
 * @property {string} [addressType] The type of the address, for example `deposit`.
 * @property {string} [amount] The amount the address receives.
 * @property {string} [amountUnit] The symbol of the asset received, for example `BTC` or `ETH`.
 * @property {boolean} [isVaultAddress] Whether the address belongs to this Vault Account.
 * @property {string} [label] The label of the address.
 */

/**
 * @typedef {Object} ListTransactionsByVaultAccountSender
 * @property {string} [address] The sender's address.
 * @property {string} [amount] The amount the address sends.
 * @property {string} [amountUnit] The symbol of the asset sent, for example `BTC` or `ETH`.
 * @property {boolean} [isVaultAddress] Whether the address belongs to this Vault Account.
 * @property {string} [label] The label of the address.
 */

/**
 * @typedef {Object} ListTransactionsByVaultAccountTransactionFee The network fee paid for the transaction.
 * @property {string} [amount] The fee amount.
 * @property {string} [amountUnit] The symbol of the asset the fee is paid in.
 */

/**
 * @typedef {Object} ListTransactionsByVaultAccountResult One item of a page of listTransactionsByVaultAccount.
 * @property {string} [blockchain] The blockchain the transaction is on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {number} [createdTimestamp] When Vaultody recorded the transaction, as a Unix timestamp in seconds.
 * @property {string} [direction] The direction of the transaction for this Vault Account: `incoming` or `outgoing`.
 * @property {boolean} [hasTokenTransfer] Whether the transaction transfers any tokens.
 * @property {string} [id] The transaction's ID in Vaultody. Pass it as `startingAfter` to get the next page.
 * @property {boolean} [isInternal] Whether the transaction includes internal transactions.
 * @property {string} [minedInBlockHeight] The height of the block the transaction was mined in.
 * @property {string} [network] The network the transaction is on: `mainnet`, or a test network such as `testnet`, `sepolia` or `nile`.
 * @property {Array<ListTransactionsByVaultAccountRecipient>} [recipients] Every address that receives assets in the transaction.
 * @property {Array<ListTransactionsByVaultAccountSender>} [senders] Every address that sends assets in the transaction.
 * @property {string} [status] The status of the transaction, for example `confirmed`.
 * @property {ListTransactionsByVaultAccountTransactionFee} [transactionFee] The network fee paid for the transaction.
 * @property {string} [transactionId] The transaction's hash on the blockchain.
 */

/**
 * @typedef {Object} ListVaultAccountsParams The params of listVaultAccounts: List Vault Accounts.
 * @property {boolean} [isHidden] When `true`, returns only the Vault Accounts hidden in the Dashboard (`isHiddenInDashboard` is `true`).
 * @property {boolean} [isHideEmpty] When `true`, returns only the Vault Accounts that have a positive balance.
 * @property {number} [limit] How many Vault Accounts to return on one page.
 * @property {string} [startingAfter] The `vaultAccountId` of the last Vault Account on the previous page. The next page starts after it; leave it out for the first page.
 * @property {string} vaultId The ID of the Vault the Vault Accounts belong to.
 */

/**
 * @typedef {Object} ListVaultAccountsBalance
 * @property {string} [assetId] The asset's ID in Vaultody.
 * @property {string} [assetName] The asset's name, for example `Ethereum` or `Bitcoin`.
 * @property {string} [assetUnit] The asset's symbol, for example `ETH` or `BTC`.
 * @property {string} [blockchain] The blockchain the asset lives on, for example `bitcoin`, `ethereum` or `tron`.
 * @property {string} [exchangeRateUnit] The currency of the exchange rate.
 * @property {string} [latestExchangeRateToUSD] The asset's latest exchange rate to USD.
 * @property {string} [totalAmount] The total amount of the asset in the Vault Account.
 */

/**
 * @typedef {Object} ListVaultAccountsResult One item of a page of listVaultAccounts.
 * @property {string} [addressesCount] How many addresses the Vault Account has.
 * @property {Array<ListVaultAccountsBalance>} [balances] One entry per asset in the Vault Account, with the amount it holds.
 * @property {number} [createdAt] When the Vault Account was created, as a Unix timestamp in seconds.
 * @property {number} [index] The Vault Account's sequential number within its Vault.
 * @property {boolean} [isFavoriteInDashboard] Whether the Vault Account is marked as a favorite in the Dashboard.
 * @property {boolean} [isHiddenInDashboard] Whether the Vault Account is hidden in the Dashboard.
 * @property {string} [vaultAccountColour] The color the Vault Account is shown in, as a hex code.
 * @property {string} [vaultAccountId] The Vault Account's ID.
 * @property {string} [vaultAccountName] The name of the Vault Account.
 * @property {string} [vaultId] The ID of the Vault the Vault Accounts belong to.
 */

/**
 * @typedef {Object} UpdateVaultAccountParams The params of updateVaultAccount: Update Vault Account.
 * @property {string} [color] The new color of the Vault Account, as a valid hex code.
 * @property {boolean} [isFavoriteInDashboard] Whether to mark the Vault Account as a favorite in the Dashboard.
 * @property {boolean} [isHiddenInDashboard] Whether the Vault Account is hidden in the Dashboard.
 * @property {string} [name] The new name of the Vault Account.
 * @property {string} vaultAccountId The ID of the Vault Account.
 * @property {string} vaultId The ID of the Vault the Vault Account belongs to.
 */

/**
 * @typedef {Object} UpdateVaultAccountResult data.item of updateVaultAccount.
 * @property {string} [addressesCount] How many addresses the Vault Account has.
 * @property {number} [createdAt] When the Vault Account was created, as a Unix timestamp in seconds.
 * @property {string} [index] The Vault Account's sequential number within its Vault.
 * @property {boolean} [isHiddenInDashboard] Whether the Vault Account is hidden in the Dashboard.
 * @property {string} [vaultAccountColour] The color the Vault Account is shown in, as a hex code.
 * @property {string} [vaultAccountId] The ID of the Vault Account.
 * @property {string} [vaultAccountName] The name of the Vault Account.
 * @property {string} [vaultId] The ID of the Vault the Vault Account belongs to.
 */

class VaultAccounts {
    #invoke;

    /** @param {function(string, Object, Object): Promise<Object>} invoke the client's call */
    constructor(invoke) {
        this.#invoke = invoke;
    }

    /**
     * Create Vault Account: `POST /vaults/{vaultId}/vault-account`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {CreateVaultAccountParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<CreateVaultAccountResult>>}
     */
    createVaultAccount(params, options) {
        return this.#invoke('createVaultAccount', params, options);
    }

    /**
     * List Vault Accounts: `GET /vaults/{vaultId}/vault-accounts/details`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `vaultAccountId`).
     *
     * @param {ListVaultAccountsParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListVaultAccountsResult>}
     */
    listVaultAccounts(params, options) {
        return this.#invoke('listVaultAccounts', params, options);
    }

    /**
     * Get Vault Account by ID: `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/details`.
     *
     * @param {GetVaultAccountByIdParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<GetVaultAccountByIdResult>>}
     */
    getVaultAccountById(params, options) {
        return this.#invoke('getVaultAccountById', params, options);
    }

    /**
     * Update Vault Account: `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {UpdateVaultAccountParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<UpdateVaultAccountResult>>}
     */
    updateVaultAccount(params, options) {
        return this.#invoke('updateVaultAccount', params, options);
    }

    /**
     * Add Asset to Vault Account: `PUT /vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset`.
     *
     * A write: never sent again with a new signature once it may have reached the API; when its outcome
     * can't be learned, RequestOutcomeUnknownError.
     *
     * @param {AddAssetToVaultAccountParams} params
     * @param {CallOptions} [options]
     * @returns {Promise<import('./common').ItemResponse<AddAssetToVaultAccountResult>>}
     */
    addAssetToVaultAccount(params, options) {
        return this.#invoke('addAssetToVaultAccount', params, options);
    }

    /**
     * List Assets by Vault Account ID: `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `assetId`).
     *
     * @param {ListAssetsByVaultAccountIdParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListAssetsByVaultAccountIdResult>}
     */
    listAssetsByVaultAccountId(params, options) {
        return this.#invoke('listAssetsByVaultAccountId', params, options);
    }

    /**
     * List Transactions by Vault Account: `GET /vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions`.
     *
     * A list: the promise gives the first page; iterating it gives every item, page after page (the next page starts
     * after the last item's `id`).
     *
     * @param {ListTransactionsByVaultAccountParams} params
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListTransactionsByVaultAccountResult>}
     */
    listTransactionsByVaultAccount(params, options) {
        return this.#invoke('listTransactionsByVaultAccount', params, options);
    }
}

module.exports = {
    VaultAccounts: bindOperations(VaultAccounts),
};
