'use strict';

/**
 * The API methods: one namespace per group of the API reference, one method per documented operation, named
 * by its operationId. scripts/coverage.mjs finds them on a real client and checks them against the contract.
 */

const { Vaults } = require('./vaults');
const { VaultAccounts } = require('./vaultAccounts');
const { AssetsAddresses } = require('./assetsAddresses');
const { Transactions } = require('./transactions');
const { ApiKeys } = require('./apiKeys');

/** Client namespace → its class, in the order of the API reference. */
const NAMESPACES = Object.freeze({
    vaults: Vaults,
    vaultAccounts: VaultAccounts,
    assetsAddresses: AssetsAddresses,
    transactions: Transactions,
    apiKeys: ApiKeys,
});

module.exports = {
    NAMESPACES,
};
