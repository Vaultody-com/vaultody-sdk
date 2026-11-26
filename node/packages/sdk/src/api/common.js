'use strict';

/**
 * What every API method shares: the call options, the shapes of what a method returns, the enums several
 * operations use, and the binding of each method to its entry in the operation table.
 *
 * The models (the *Params and *Result typedefs in each group's file) are written by hand from the published
 * OpenAPI document; test/contract.test.js checks every field name, type and required flag against it.
 * Responses: the document marks no response field as required, so every field is optional, and the API may
 * add fields at any time: they pass through untouched. Amounts are strings.
 */

const { operationById } = require('../operations');

/**
 * @typedef {Object} CallOptions
 * @property {string} [context] a value of your own the API returns unchanged in `meta.context` (in the query
 *           of a GET, in the body of a POST or PUT)
 * @property {AbortSignal} [signal] aborts the call
 */

/**
 * @typedef {Object} AddressCheck
 * @property {string|null} address
 * @property {'verified'|'unverified'|'not_verifiable'} status verified: derived from the vault's pinned xpub,
 *           pinned from a signed answer; unverified: the same, pinned from an unsigned one (trust on first use);
 *           not_verifiable: the answer carries no derivation path, or the vault has no MPC keys
 */

/**
 * @typedef {Object} ResponseMeta
 * @property {string} operationId
 * @property {string|null} requestId quote it when you contact support
 * @property {string|null} apiVersion
 * @property {string|null} context the `context` option, returned unchanged
 * @property {boolean} replayed the gateway answered a resent request with the first answer
 * @property {'verified'|'absent'} signature whether the answer was signed and verified
 * @property {string} [rootId] the response-signing root that verified it
 * @property {number} [signedAt] the signed response timestamp, Unix seconds
 * @property {Array<AddressCheck>} [addressChecks] generateDepositAddress, listAddressesByVaultAccountId and
 *           addAssetToVaultAccount: one per address in the answer, in order
 * @property {Array<{ vaultId: string, outcome: string }>} [vaultKeys] listVaults: how each vault compared with
 *           its pinned xpubs
 */

/**
 * The answer of an operation that returns one item.
 *
 * @template T
 * @typedef {Object} ItemResponse
 * @property {T} item data.item of the answer
 * @property {ResponseMeta} meta
 */

/**
 * One page of a list operation (page.js).
 *
 * @template T
 * @typedef {Object} ResultPage
 * @property {Array<T>} items
 * @property {boolean} hasMore
 * @property {number|null} limit
 * @property {string|null} [startingAfter] cursor-paged lists
 * @property {number|null} [offset] offset-paged lists
 * @property {number|null} [total] offset-paged lists
 * @property {ResponseMeta} meta
 * @property {function(): Promise<ResultPage<T>|null>} nextPage the next page, or null after the last
 * @property {function({ maxItems?: number }=): AsyncIterable<T>} autoPaging every item from this page on;
 *           after the loop, its `stop` says why it ended: 'end', 'empty_page' or 'max_items'
 */

/**
 * What a list operation returns: a promise of its first page that is also an async iterable over every item
 * of the list, page after page. The first page is asked for once, whichever way it is used.
 *
 *   const page = await vaultody.vaults.listVaults({ networkType: 'main' });       // one page
 *   for await (const vault of vaultody.vaults.listVaults({ networkType: 'main' })) { ... }   // every item
 *
 * @template T
 * @typedef {Promise<ResultPage<T>> & AsyncIterable<T>} PageRequest
 */

/** @typedef {'arbitrum'|'avalanche'|'base'|'binance-smart-chain'|'bitcoin'|'bitcoin-cash'|'dash'|'dogecoin'|'ethereum'|'ethereum-classic'|'litecoin'|'optimism'|'polygon'|'solana'|'tron'|'xrp'|'zcash'} Blockchain */
/** @typedef {'mainnet'|'testnet'|'devnet'|'mordor'|'nile'|'fuji'|'sepolia'|'amoy'} Network */
/** @typedef {'main'|'test'} NetworkType */
/** @typedef {'slow'|'standard'|'fast'} FeePriority */

/**
 * A fee you set yourself instead of the fee Vaultody calculates from `feePriority`, on the transfer
 * operations. Send either `total` or the fee fields your blockchain takes, not both. Which fields a blockchain
 * takes, and in which unit, is on each operation's page in the API reference: a field the blockchain does not
 * take makes the transaction request fail when it is prepared.
 *
 * @typedef {Object} FeeInput
 * @property {boolean} [acknowledgeHighFee] Confirms a fee far above Vaultody's own estimate.
 * @property {string} [computeUnitPrice] Not supported on any blockchain today.
 * @property {string} [fee] XRP: the fee in drops. UTXO-based blockchains: the fee for the whole transaction in the
 *           coin's smallest unit.
 * @property {string} [feeLimit] Tron: the most TRX, in SUN, you accept to spend on the transaction's energy.
 * @property {string} [feeRate] UTXO-based blockchains: satoshis per virtual byte.
 * @property {string} [gasPrice] BNB Smart Chain, Ethereum Classic and Avalanche: the price per unit of gas, in wei.
 * @property {string} [maxFeePerGas] Ethereum, Polygon, Optimism, Base and Arbitrum: the most per unit of gas, in wei.
 * @property {string} [maxPriorityFeePerGas] Ethereum, Polygon, Optimism, Base and Arbitrum: the tip per unit of
 *           gas, in wei.
 * @property {string} [total] The whole fee, in the blockchain's native coin.
 */

/**
 * Wraps the first page of a list call so that it can also be iterated item by item.
 *
 * @param {Promise<Object>} firstPage
 * @returns {Promise<Object> & AsyncIterable<Object>}
 */
function pageRequest(firstPage) {
    return Object.defineProperty(firstPage, Symbol.asyncIterator, {
        value: async function* items() {
            const page = await firstPage;
            yield* page.autoPaging();
        },
    });
}

/**
 * Marks every method of a group's class with the operation it calls (the coverage check and the client find
 * them by it). A method is named exactly as its operationId; one without an entry in the table is a bug, so
 * loading the module fails.
 *
 * @param {Function} Group
 * @returns {Function} Group
 */
function bindOperations(Group) {
    for (const name of Object.getOwnPropertyNames(Group.prototype)) {
        if (name === 'constructor') {
            continue;
        }
        const method = Group.prototype[name];
        if (typeof method !== 'function' || !operationById(name)) {
            throw new Error(`${Group.name}.${name} is not an operation of the table`);
        }
        Object.defineProperty(method, 'operationId', { value: name, enumerable: true });
    }

    return Object.freeze(Group);
}

module.exports = {
    bindOperations,
    pageRequest,
};
