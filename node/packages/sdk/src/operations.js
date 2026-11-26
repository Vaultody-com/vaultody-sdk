'use strict';

/**
 * The operation table: one entry per documented operation, the data the transport builds a request from.
 * Written by hand from the published OpenAPI document (contract/openapi.json; listApiKeySigningKeys from
 * contract/pending/): scripts/coverage.mjs checks every entry's method, path and parameters against it, and
 * test/contract.test.js checks every parameter's schema. contract/overlay.json gives what the document does
 * not say:
 *  - retry: 'read' (GET, and the POSTs that change nothing) is retried and re-signed freely; 'write' is never
 *    signed again with a new nonce once it may have reached the gateway (retry.js);
 *  - paging: 'cursor' (startingAfter + hasMore, cursorField names the item field sent as the next
 *    startingAfter; null while unknown) or 'offset' (limit, offset, total); maxLimit is the largest page.
 *
 * Each param is { name, in: 'path'|'query'|'body', required, schema }: a call takes them all in one flat params
 * object, the table says where each goes, and the API methods check each value against its schema before
 * anything is sent (params.js). A schema is the document's own, in a small subset of JSON Schema: type
 * (string, integer, boolean, object, array), enum, maximum, properties with required, items. The one
 * addition: a page size (limit) must be at least 1, which the document does not state.
 */

const deepFreeze = value => {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        Object.values(value).forEach(deepFreeze);
        Object.freeze(value);
    }

    return value;
};

const STRING = { type: 'string' };
const BOOLEAN = { type: 'boolean' };
// The page size: the document says at most 50 on every list; less than 1 is refused here.
const LIMIT = { type: 'integer', minimum: 1, maximum: 50 };
const oneOf = (...values) => ({ type: 'string', enum: values });
const objectOf = (properties, required = []) => ({ type: 'object', properties, required });
const arrayOf = items => ({ type: 'array', items });

const BLOCKCHAIN = oneOf('arbitrum', 'avalanche', 'base', 'binance-smart-chain', 'bitcoin', 'bitcoin-cash', 'dash', 'dogecoin',
    'ethereum', 'ethereum-classic', 'litecoin', 'optimism', 'polygon', 'solana', 'tron', 'xrp', 'zcash');
const NETWORK = oneOf('mainnet', 'testnet', 'devnet', 'mordor', 'nile', 'fuji', 'sepolia', 'amoy');
const NETWORK_TYPE = oneOf('main', 'test');
const FEE_PRIORITY = oneOf('slow', 'standard', 'fast');
// A fee set by the caller instead of the one Vaultody calculates (the transfer operations).
const FEE_INPUT = objectOf({
    acknowledgeHighFee: BOOLEAN,
    computeUnitPrice: STRING,
    fee: STRING,
    feeLimit: STRING,
    feeRate: STRING,
    gasPrice: STRING,
    maxFeePerGas: STRING,
    maxPriorityFeePerGas: STRING,
    total: STRING,
});

const REQUIRED = true;
const path = (name, schema = STRING) => ({ name, in: 'path', required: true, schema });
const query = (name, schema, required = false) => ({ name, in: 'query', required, schema });
const body = (name, schema, required = false) => ({ name, in: 'body', required, schema });

const op = (operationId, method, operationPath, extra, params) => deepFreeze({
    operationId,
    method,
    path: operationPath,
    params,
    paging: null,
    ...extra,
});

const OPERATIONS = Object.freeze([
    op('addAssetToVaultAccount', 'PUT', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset', { retry: 'write' }, [
        path('vaultAccountId'),
        path('vaultId'),
        body('address', STRING),
        body('assetId', STRING, REQUIRED),
        body('label', STRING),
    ]),
    op('createBatchTransactionRequest', 'POST', '/vaults/{vaultId}/transaction-requests/batch', { retry: 'write' }, [
        path('vaultId'),
        body('feePayer', objectOf({ address: STRING, assetId: STRING }, ['address', 'assetId']), REQUIRED),
        body('feePriority', FEE_PRIORITY),
        body('fromAddress', STRING, REQUIRED),
        body('note', STRING, REQUIRED),
        body('recipients', arrayOf(objectOf({ address: STRING, amount: STRING, assetId: STRING }, ['address', 'amount', 'assetId'])), REQUIRED),
        body('vaultAccountId', STRING),
    ]),
    op('createMultipleTransfer', 'POST', '/vaults/{vaultId}/transaction-requests/multiple-transfer', { retry: 'write' }, [
        path('vaultId'),
        body('assetId', STRING, REQUIRED),
        body('feeInput', FEE_INPUT),
        body('feePriority', FEE_PRIORITY, REQUIRED),
        body('gross', BOOLEAN),
        body('maxFee', STRING),
        body('note', STRING, REQUIRED),
        body('prepareStrategy', oneOf('minimize-dust', 'optimize-size'), REQUIRED),
        body('recipients', arrayOf(objectOf({ address: STRING, amount: STRING }, ['address', 'amount'])), REQUIRED),
        body('vaultAccountId', STRING, REQUIRED),
    ]),
    op('createSingleTransfer', 'POST', '/vaults/{vaultId}/transaction-requests/single-transfer', { retry: 'write' }, [
        path('vaultId'),
        body('amount', STRING, REQUIRED),
        body('assetId', STRING, REQUIRED),
        body('feeInput', FEE_INPUT),
        body('feeOptimization', BOOLEAN),
        body('feePriority', FEE_PRIORITY),
        body('fromAddress', STRING, REQUIRED),
        body('gross', BOOLEAN),
        body('maxFee', STRING),
        body('note', STRING, REQUIRED),
        body('toAddress', STRING, REQUIRED),
        body('vaultAccountId', STRING, REQUIRED),
    ]),
    op('createTronContractInteractionRequest', 'POST', '/vaults/{vaultId}/transaction-requests/contract-interaction', { retry: 'write' }, [
        path('vaultId'),
        body('amount', STRING),
        body('assetId', STRING, REQUIRED),
        body('feeInput', FEE_INPUT),
        body('feeOptimization', BOOLEAN),
        body('feePayer', STRING, REQUIRED),
        body('fromAddress', STRING, REQUIRED),
        body('maxFee', STRING),
        body('method', oneOf('approve', 'transfer-from'), REQUIRED),
        body('note', STRING, REQUIRED),
        body('toAddress', STRING),
        body('vaultAccountId', STRING, REQUIRED),
    ]),
    op('createUtxoTransfer', 'POST', '/vaults/{vaultId}/transaction-requests/utxo-transfer', { retry: 'write' }, [
        path('vaultId'),
        body('assetId', STRING, REQUIRED),
        body('changeData', objectOf({ address: STRING, vaultAccountId: STRING })),
        body('feeInput', FEE_INPUT),
        body('feePayer', STRING),
        body('feePriority', STRING, REQUIRED),
        body('gross', BOOLEAN),
        body('maxFee', STRING),
        body('note', STRING, REQUIRED),
        body('recipients', arrayOf(objectOf({ address: STRING, amount: STRING }, ['address', 'amount'])), REQUIRED),
        body('senders', arrayOf(objectOf({ utxoId: STRING }, ['utxoId'])), REQUIRED),
    ]),
    op('createVaultAccount', 'POST', '/vaults/{vaultId}/vault-account', { retry: 'write' }, [
        path('vaultId'),
        body('color', STRING, REQUIRED),
        body('isHiddenInDashboard', BOOLEAN, REQUIRED),
        body('name', STRING, REQUIRED),
    ]),
    op('decodeXrpAddress', 'GET', '/utils/xrp/{network}/addresses/decode/{xAddress}', { retry: 'read' }, [
        path('network', oneOf('mainnet', 'testnet')),
        path('xAddress'),
    ]),
    op('encodeXrpAddress', 'GET', '/utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}', { retry: 'read' }, [
        path('addressTag'),
        path('classicAddress'),
        path('network', oneOf('mainnet', 'testnet')),
    ]),
    op('estimateTransactionFeeByAssetId', 'POST', '/vaults/{vaultId}/approximate-fee', { retry: 'read' }, [
        path('vaultId'),
        body('amount', STRING),
        body('assetId', STRING),
        body('feeOptimization', BOOLEAN),
        body('feePayer', STRING),
        body('feePayerAssetId', STRING),
        body('feePriority', FEE_PRIORITY),
        body('fromAddress', STRING),
        body('method', oneOf('approve', 'transfer-from')),
        body('prepareStrategy', oneOf('minimize_dust', 'optimize_size')),
        body('recipients', arrayOf(objectOf({ address: STRING, amount: STRING, assetId: STRING }))),
        body('toAddress', STRING),
        body('transactionType', STRING, REQUIRED),
        body('vaultAccountId', STRING, REQUIRED),
    ]),
    op('gasSponsorshipTransfer', 'POST', '/vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer', { retry: 'write' }, [
        path('vaultId'),
        body('amount', STRING, REQUIRED),
        body('assetId', STRING, REQUIRED),
        body('feeInput', FEE_INPUT),
        body('feePayer', STRING, REQUIRED),
        body('feePriority', FEE_PRIORITY),
        body('fromAddress', STRING, REQUIRED),
        body('maxFee', STRING),
        body('note', STRING, REQUIRED),
        body('toAddress', STRING, REQUIRED),
        body('vaultAccountId', STRING, REQUIRED),
    ]),
    op('generateDepositAddress', 'POST', '/vaults/{vaultId}/{blockchain}/{network}/addresses', { retry: 'write' }, [
        path('blockchain', BLOCKCHAIN),
        path('network', NETWORK),
        path('vaultId'),
        body('label', STRING, REQUIRED),
        body('vaultAccountId', STRING, REQUIRED),
    ]),
    op('getAddressBalance', 'GET', '/vaults/{vaultId}/addresses/{address}/balance', { paging: 'cursor', retry: 'read', cursorField: null, maxLimit: 50 }, [
        path('address'),
        query('assetUnit', STRING),
        query('blockchain', BLOCKCHAIN),
        query('limit', LIMIT),
        query('startingAfter', STRING),
        path('vaultId'),
    ]),
    op('getTransactionDetails', 'GET', '/vaults/{vaultId}/{blockchain}/transactions/{transactionId}', { retry: 'read' }, [
        path('blockchain', BLOCKCHAIN),
        path('transactionId'),
        path('vaultId'),
    ]),
    op('getTransactionRequestDetails', 'GET', '/transaction-requests/{transactionRequestId}', { retry: 'read' }, [
        path('transactionRequestId'),
    ]),
    op('getVaultAccountById', 'GET', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/details', { retry: 'read' }, [
        path('vaultAccountId'),
        path('vaultId'),
    ]),
    op('listAddressesByVaultAccountId', 'GET', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses', { paging: 'cursor', retry: 'read', cursorField: 'addressId', maxLimit: 50 }, [
        query('assetId', STRING),
        query('blockchain', BLOCKCHAIN),
        query('limit', LIMIT),
        query('startingAfter', STRING),
        path('vaultAccountId'),
        path('vaultId'),
    ]),
    // Pending in the docs, which say the request takes no parameters: the list covers the calling API key and
    // holds at most two keys. The answer is offset-paged ({ limit, offset, total, items }), always in one page.
    op('listApiKeySigningKeys', 'GET', '/api-keys/current/signing-keys', { paging: 'offset', retry: 'read', maxLimit: 2 }, []),
    op('listAssetsByVault', 'GET', '/vaults/{vaultId}/assets', { retry: 'read' }, [
        path('vaultId'),
    ]),
    op('listAssetsByVaultAccountId', 'GET', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets', { paging: 'cursor', retry: 'read', cursorField: 'assetId', maxLimit: 50 }, [
        query('assetUnit', STRING),
        query('limit', LIMIT),
        query('startingAfter', STRING),
        path('vaultAccountId'),
        path('vaultId'),
    ]),
    op('listSupportedAssets', 'GET', '/supported-assets', { paging: 'cursor', retry: 'read', cursorField: 'assetId', maxLimit: 50 }, [
        query('assetUnit', STRING),
        query('blockchain', BLOCKCHAIN),
        query('limit', LIMIT),
        query('networkType', NETWORK_TYPE),
        query('startingAfter', STRING),
    ]),
    op('listTransactionsByVault', 'GET', '/vaults/{vaultId}/transactions', { paging: 'cursor', retry: 'read', cursorField: 'id', maxLimit: 50 }, [
        query('limit', LIMIT),
        query('startingAfter', STRING),
        path('vaultId'),
    ]),
    op('listTransactionsByVaultAccount', 'GET', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions', { paging: 'cursor', retry: 'read', cursorField: 'id', maxLimit: 50 }, [
        query('limit', LIMIT),
        query('startingAfter', STRING),
        path('vaultAccountId'),
        path('vaultId'),
    ]),
    op('listUtxos', 'GET', '/vaults/{vaultId}/utxos', { paging: 'cursor', retry: 'read', cursorField: 'utxoId', maxLimit: 50 }, [
        query('address', STRING),
        query('assetId', STRING),
        query('isSpent', BOOLEAN),
        query('limit', LIMIT),
        query('startingAfter', STRING),
        query('vaultAccountId', STRING),
        path('vaultId'),
    ]),
    op('listVaultAccounts', 'GET', '/vaults/{vaultId}/vault-accounts/details', { paging: 'cursor', retry: 'read', cursorField: 'vaultAccountId', maxLimit: 50 }, [
        query('isHidden', BOOLEAN),
        query('isHideEmpty', BOOLEAN),
        query('limit', LIMIT),
        query('startingAfter', STRING),
        path('vaultId'),
    ]),
    op('listVaults', 'GET', '/vaults/{networkType}', { paging: 'cursor', retry: 'read', cursorField: 'id', maxLimit: 50 }, [
        query('limit', LIMIT),
        path('networkType', NETWORK_TYPE),
        query('startingAfter', STRING),
    ]),
    op('listVaultsByAssetId', 'GET', '/assets/{assetId}/{blockchain}/vaults/{networkType}', { retry: 'read' }, [
        path('assetId'),
        path('blockchain', BLOCKCHAIN),
        path('networkType', NETWORK_TYPE),
    ]),
    op('tronResourceManagement', 'POST', '/vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource', { retry: 'write' }, [
        path('blockchain', oneOf('tron')),
        path('fromAddress'),
        path('network', oneOf('mainnet', 'nile')),
        path('vaultId'),
        body('amount', STRING),
        body('lock', STRING),
        body('lockPeriod', STRING),
        body('note', STRING),
        body('resource', oneOf('bandwidth', 'energy'), REQUIRED),
        body('toAddress', STRING),
        body('type', oneOf('freeze', 'unfreeze', 'withdraw-resource', 'delegate', 'undelegate'), REQUIRED),
    ]),
    op('tronResourceOverview', 'GET', '/vaults/{vaultId}/{blockchain}/{network}/{address}/overview', { retry: 'read' }, [
        path('address'),
        path('blockchain', oneOf('tron')),
        path('network', oneOf('mainnet', 'nile')),
        path('vaultId'),
    ]),
    op('updateVaultAccount', 'PUT', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit', { retry: 'write' }, [
        path('vaultAccountId'),
        path('vaultId'),
        body('color', STRING),
        body('isFavoriteInDashboard', BOOLEAN),
        body('isHiddenInDashboard', BOOLEAN),
        body('name', STRING),
    ]),
    op('validateAddress', 'POST', '/info/{blockchain}/{network}/addresses/validate', { retry: 'read' }, [
        path('blockchain', BLOCKCHAIN),
        path('network', NETWORK),
        body('address', STRING, REQUIRED),
    ]),
    op('validateUtxoTransfer', 'POST', '/vaults/{vaultId}/transaction-requests/utxo-transfer/validate', { retry: 'read' }, [
        path('vaultId'),
        body('assetId', STRING, REQUIRED),
        body('changeData', objectOf({ address: STRING, vaultAccountId: STRING })),
        body('feePayer', STRING),
        body('feePriority', STRING, REQUIRED),
        body('gross', BOOLEAN),
        body('maxFee', STRING),
        body('note', STRING),
        body('recipients', arrayOf(objectOf({ address: STRING, amount: STRING }, ['address', 'amount'])), REQUIRED),
        body('senders', arrayOf(objectOf({ utxoId: STRING }, ['utxoId'])), REQUIRED),
    ]),
]);

const BY_ID = new Map(OPERATIONS.map(entry => [entry.operationId, entry]));

/**
 * @param {string} operationId
 * @returns {Object|null} the operation's entry, or null when the table has none
 */
const operationById = operationId => BY_ID.get(operationId) || null;

module.exports = {
    OPERATIONS,
    operationById,
};
