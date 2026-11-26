<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

use Vaultody\Sdk\Transport\Operation;

/**
 * The operation table: one entry per documented operation, the data the client methods build, check and
 * send a request from. scripts/coverage.mjs checks every entry's method, path and parameters against the
 * published OpenAPI document (contract/openapi.json; listApiKeySigningKeys from contract/pending/), and
 * tests/ApiMethodsTest.php checks the types, the overlay fields and the models against it too.
 *
 * Each entry:
 *  - operationId, group (the client namespace: the docs group), method, path;
 *  - params: [['name', 'in' => 'path'|'query'|'body', 'required', 'type']]: one flat params argument holds
 *    them all; 'type' is 'string', 'integer', 'boolean', or ['type' => 'object', 'properties' => [...],
 *    'required' => [...]] / ['type' => 'array', 'items' => ...] / ['type' => 'integer', 'minimum', 'maximum']
 *    / ['type' => 'string', 'enum' => [...]] (the values that operation documents for the API version the SDK
 *    pins; a param without a documented list takes any string);
 *  - retry (contract/overlay.json): 'read' is retried and re-signed freely (GET, and the POSTs that change
 *    nothing), 'write' is never signed again once it may have reached the gateway;
 *  - paging: 'none', 'cursor' (startingAfter + hasMore; cursorField names the item field sent as the next
 *    startingAfter, null while the docs don't say) or 'offset'; maxLimit: the largest page;
 *  - addresses: an Operation::ADDRESSES_* constant when the answer carries vault addresses, checked against
 *    the vault's pinned xpub; vaultList: the answer lists vaults with their xpubs (pinned and compared);
 *  - model: the class of the answer's item (of each list item for a list).
 *
 * `context` is not a param: it is a call option of every method.
 */
final class Operations
{
    private const LIMIT = ['type' => 'integer', 'minimum' => 1, 'maximum' => 50];

    // The values each operation documents for a param; a value outside its list is refused before sending.
    private const BLOCKCHAIN = ['type' => 'string', 'enum' => [
        'arbitrum', 'avalanche', 'base', 'binance-smart-chain', 'bitcoin', 'bitcoin-cash', 'dash', 'dogecoin', 'ethereum',
        'ethereum-classic', 'litecoin', 'optimism', 'polygon', 'solana', 'tron', 'xrp', 'zcash',
    ]];
    private const NETWORK = ['type' => 'string', 'enum' => ['mainnet', 'testnet', 'devnet', 'sepolia', 'mordor', 'nile', 'fuji', 'amoy']];
    private const NETWORK_TYPE = ['type' => 'string', 'enum' => ['main', 'test']];
    private const XRP_NETWORK = ['type' => 'string', 'enum' => ['mainnet', 'testnet']];
    private const TRON_BLOCKCHAIN = ['type' => 'string', 'enum' => ['tron']];
    private const TRON_NETWORK = ['type' => 'string', 'enum' => ['mainnet', 'nile']];
    private const TRON_RESOURCE = ['type' => 'string', 'enum' => ['bandwidth', 'energy']];
    private const TRON_OPERATION = ['type' => 'string', 'enum' => ['freeze', 'unfreeze', 'withdraw-resource', 'delegate', 'undelegate']];
    private const FEE_PRIORITY = ['type' => 'string', 'enum' => ['slow', 'standard', 'fast']];
    private const CONTRACT_METHOD = ['type' => 'string', 'enum' => ['approve', 'transfer-from']];
    /** createMultipleTransfer documents these with hyphens ... */
    private const PREPARE_STRATEGY = ['type' => 'string', 'enum' => ['minimize-dust', 'optimize-size']];
    /** ... and estimateTransactionFeeByAssetId with underscores: each operation takes its own. */
    private const ESTIMATE_PREPARE_STRATEGY = ['type' => 'string', 'enum' => ['minimize_dust', 'optimize_size']];

    private const FEE_INPUT = ['type' => 'object', 'properties' => [
        'acknowledgeHighFee' => 'boolean',
        'computeUnitPrice' => 'string',
        'fee' => 'string',
        'feeLimit' => 'string',
        'feeRate' => 'string',
        'gasPrice' => 'string',
        'maxFeePerGas' => 'string',
        'maxPriorityFeePerGas' => 'string',
        'total' => 'string',
    ], 'required' => []];

    /** Recipients of the UTXO transfers: an address and an amount each. */
    private const UTXO_RECIPIENTS = ['type' => 'array', 'items' => ['type' => 'object', 'properties' => [
        'address' => 'string',
        'amount' => 'string',
    ], 'required' => ['address', 'amount']]];

    private const UTXO_SENDERS = ['type' => 'array', 'items' => ['type' => 'object', 'properties' => [
        'utxoId' => 'string',
    ], 'required' => ['utxoId']]];

    private const UTXO_CHANGE_DATA = ['type' => 'object', 'properties' => [
        'address' => 'string',
        'vaultAccountId' => 'string',
    ], 'required' => []];

    private const BATCH_RECIPIENTS = ['type' => 'array', 'items' => ['type' => 'object', 'properties' => [
        'address' => 'string',
        'amount' => 'string',
        'assetId' => 'string',
    ], 'required' => ['address', 'amount', 'assetId']]];

    private const BATCH_FEE_PAYER = ['type' => 'object', 'properties' => [
        'address' => 'string',
        'assetId' => 'string',
    ], 'required' => ['address', 'assetId']];

    private const ESTIMATE_RECIPIENTS = ['type' => 'array', 'items' => ['type' => 'object', 'properties' => [
        'address' => 'string',
        'amount' => 'string',
        'assetId' => 'string',
    ], 'required' => []]];

    private const NONE = [
        'paging' => 'none', 'cursorField' => null, 'maxLimit' => null, 'addresses' => null, 'vaultList' => false,
    ];

    /**
     * @var list<array{operationId: string, group: string, method: string, path: string,
     *      params: list<array{name: string, in: string, required: bool, type: mixed}>, retry: string,
     *      paging: string, cursorField: ?string, maxLimit: ?int, addresses: ?string, vaultList: bool,
     *      model: class-string<Model\Model>}>
     */
    public const ALL = [
        // vaults
        [
            'operationId' => 'listVaults', 'group' => 'vaults', 'method' => 'GET', 'path' => '/vaults/{networkType}',
            'params' => [
                ['name' => 'networkType', 'in' => 'path', 'required' => true, 'type' => self::NETWORK_TYPE],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'id', 'maxLimit' => 50, 'addresses' => null, 'vaultList' => true,
            'model' => Model\Vault::class,
        ],
        [
            'operationId' => 'listVaultsByAssetId', 'group' => 'vaults', 'method' => 'GET', 'path' => '/assets/{assetId}/{blockchain}/vaults/{networkType}',
            'params' => [
                ['name' => 'assetId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'blockchain', 'in' => 'path', 'required' => true, 'type' => self::BLOCKCHAIN],
                ['name' => 'networkType', 'in' => 'path', 'required' => true, 'type' => self::NETWORK_TYPE],
            ],
            'retry' => 'read', 'model' => Model\VaultsByAsset::class,
        ] + self::NONE,
        [
            'operationId' => 'listAssetsByVault', 'group' => 'vaults', 'method' => 'GET', 'path' => '/vaults/{vaultId}/assets',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'read', 'model' => Model\VaultAssets::class,
        ] + self::NONE,
        [
            'operationId' => 'listTransactionsByVault', 'group' => 'vaults', 'method' => 'GET', 'path' => '/vaults/{vaultId}/transactions',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'id', 'maxLimit' => 50, 'addresses' => null, 'vaultList' => false,
            'model' => Model\Transaction::class,
        ],

        // vault accounts
        [
            'operationId' => 'createVaultAccount', 'group' => 'vaultAccounts', 'method' => 'POST', 'path' => '/vaults/{vaultId}/vault-account',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'color', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'isHiddenInDashboard', 'in' => 'body', 'required' => true, 'type' => 'boolean'],
                ['name' => 'name', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'write', 'model' => Model\VaultAccount::class,
        ] + self::NONE,
        [
            'operationId' => 'listVaultAccounts', 'group' => 'vaultAccounts', 'method' => 'GET', 'path' => '/vaults/{vaultId}/vault-accounts/details',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'isHidden', 'in' => 'query', 'required' => false, 'type' => 'boolean'],
                ['name' => 'isHideEmpty', 'in' => 'query', 'required' => false, 'type' => 'boolean'],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'vaultAccountId', 'maxLimit' => 50, 'addresses' => null, 'vaultList' => false,
            'model' => Model\VaultAccount::class,
        ],
        [
            'operationId' => 'getVaultAccountById', 'group' => 'vaultAccounts', 'method' => 'GET', 'path' => '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/details',
            'params' => [
                ['name' => 'vaultAccountId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'read', 'model' => Model\VaultAccount::class,
        ] + self::NONE,
        [
            'operationId' => 'updateVaultAccount', 'group' => 'vaultAccounts', 'method' => 'PUT', 'path' => '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/edit',
            'params' => [
                ['name' => 'vaultAccountId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'color', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'isFavoriteInDashboard', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'isHiddenInDashboard', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'name', 'in' => 'body', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'write', 'model' => Model\VaultAccount::class,
        ] + self::NONE,
        [
            'operationId' => 'addAssetToVaultAccount', 'group' => 'vaultAccounts', 'method' => 'PUT', 'path' => '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset',
            'params' => [
                ['name' => 'vaultAccountId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'address', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'label', 'in' => 'body', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'write', 'paging' => 'none', 'cursorField' => null, 'maxLimit' => null,
            'addresses' => Operation::ADDRESSES_ADD_ASSET, 'vaultList' => false,
            'model' => Model\AddedAsset::class,
        ],
        [
            'operationId' => 'listAssetsByVaultAccountId', 'group' => 'vaultAccounts', 'method' => 'GET', 'path' => '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-assets',
            'params' => [
                ['name' => 'vaultAccountId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'assetUnit', 'in' => 'query', 'required' => false, 'type' => 'string'],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'assetId', 'maxLimit' => 50, 'addresses' => null, 'vaultList' => false,
            'model' => Model\VaultAccountAsset::class,
        ],
        [
            'operationId' => 'listTransactionsByVaultAccount', 'group' => 'vaultAccounts', 'method' => 'GET', 'path' => '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/transactions',
            'params' => [
                ['name' => 'vaultAccountId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'id', 'maxLimit' => 50, 'addresses' => null, 'vaultList' => false,
            'model' => Model\Transaction::class,
        ],

        // assets and addresses
        [
            'operationId' => 'generateDepositAddress', 'group' => 'assetsAddresses', 'method' => 'POST', 'path' => '/vaults/{vaultId}/{blockchain}/{network}/addresses',
            'params' => [
                ['name' => 'blockchain', 'in' => 'path', 'required' => true, 'type' => self::BLOCKCHAIN],
                ['name' => 'network', 'in' => 'path', 'required' => true, 'type' => self::NETWORK],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'label', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultAccountId', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'write', 'paging' => 'none', 'cursorField' => null, 'maxLimit' => null,
            'addresses' => Operation::ADDRESSES_IN_PATH, 'vaultList' => false,
            'model' => Model\DepositAddress::class,
        ],
        [
            'operationId' => 'getAddressBalance', 'group' => 'assetsAddresses', 'method' => 'GET', 'path' => '/vaults/{vaultId}/addresses/{address}/balance',
            'params' => [
                ['name' => 'address', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'assetUnit', 'in' => 'query', 'required' => false, 'type' => 'string'],
                ['name' => 'blockchain', 'in' => 'query', 'required' => false, 'type' => self::BLOCKCHAIN],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            // The docs say only "the ID of the last item" for its cursor, so the SDK does not page it on its own.
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => null, 'maxLimit' => 50, 'addresses' => null, 'vaultList' => false,
            'model' => Model\AddressBalance::class,
        ],
        [
            'operationId' => 'listAddressesByVaultAccountId', 'group' => 'assetsAddresses', 'method' => 'GET', 'path' => '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses',
            'params' => [
                ['name' => 'vaultAccountId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'query', 'required' => false, 'type' => 'string'],
                ['name' => 'blockchain', 'in' => 'query', 'required' => false, 'type' => self::BLOCKCHAIN],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'addressId', 'maxLimit' => 50,
            'addresses' => Operation::ADDRESSES_IN_ITEMS, 'vaultList' => false,
            'model' => Model\VaultAddress::class,
        ],
        [
            'operationId' => 'listSupportedAssets', 'group' => 'assetsAddresses', 'method' => 'GET', 'path' => '/supported-assets',
            'params' => [
                ['name' => 'assetUnit', 'in' => 'query', 'required' => false, 'type' => 'string'],
                ['name' => 'blockchain', 'in' => 'query', 'required' => false, 'type' => self::BLOCKCHAIN],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'networkType', 'in' => 'query', 'required' => false, 'type' => self::NETWORK_TYPE],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'assetId', 'maxLimit' => 50, 'addresses' => null, 'vaultList' => false,
            'model' => Model\SupportedAsset::class,
        ],
        [
            'operationId' => 'validateAddress', 'group' => 'assetsAddresses', 'method' => 'POST', 'path' => '/info/{blockchain}/{network}/addresses/validate',
            'params' => [
                ['name' => 'blockchain', 'in' => 'path', 'required' => true, 'type' => self::BLOCKCHAIN],
                ['name' => 'network', 'in' => 'path', 'required' => true, 'type' => self::NETWORK],
                ['name' => 'address', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'read', 'model' => Model\AddressValidation::class,
        ] + self::NONE,
        [
            'operationId' => 'encodeXrpAddress', 'group' => 'assetsAddresses', 'method' => 'GET', 'path' => '/utils/xrp/{network}/addresses/encode/{classicAddress}/{addressTag}',
            'params' => [
                ['name' => 'addressTag', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'classicAddress', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'network', 'in' => 'path', 'required' => true, 'type' => self::XRP_NETWORK],
            ],
            'retry' => 'read', 'model' => Model\XrpXAddress::class,
        ] + self::NONE,
        [
            'operationId' => 'decodeXrpAddress', 'group' => 'assetsAddresses', 'method' => 'GET', 'path' => '/utils/xrp/{network}/addresses/decode/{xAddress}',
            'params' => [
                ['name' => 'network', 'in' => 'path', 'required' => true, 'type' => self::XRP_NETWORK],
                ['name' => 'xAddress', 'in' => 'path', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'read', 'model' => Model\XrpClassicAddress::class,
        ] + self::NONE,
        [
            'operationId' => 'tronResourceOverview', 'group' => 'assetsAddresses', 'method' => 'GET', 'path' => '/vaults/{vaultId}/{blockchain}/{network}/{address}/overview',
            'params' => [
                ['name' => 'address', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'blockchain', 'in' => 'path', 'required' => true, 'type' => self::TRON_BLOCKCHAIN],
                ['name' => 'network', 'in' => 'path', 'required' => true, 'type' => self::TRON_NETWORK],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'read', 'model' => Model\TronResourceOverview::class,
        ] + self::NONE,
        [
            'operationId' => 'tronResourceManagement', 'group' => 'assetsAddresses', 'method' => 'POST', 'path' => '/vaults/{vaultId}/{blockchain}/{network}/addresses/{fromAddress}/manage-resource',
            'params' => [
                ['name' => 'blockchain', 'in' => 'path', 'required' => true, 'type' => self::TRON_BLOCKCHAIN],
                ['name' => 'fromAddress', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'network', 'in' => 'path', 'required' => true, 'type' => self::TRON_NETWORK],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'amount', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'lock', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'lockPeriod', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'note', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'resource', 'in' => 'body', 'required' => true, 'type' => self::TRON_RESOURCE],
                ['name' => 'toAddress', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'type', 'in' => 'body', 'required' => true, 'type' => self::TRON_OPERATION],
            ],
            'retry' => 'write', 'model' => Model\TronResourceOperation::class,
        ] + self::NONE,

        // transactions
        [
            'operationId' => 'createSingleTransfer', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/transaction-requests/single-transfer',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'amount', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'feeInput', 'in' => 'body', 'required' => false, 'type' => self::FEE_INPUT],
                ['name' => 'feeOptimization', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'feePriority', 'in' => 'body', 'required' => false, 'type' => self::FEE_PRIORITY],
                ['name' => 'fromAddress', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'gross', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'maxFee', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'note', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'toAddress', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultAccountId', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'write', 'model' => Model\SingleTransferRequest::class,
        ] + self::NONE,
        [
            'operationId' => 'createMultipleTransfer', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/transaction-requests/multiple-transfer',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'feeInput', 'in' => 'body', 'required' => false, 'type' => self::FEE_INPUT],
                ['name' => 'feePriority', 'in' => 'body', 'required' => true, 'type' => self::FEE_PRIORITY],
                ['name' => 'gross', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'maxFee', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'note', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'prepareStrategy', 'in' => 'body', 'required' => true, 'type' => self::PREPARE_STRATEGY],
                ['name' => 'recipients', 'in' => 'body', 'required' => true, 'type' => self::UTXO_RECIPIENTS],
                ['name' => 'vaultAccountId', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'write', 'model' => Model\MultipleTransferRequest::class,
        ] + self::NONE,
        [
            'operationId' => 'createUtxoTransfer', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/transaction-requests/utxo-transfer',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'changeData', 'in' => 'body', 'required' => false, 'type' => self::UTXO_CHANGE_DATA],
                ['name' => 'feeInput', 'in' => 'body', 'required' => false, 'type' => self::FEE_INPUT],
                ['name' => 'feePayer', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'feePriority', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'gross', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'maxFee', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'note', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'recipients', 'in' => 'body', 'required' => true, 'type' => self::UTXO_RECIPIENTS],
                ['name' => 'senders', 'in' => 'body', 'required' => true, 'type' => self::UTXO_SENDERS],
            ],
            'retry' => 'write', 'model' => Model\UtxoTransferRequest::class,
        ] + self::NONE,
        [
            'operationId' => 'validateUtxoTransfer', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/transaction-requests/utxo-transfer/validate',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'changeData', 'in' => 'body', 'required' => false, 'type' => self::UTXO_CHANGE_DATA],
                ['name' => 'feePayer', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'feePriority', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'gross', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'maxFee', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'note', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'recipients', 'in' => 'body', 'required' => true, 'type' => self::UTXO_RECIPIENTS],
                ['name' => 'senders', 'in' => 'body', 'required' => true, 'type' => self::UTXO_SENDERS],
            ],
            // A dry run: it changes nothing, so it is retried like a read.
            'retry' => 'read', 'model' => Model\UtxoTransferValidation::class,
        ] + self::NONE,
        [
            'operationId' => 'createBatchTransactionRequest', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/transaction-requests/batch',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'feePayer', 'in' => 'body', 'required' => true, 'type' => self::BATCH_FEE_PAYER],
                ['name' => 'feePriority', 'in' => 'body', 'required' => false, 'type' => self::FEE_PRIORITY],
                ['name' => 'fromAddress', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'note', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'recipients', 'in' => 'body', 'required' => true, 'type' => self::BATCH_RECIPIENTS],
                ['name' => 'vaultAccountId', 'in' => 'body', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'write', 'model' => Model\BatchTransactionRequest::class,
        ] + self::NONE,
        [
            'operationId' => 'gasSponsorshipTransfer', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/transaction-requests/gas-sponsorship-transfer',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'amount', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'feeInput', 'in' => 'body', 'required' => false, 'type' => self::FEE_INPUT],
                ['name' => 'feePayer', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'feePriority', 'in' => 'body', 'required' => false, 'type' => self::FEE_PRIORITY],
                ['name' => 'fromAddress', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'maxFee', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'note', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'toAddress', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultAccountId', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'write', 'model' => Model\GasSponsorshipTransferRequest::class,
        ] + self::NONE,
        [
            'operationId' => 'createTronContractInteractionRequest', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/transaction-requests/contract-interaction',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'amount', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'feeInput', 'in' => 'body', 'required' => false, 'type' => self::FEE_INPUT],
                ['name' => 'feeOptimization', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'feePayer', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'fromAddress', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'maxFee', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'method', 'in' => 'body', 'required' => true, 'type' => self::CONTRACT_METHOD],
                ['name' => 'note', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'toAddress', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'vaultAccountId', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'write', 'model' => Model\TronContractInteractionRequest::class,
        ] + self::NONE,
        [
            'operationId' => 'estimateTransactionFeeByAssetId', 'group' => 'transactions', 'method' => 'POST', 'path' => '/vaults/{vaultId}/approximate-fee',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'amount', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'feeOptimization', 'in' => 'body', 'required' => false, 'type' => 'boolean'],
                ['name' => 'feePayer', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'feePayerAssetId', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'feePriority', 'in' => 'body', 'required' => false, 'type' => self::FEE_PRIORITY],
                ['name' => 'fromAddress', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'method', 'in' => 'body', 'required' => false, 'type' => self::CONTRACT_METHOD],
                ['name' => 'prepareStrategy', 'in' => 'body', 'required' => false, 'type' => self::ESTIMATE_PREPARE_STRATEGY],
                ['name' => 'recipients', 'in' => 'body', 'required' => false, 'type' => self::ESTIMATE_RECIPIENTS],
                ['name' => 'toAddress', 'in' => 'body', 'required' => false, 'type' => 'string'],
                ['name' => 'transactionType', 'in' => 'body', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultAccountId', 'in' => 'body', 'required' => true, 'type' => 'string'],
            ],
            // An estimate: it changes nothing, so it is retried like a read.
            'retry' => 'read', 'model' => Model\FeeEstimate::class,
        ] + self::NONE,
        [
            'operationId' => 'getTransactionDetails', 'group' => 'transactions', 'method' => 'GET', 'path' => '/vaults/{vaultId}/{blockchain}/transactions/{transactionId}',
            'params' => [
                ['name' => 'blockchain', 'in' => 'path', 'required' => true, 'type' => self::BLOCKCHAIN],
                ['name' => 'transactionId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'read', 'model' => Model\TransactionDetails::class,
        ] + self::NONE,
        [
            'operationId' => 'getTransactionRequestDetails', 'group' => 'transactions', 'method' => 'GET', 'path' => '/transaction-requests/{transactionRequestId}',
            'params' => [
                ['name' => 'transactionRequestId', 'in' => 'path', 'required' => true, 'type' => 'string'],
            ],
            'retry' => 'read', 'model' => Model\TransactionRequestDetails::class,
        ] + self::NONE,
        [
            'operationId' => 'listUtxos', 'group' => 'transactions', 'method' => 'GET', 'path' => '/vaults/{vaultId}/utxos',
            'params' => [
                ['name' => 'vaultId', 'in' => 'path', 'required' => true, 'type' => 'string'],
                ['name' => 'address', 'in' => 'query', 'required' => false, 'type' => 'string'],
                ['name' => 'assetId', 'in' => 'query', 'required' => false, 'type' => 'string'],
                ['name' => 'isSpent', 'in' => 'query', 'required' => false, 'type' => 'boolean'],
                ['name' => 'limit', 'in' => 'query', 'required' => false, 'type' => self::LIMIT],
                ['name' => 'startingAfter', 'in' => 'query', 'required' => false, 'type' => 'string'],
                ['name' => 'vaultAccountId', 'in' => 'query', 'required' => false, 'type' => 'string'],
            ],
            'retry' => 'read', 'paging' => 'cursor', 'cursorField' => 'utxoId', 'maxLimit' => 50, 'addresses' => null, 'vaultList' => false,
            'model' => Model\Utxo::class,
        ],

        // API keys. Pending in the docs: the request takes no parameters (the list holds at most two keys,
        // which is also the route's default page size), so the SDK sends none.
        [
            'operationId' => 'listApiKeySigningKeys', 'group' => 'apiKeys', 'method' => 'GET', 'path' => '/api-keys/current/signing-keys',
            'params' => [],
            'retry' => 'read', 'paging' => 'offset', 'cursorField' => null, 'maxLimit' => 2, 'addresses' => null, 'vaultList' => false,
            'model' => Model\ApiKeySigningKey::class,
        ],
    ];

    /** @var array<string, array<string, mixed>>|null */
    private static ?array $byId = null;

    /**
     * The table entry of one operation.
     *
     * @return array<string, mixed>
     * @throws \InvalidArgumentException for an operation the table does not hold
     */
    public static function get(string $operationId): array
    {
        if (self::$byId === null) {
            self::$byId = [];
            foreach (self::ALL as $entry) {
                self::$byId[$entry['operationId']] = $entry;
            }
        }

        return self::$byId[$operationId] ?? throw new \InvalidArgumentException(sprintf('no operation %s', $operationId));
    }

    /**
     * What the transport needs to send, retry, page and check one operation.
     *
     * @internal
     */
    public static function transportOperation(string $operationId): Operation
    {
        $entry = self::get($operationId);
        $in = static fn (string $place): array => array_values(array_map(
            static fn (array $param): string => $param['name'],
            array_filter($entry['params'], static fn (array $param): bool => $param['in'] === $place),
        ));

        return new Operation(
            operationId: $entry['operationId'],
            method: $entry['method'],
            path: $entry['path'],
            retry: $entry['retry'],
            pathParams: $in('path'),
            queryParams: $in('query'),
            hasBody: $entry['method'] !== 'GET',
            paging: $entry['paging'],
            cursorField: $entry['cursorField'],
            maxLimit: $entry['maxLimit'] ?? 50,
            addresses: $entry['addresses'],
            vaultList: $entry['vaultList'],
        );
    }
}
