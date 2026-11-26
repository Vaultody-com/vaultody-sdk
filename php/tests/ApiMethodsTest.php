<?php

declare(strict_types=1);

// The client methods. One test per documented operation, against the mock gateway (support/mock-gateway.php,
// which checks the request signatures and signs its answers): the params checked before anything is sent,
// the request line, the method and where each param goes, the {context, data: {item}} body, the documented
// answer read into its model, a documented error as its typed error, the retry rule of the operation's class,
// paging for the lists, and the address checks for the operations that return vault addresses. Then the
// operation table and the models against contract/openapi.json, and Model\Page against the pagination vectors.

require_once __DIR__ . '/support/MockGateway.php';
require_once __DIR__ . '/support/RecordingLogger.php';

use Vaultody\Sdk\Api\ApiKeys;
use Vaultody\Sdk\Api\AssetsAddresses;
use Vaultody\Sdk\Api\Transactions;
use Vaultody\Sdk\Api\VaultAccounts;
use Vaultody\Sdk\Api\Vaults;
use Vaultody\Sdk\Attribute\Operation as OperationAttribute;
use Vaultody\Sdk\Envelope;
use Vaultody\Sdk\Exception\AddressVerificationError;
use Vaultody\Sdk\Exception\ApiError;
use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\NotFoundError;
use Vaultody\Sdk\Exception\PaginationError;
use Vaultody\Sdk\Exception\ParameterError;
use Vaultody\Sdk\Exception\RequestOutcomeUnknownError;
use Vaultody\Sdk\Exception\VaultKeyChangedError;
use Vaultody\Sdk\Model\ApiKeySigningKey;
use Vaultody\Sdk\Model\Model;
use Vaultody\Sdk\Model\Page;
use Vaultody\Sdk\Model\Vault;
use Vaultody\Sdk\Operations;
use Vaultody\Sdk\Retry;
use Vaultody\Sdk\Transport\Meta;
use Vaultody\Sdk\Transport\Operation;
use Vaultody\Sdk\VaultKeys\MemoryVaultKeyStore;
use Vaultody\Sdk\Vaultody;
use Vaultody\Sdk\Verify\Keys;

$gateway = MockGateway::start();
$full = vectors('request-full-v1.json');
$addressVectors = vectors('address-v1.json');
$root = dirname(__DIR__, 2);
$contract = json_decode((string) file_get_contents($root . '/contract/openapi.json'), true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
$overlay = json_decode((string) file_get_contents($root . '/contract/overlay.json'), true, 512, JSON_THROW_ON_ERROR)['operations'];

/** @var array<string, array{method: string, path: string, operation: array<string, mixed>}> $documented */
$documented = [];
foreach ($contract['paths'] as $path => $pathItem) {
    foreach (['get', 'post', 'put'] as $method) {
        if (isset($pathItem[$method])) {
            $documented[$pathItem[$method]['operationId']] = ['method' => strtoupper($method), 'path' => $path, 'operation' => $pathItem[$method]];
        }
    }
}
$successStatus = static fn (array $operation): string => (string) array_values(array_filter(array_keys($operation['responses']), static fn ($code): bool => str_starts_with((string) $code, '2')))[0];
$successExample = static function (string $operationId) use ($documented, $successStatus): array {
    $operation = $documented[$operationId]['operation'];

    return $operation['responses'][$successStatus($operation)]['content']['application/json']['examples']['success']['value'];
};
$requestExample = static fn (string $operationId): ?array => $documented[$operationId]['operation']['requestBody']['content']['application/json']['example'] ?? null;
/** A documented error the call can't retry: [status, body]. */
$errorExample = static function (string $operationId) use ($documented): array {
    $responses = $documented[$operationId]['operation']['responses'];
    foreach (['404', '422', '409', '400', '403'] as $status) {
        foreach ($responses[$status]['content']['application/json']['examples'] ?? [] as $example) {
            if (!in_array($example['value']['error']['code'], Retry::CONFLICT_RETRY_CODES, true)) {
                return [(int) $status, $example['value']];
            }
        }
    }
    throw new RuntimeException('no documented error for ' . $operationId);
};

/** A client against the mock gateway, trusting the TEST-ONLY current root, with no real waiting. */
$client = static function (array $options = []) use ($gateway, $full): Vaultody {
    $gateway->reset();

    return new Vaultody($options + [
        'apiKey' => $full['credentials']['apiKey'],
        'apiSecret' => $full['credentials']['apiSecret'],
        'passphrase' => $full['credentials']['passphrase'],
        'baseUrl' => $gateway->url(),
        'roots' => [root_pem('current')],
        'sleep' => static function (int $ms): void {
        },
        'maxRequestsPerSecond' => 1000,
        'timeoutSeconds' => 5,
        'vaultKeyStore' => new MemoryVaultKeyStore(),
        'logger' => new RecordingLogger(),
    ]);
};
$json = static fn (array $value): string => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

/** Every documented field of $raw is read into the model with the same value, at every depth. */
$assertModel = static function (Model $model, array $raw, string $at) use (&$assertModel): void {
    check($model->raw === $raw, $at . ': raw is the object as it came');
    foreach (Model::fieldsOf($model::class) as $name => $field) {
        $value = $model->{$name};
        if (!array_key_exists($name, $raw)) {
            check($value === null || $value === [], sprintf('%s.%s is absent, so empty', $at, $name));
            continue;
        }
        $listOf = Model::listClassOf($model::class, $name);
        if ($listOf !== null) {
            check(is_array($value) && count($value) === count($raw[$name]), sprintf('%s.%s: every item of the list', $at, $name));
            foreach ($value as $index => $item) {
                check($item instanceof $listOf, sprintf('%s.%s[%d] is a %s', $at, $name, $index, $listOf));
                $assertModel($item, $raw[$name][$index], sprintf('%s.%s[%d]', $at, $name, $index));
            }
        } elseif ($value instanceof Model) {
            $assertModel($value, $raw[$name], $at . '.' . $name);
        } else {
            check($value === $raw[$name], sprintf('%s.%s: the documented %s reads as %s', $at, $name, json_encode($raw[$name]), json_encode($value)));
        }
    }
};

/**
 * Each operation: how to call it, its path and query params, and the request target they must make (before
 * the context option). Body params come from the operation's documented request example.
 *
 * @var array<string, array{call: callable(Vaultody, array, array): mixed, params: array<string, mixed>, target: string}> $cases
 */
$cases = [
    'listVaults' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaults->listVaults($p, $o),
        'params' => ['networkType' => 'test'],
        'target' => '/vaults/test?limit=50',
    ],
    'listVaultsByAssetId' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaults->listVaultsByAssetId($p, $o),
        'params' => ['assetId' => '6523e058a06ebf1322d7dd6f', 'blockchain' => 'ethereum', 'networkType' => 'test'],
        'target' => '/assets/6523e058a06ebf1322d7dd6f/ethereum/vaults/test',
    ],
    'listAssetsByVault' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaults->listAssetsByVault($p, $o),
        'params' => ['vaultId' => '60c9d9921c38030006675ff6'],
        'target' => '/vaults/60c9d9921c38030006675ff6/assets',
    ],
    'listTransactionsByVault' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaults->listTransactionsByVault($p, $o),
        'params' => ['vaultId' => '6565f9a13f8dcd000760d33a'],
        'target' => '/vaults/6565f9a13f8dcd000760d33a/transactions?limit=50',
    ],
    'createVaultAccount' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaultAccounts->createVaultAccount($p, $o),
        'params' => ['vaultId' => '66d866bd469e1d00079d91d5'],
        'target' => '/vaults/66d866bd469e1d00079d91d5/vault-account',
    ],
    'listVaultAccounts' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaultAccounts->listVaultAccounts($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'isHideEmpty' => true, 'isHidden' => false],
        'target' => '/vaults/68dfae9739a4b80007c4f706/vault-accounts/details?isHidden=false&isHideEmpty=true&limit=50',
    ],
    'getVaultAccountById' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaultAccounts->getVaultAccountById($p, $o),
        // Every path value is percent-encoded outside the unreserved set, "/" included.
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'vaultAccountId' => 'A 1/ü'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/vault-accounts/A%201%2F%C3%BC/details',
    ],
    'updateVaultAccount' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaultAccounts->updateVaultAccount($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'vaultAccountId' => '68dfaeae39a4b80007c4f707'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/vault-accounts/68dfaeae39a4b80007c4f707/edit',
    ],
    'addAssetToVaultAccount' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaultAccounts->addAssetToVaultAccount($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'vaultAccountId' => '68dfaeae39a4b80007c4f707'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/vault-accounts/68dfaeae39a4b80007c4f707/add-asset',
    ],
    'listAssetsByVaultAccountId' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaultAccounts->listAssetsByVaultAccountId($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'vaultAccountId' => '68dfaeae39a4b80007c4f707', 'assetUnit' => 'BTC'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/vault-accounts/68dfaeae39a4b80007c4f707/list-assets?assetUnit=BTC&limit=50',
    ],
    'listTransactionsByVaultAccount' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->vaultAccounts->listTransactionsByVaultAccount($p, $o),
        'params' => ['vaultId' => '69932091c938220102488236', 'vaultAccountId' => '699c44632786e90007bf8fb0'],
        'target' => '/vaults/69932091c938220102488236/vault-accounts/699c44632786e90007bf8fb0/transactions?limit=50',
    ],
    'generateDepositAddress' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->generateDepositAddress($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'blockchain' => 'ethereum', 'network' => 'sepolia'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/ethereum/sepolia/addresses',
    ],
    'getAddressBalance' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->getAddressBalance($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'address' => '0x8f010f8dfa6436257957b4a8a2f5f091591f4caf', 'blockchain' => 'ethereum', 'assetUnit' => 'USDC'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/addresses/0x8f010f8dfa6436257957b4a8a2f5f091591f4caf/balance?assetUnit=USDC&blockchain=ethereum&limit=50',
    ],
    'listAddressesByVaultAccountId' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->listAddressesByVaultAccountId($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'vaultAccountId' => '68f0d5ab92a3560007ab5a69', 'blockchain' => 'ethereum', 'assetId' => '6523e058a06ebf1322d7dd6f'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/vault-accounts/68f0d5ab92a3560007ab5a69/list-addresses?assetId=6523e058a06ebf1322d7dd6f&blockchain=ethereum&limit=50',
    ],
    'listSupportedAssets' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->listSupportedAssets($p, $o),
        'params' => ['networkType' => 'main', 'assetUnit' => 'USDC', 'blockchain' => 'ethereum'],
        'target' => '/supported-assets?assetUnit=USDC&blockchain=ethereum&limit=50&networkType=main',
    ],
    'validateAddress' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->validateAddress($p, $o),
        'params' => ['blockchain' => 'bitcoin', 'network' => 'testnet'],
        'target' => '/info/bitcoin/testnet/addresses/validate',
    ],
    'encodeXrpAddress' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->encodeXrpAddress($p, $o),
        'params' => ['network' => 'testnet', 'classicAddress' => 'rB1QL2KsiwrwaErZ8Pa8dVh3ZEQ2oKGp9J', 'addressTag' => '123'],
        'target' => '/utils/xrp/testnet/addresses/encode/rB1QL2KsiwrwaErZ8Pa8dVh3ZEQ2oKGp9J/123',
    ],
    'decodeXrpAddress' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->decodeXrpAddress($p, $o),
        'params' => ['network' => 'testnet', 'xAddress' => 'T7zVRFzUcVxFfE3MUM6jV3SpobVdECBZ1K9UnX62Jacc6AV'],
        'target' => '/utils/xrp/testnet/addresses/decode/T7zVRFzUcVxFfE3MUM6jV3SpobVdECBZ1K9UnX62Jacc6AV',
    ],
    'tronResourceOverview' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->tronResourceOverview($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'blockchain' => 'tron', 'network' => 'nile', 'address' => 'TMLmaAS4GfshG6PfToD5YYRm5G8giauYc4'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/tron/nile/TMLmaAS4GfshG6PfToD5YYRm5G8giauYc4/overview',
    ],
    'tronResourceManagement' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->assetsAddresses->tronResourceManagement($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706', 'blockchain' => 'tron', 'network' => 'nile', 'fromAddress' => 'TMLmaAS4GfshG6PfToD5YYRm5G8giauYc4'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/tron/nile/addresses/TMLmaAS4GfshG6PfToD5YYRm5G8giauYc4/manage-resource',
    ],
    'createSingleTransfer' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->createSingleTransfer($p, $o),
        'params' => ['vaultId' => '60c9d9921c38030006675ff6'],
        'target' => '/vaults/60c9d9921c38030006675ff6/transaction-requests/single-transfer',
    ],
    'createMultipleTransfer' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->createMultipleTransfer($p, $o),
        'params' => ['vaultId' => '60c9d9921c38030006675ff6'],
        'target' => '/vaults/60c9d9921c38030006675ff6/transaction-requests/multiple-transfer',
    ],
    'createUtxoTransfer' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->createUtxoTransfer($p, $o),
        'params' => ['vaultId' => '60c9d9921c38030006675ff6'],
        'target' => '/vaults/60c9d9921c38030006675ff6/transaction-requests/utxo-transfer',
    ],
    'validateUtxoTransfer' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->validateUtxoTransfer($p, $o),
        'params' => ['vaultId' => '60c9d9921c38030006675ff6'],
        'target' => '/vaults/60c9d9921c38030006675ff6/transaction-requests/utxo-transfer/validate',
    ],
    'createBatchTransactionRequest' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->createBatchTransactionRequest($p, $o),
        'params' => ['vaultId' => '68dfae9739a4b80007c4f706'],
        'target' => '/vaults/68dfae9739a4b80007c4f706/transaction-requests/batch',
    ],
    'gasSponsorshipTransfer' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->gasSponsorshipTransfer($p, $o),
        'params' => ['vaultId' => '60c9d9921c38030006675ff6'],
        'target' => '/vaults/60c9d9921c38030006675ff6/transaction-requests/gas-sponsorship-transfer',
    ],
    'createTronContractInteractionRequest' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->createTronContractInteractionRequest($p, $o),
        'params' => ['vaultId' => '60c9d9921c38030006675ff6'],
        'target' => '/vaults/60c9d9921c38030006675ff6/transaction-requests/contract-interaction',
    ],
    'estimateTransactionFeeByAssetId' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->estimateTransactionFeeByAssetId($p, $o),
        'params' => ['vaultId' => '69c28b729d1ca8000714911a'],
        'target' => '/vaults/69c28b729d1ca8000714911a/approximate-fee',
    ],
    'getTransactionDetails' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->getTransactionDetails($p, $o),
        'params' => ['vaultId' => '6565f9a13f8dcd000760d33a', 'blockchain' => 'ethereum', 'transactionId' => '0xcf6fd49df315f8fc542dabe090e1426e85bdd7eeea3b2970e4101dc278b406ae'],
        'target' => '/vaults/6565f9a13f8dcd000760d33a/ethereum/transactions/0xcf6fd49df315f8fc542dabe090e1426e85bdd7eeea3b2970e4101dc278b406ae',
    ],
    'getTransactionRequestDetails' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->getTransactionRequestDetails($p, $o),
        'params' => ['transactionRequestId' => '6115126693397c0006f78eb4'],
        'target' => '/transaction-requests/6115126693397c0006f78eb4',
    ],
    'listUtxos' => [
        'call' => static fn (Vaultody $v, array $p, array $o) => $v->transactions->listUtxos($p, $o),
        'params' => ['vaultId' => '6936c7e88097040007891abe', 'vaultAccountId' => '6936c7e88097040007891abe', 'isSpent' => false, 'address' => 'tb1qulfd8mt9j57sxv6k4gqz3766n5qa97049kuc35', 'assetId' => '6913471c6b2794841dc8fb6f'],
        'target' => '/vaults/6936c7e88097040007891abe/utxos?address=tb1qulfd8mt9j57sxv6k4gqz3766n5qa97049kuc35&assetId=6913471c6b2794841dc8fb6f&isSpent=false&limit=50&vaultAccountId=6936c7e88097040007891abe',
    ],
];

$tests = [];

$tests['every documented operation has a test here'] = static function () use ($cases, $documented): void {
    $ids = array_keys($cases);
    sort($ids);
    $published = array_keys($documented);
    sort($published);
    check($ids === $published && count($ids) === 31, 'the published operations');
    // listApiKeySigningKeys, pending in the docs, has its own test below.
    check(count(Operations::ALL) === count($cases) + 1, 'and the pending one');
};

foreach ($cases as $operationId => $case) {
    $entry = Operations::get($operationId);
    $title = sprintf('%s.%s: %s %s, params checked first, the documented answer and error, the %s retry rule%s%s', $entry['group'], $operationId, $entry['method'], $entry['path'], $entry['retry'], $entry['paging'] === 'cursor' ? ', paging' : '', $entry['addresses'] !== null ? ', address status' : '');
    $tests[$title] = static function () use ($operationId, $case, $entry, $client, $gateway, $successExample, $requestExample, $errorExample, $json, $assertModel): void {
        $vaultody = $client();
        $call = $case['call'];
        $hasBody = $entry['method'] !== 'GET';
        $example = $requestExample($operationId);
        check($hasBody === ($example !== null), 'a body example exactly for the operations with a body');
        $params = $case['params'] + ($hasBody ? $example['data']['item'] : []);
        $context = $hasBody ? $example['context'] : 'order-1842';
        $listPath = $operationId === 'listVaults' ? '/vaults/test' : null;
        $serve = static function (array $answers) use ($gateway, $listPath): void {
            $listPath === null ? $gateway->script($answers) : $gateway->set(['routes' => [$listPath => $answers]]);
        };

        // 1. Checked against the contract before anything is signed or sent.
        check(thrown(static fn () => $call($vaultody, $params + ['notDocumented' => 'x'], []), ParameterError::class)->code === 'unknown_param', 'an undocumented param');
        foreach ($entry['params'] as $param) {
            if ($param['required']) {
                $without = $params;
                unset($without[$param['name']]);
                check(thrown(static fn () => $call($vaultody, $without, []), ParameterError::class)->code === 'missing_param', 'missing ' . $param['name']);
            }
        }
        check(thrown(static fn () => $call($vaultody, $params, ['timeoutSeconds' => 1]), ParameterError::class)->code === 'unknown_option', 'an unknown option');
        foreach ($entry['params'] as $param) {
            if (is_array($param['type']) && isset($param['type']['enum'])) {
                // Exactly one of the operation's documented values; the error names the field, never the value.
                foreach (['NOT-DOCUMENTED-7', strtoupper($param['type']['enum'][0])] as $bad) {
                    $error = thrown(static fn () => $call($vaultody, [$param['name'] => $bad] + $params, []), ParameterError::class);
                    check($error->code === 'invalid_param' && str_contains($error->getMessage(), $param['name']) && !str_contains($error->getMessage(), $bad), sprintf('%s %s refused without the value: %s', $param['name'], $bad, $error->getMessage()));
                }
            }
        }
        check($gateway->requests() === [], 'nothing was sent');

        // 2. The request, and the documented answer read into the model.
        $answer = $successExample($operationId);
        $serve([['status' => 200, 'body' => $json($answer)]]);
        $result = $call($vaultody, $params, ['context' => $context]);
        $requests = $gateway->requests();
        if ($entry['retry'] === 'write') {
            // The client has response-signing roots: its first write is preceded by one signed read, which latches
            // the origin, so the later writes go straight out.
            check(($requests[0]['path'] ?? null) === Keys::SIGNING_KEYS_PATH, 'a signed read before the first write');
            array_shift($requests);
        }
        check(count($requests) === 1, 'one request, ' . count($requests) . ' sent');
        $request = $requests[0];
        check($request['method'] === $entry['method'], 'method ' . $request['method']);
        check($request['hmacValid'] === true && $request['apiVersion'] === '2026-03-20', 'signed, with the pinned API version');
        if ($hasBody) {
            check($request['uri'] === $case['target'], 'target ' . $request['uri']);
            check($request['contentType'] === 'application/json', 'content type');
            check(json_decode($request['body'], true) === $example, 'the body is the documented request: ' . $request['body']);
        } else {
            $expected = $case['target'] . (str_contains($case['target'], '?') ? '&' : '?') . 'context=' . $context;
            check($request['uri'] === $expected, 'target ' . $request['uri'] . ', expected ' . $expected);
            check($request['body'] === '', 'no body');
        }
        $data = $answer['data'];
        if ($entry['paging'] === 'none') {
            check($result instanceof $entry['model'], 'an ' . $entry['model']);
            $assertModel($result, $data['item'], $operationId);
            $meta = $result->meta;
        } else {
            check($result instanceof Page && count($result->items) === count($data['items']), 'a page of the documented items');
            foreach ($result->items as $index => $item) {
                check($item instanceof $entry['model'], 'an ' . $entry['model']);
                $assertModel($item, $data['items'][$index], $operationId . '[' . $index . ']');
            }
            check($result->hasMore === $data['hasMore'] && $result->limit === $data['limit'], 'hasMore and limit');
            $meta = $result->meta;
        }
        check($meta instanceof Meta && $meta->signature === 'verified', 'the answer\'s signature was verified');
        check($meta->requestId === $answer['requestId'] && $meta->apiVersion === $answer['apiVersion'] && $meta->context === ($answer['context'] ?? null), 'meta');
        if ($entry['addresses'] !== null) {
            // The documented addresses carry no derivation path yet, so they can't be checked: said, never "verified".
            check(array_column($meta->addressChecks, 'status') === array_fill(0, $entry['paging'] === 'none' ? 1 : count($data['items']), 'not_verifiable'), 'address checks ' . json_encode($meta->addressChecks));
        }

        // 3. A documented error, as its typed error, not retried.
        $gateway->reset();
        [$status, $body] = $errorExample($operationId);
        $serve([['status' => $status, 'body' => $json($body)]]);
        $error = thrown(static fn () => $call($vaultody, $params, []), ApiError::class);
        $class = Envelope::errorClassFor($status, $body['error']['code']);
        check($error instanceof $class && $error->code === $body['error']['code'] && $error->status === $status, sprintf('a %s %s, got %s %s', $class, $body['error']['code'], $error::class, (string) $error->code));
        check(count($gateway->requests()) === 1, 'not retried');

        // 4. The retry rule of its class: a read is retried, re-signed; a write that may have run is never sent again.
        $gateway->reset();
        if ($entry['retry'] === 'read') {
            $serve([['status' => 503, 'body' => 'Service Unavailable'], ['status' => 200, 'body' => $json($answer)]]);
            $call($vaultody, $params, []);
            $nonces = array_column($gateway->requests(), 'nonce');
            check(count($nonces) === 2 && $nonces[0] !== $nonces[1], 'retried once, re-signed');
        } else {
            $serve([['status' => 500, 'body' => '{"error":{"code":"unexpected_server_error"}}']]);
            thrown(static fn () => $call($vaultody, $params, []), RequestOutcomeUnknownError::class);
            check(count($gateway->requests()) === 1, 'a write is not sent again');
        }

        // 5. Paging: every item of every page, each page an ordinary call that continues from the last cursor.
        if ($entry['paging'] === 'cursor' && $entry['cursorField'] !== null) {
            $gateway->reset();
            $item = $data['items'][0];
            $page = static fn (string $cursor, bool $hasMore): array => ['status' => 200, 'body' => ['limit' => 1, 'hasMore' => $hasMore, 'items' => [array_replace($item, [$entry['cursorField'] => $cursor])]]];
            if ($listPath === null) {
                $serve([$page('cursor-1', true), $page('cursor-2', false)]);
            } else {
                $gateway->set(['vaults' => ['main' => [], 'test' => [array_replace($item, ['id' => 'cursor-1']), array_replace($item, ['id' => 'cursor-2'])]]]);
            }
            $seen = [];
            foreach ($call($vaultody, ['limit' => 1] + $params, []) as $model) {
                $seen[] = $model->raw[$entry['cursorField']];
            }
            check($seen === ['cursor-1', 'cursor-2'], 'every item ' . json_encode($seen));
            [$first, $second] = $gateway->requests() + [null, null];
            check($second !== null && count($gateway->requests()) === 2, 'two pages');
            parse_str((string) parse_url('http://x' . $first['uri'], PHP_URL_QUERY), $firstQuery);
            parse_str((string) parse_url('http://x' . $second['uri'], PHP_URL_QUERY), $secondQuery);
            check($firstQuery['limit'] === '1' && !isset($firstQuery['startingAfter']), 'the first page');
            check($secondQuery == $firstQuery + ['startingAfter' => 'cursor-1'], 'the next page continues after the last item, the filters kept: ' . $second['uri']);
        }
    };
}

$tests['apiKeys.listApiKeySigningKeys: GET /api-keys/current/signing-keys with no params, one whole page, error and retry'] = static function () use ($client, $gateway, $full): void {
    $vaultody = $client();
    $path = '/api-keys/current/signing-keys';
    check(thrown(static fn () => $vaultody->apiKeys->listApiKeySigningKeys(['limit' => 2]), ParameterError::class)->code === 'unknown_param', 'the docs declare no params');
    check(thrown(static fn () => $vaultody->apiKeys->listApiKeySigningKeys(['offset' => 0]), ParameterError::class)->code === 'unknown_param', 'no offset either');
    check($gateway->requests() === [], 'nothing sent');

    $keys = [
        ['fingerprint' => $full['keys']['ed25519']['fingerprint'], 'algorithm' => 'ed25519', 'status' => 'active', 'createdTimestamp' => 1795000000, 'approvedTimestamp' => 1795000300],
        ['fingerprint' => $full['keys']['p256']['fingerprint'], 'algorithm' => 'p-256', 'status' => 'active', 'createdTimestamp' => 1795000100, 'approvedTimestamp' => 1795000400],
    ];
    $gateway->set(['signingKeys' => $keys]);
    $page = $vaultody->apiKeys->listApiKeySigningKeys();
    check($gateway->requests()[0]['uri'] === $path && $gateway->requests()[0]['method'] === 'GET', 'no query at all');
    check($page->meta->signature === 'verified' && !$page->hasMore && $page->total === 2, 'whole and verified');
    $read = iterator_to_array($page, false);
    check(count($read) === 2 && $read[0] instanceof ApiKeySigningKey && $read[1]->fingerprint === $keys[1]['fingerprint'] && $read[0]->approvedTimestamp === 1795000300 && $read[1]->algorithm === 'p-256', 'the keys');
    check($page->nextPage() === null, 'no next page');
    $vaultody->apiKeys->listApiKeySigningKeys([], ['context' => 'check']);
    check($gateway->requests()[1]['uri'] === $path . '?context=check', 'context in the query');

    // More keys than one page holds can't be asked for, so the list says so instead of ending quietly.
    $gateway->set(['routes' => [$path => [['status' => 200, 'body' => ['limit' => 2, 'offset' => 0, 'total' => 3, 'items' => $keys]]]]]);
    $page = $vaultody->apiKeys->listApiKeySigningKeys();
    check($page->hasMore, 'has more');
    $read = [];
    check(thrown(static function () use ($page, &$read): void {
        foreach ($page as $key) {
            $read[] = $key;
        }
    }, PaginationError::class)->code === 'cannot_continue', 'refuses to stop quietly');
    check(count($read) === 2, 'after the items it has');
    check(thrown(static fn () => $page->nextPage(), PaginationError::class)->code === 'cannot_continue', 'nextPage too');

    $gateway->reset();
    $gateway->set(['routes' => [$path => [['status' => 404, 'body' => '{"requestId":"r","error":{"code":"resource_not_found","message":"TEST"}}']]]]);
    check(thrown(static fn () => $vaultody->apiKeys->listApiKeySigningKeys(), NotFoundError::class)->code === 'resource_not_found', 'a typed error');
    $gateway->reset();
    $gateway->set(['signingKeys' => $keys, 'routes' => [$path => [['status' => 503, 'body' => 'Service Unavailable']]]]);
    check(count($vaultody->apiKeys->listApiKeySigningKeys()->items) === 2, 'a read retried');
    check(count($gateway->requests()) === 2, 'once');
};

$tests['assetsAddresses.getAddressBalance: the docs name no cursor field, so the SDK never pages it on its own; startingAfter by hand works'] = static function () use ($client, $gateway, $successExample, $json): void {
    $vaultody = $client();
    $answer = $successExample('getAddressBalance');
    $answer['data']['hasMore'] = true;
    $gateway->script([['status' => 200, 'body' => $json($answer)], ['status' => 200, 'body' => $json($answer)]]);
    $params = ['vaultId' => 'V1', 'address' => '0x8f010f8dfa6436257957b4a8a2f5f091591f4caf'];
    $page = $vaultody->assetsAddresses->getAddressBalance($params);
    $read = 0;
    check(thrown(static function () use ($page, &$read): void {
        foreach ($page as $balance) {
            $read++;
        }
    }, PaginationError::class)->code === 'cannot_continue', 'iterating past the page');
    check($read === count($answer['data']['items']), 'after the page\'s items');
    check(thrown(static fn () => $page->nextPage(), PaginationError::class)->code === 'cannot_continue', 'nextPage');
    $vaultody->assetsAddresses->getAddressBalance($params + ['startingAfter' => 'last-id', 'limit' => 10]);
    check($gateway->requests()[1]['uri'] === '/vaults/V1/addresses/0x8f010f8dfa6436257957b4a8a2f5f091591f4caf/balance?limit=10&startingAfter=last-id', 'by hand: ' . $gateway->requests()[1]['uri']);
    check(count($gateway->requests()) === 2, 'nothing else was sent');
};

// The operations that return vault addresses: each address is checked against the vault's pinned xpub.

$caseOf = static function (string $name) use ($addressVectors): array {
    foreach ($addressVectors['cases'] as $case) {
        if ($case['name'] === $name) {
            return $case;
        }
    }
    throw new RuntimeException('no address case ' . $name);
};
$xpubOf = static function (string $name) use ($addressVectors): string {
    foreach ($addressVectors['xpubs'] as $xpub) {
        if ($xpub['name'] === $name) {
            return $xpub['xpub'];
        }
    }
    throw new RuntimeException('no xpub ' . $name);
};
$vault = static fn (string $id, string $type, ?string $ecdsa, ?string $eddsa = null): array => [
    'id' => $id, 'type' => $type, 'name' => 'TEST vault ' . $id,
    'mpcKeys' => array_values(array_filter([
        $ecdsa === null ? null : ['algorithm' => 'ECDSA', 'xpub' => $ecdsa],
        $eddsa === null ? null : ['algorithm' => 'EDDSA', 'xpub' => $eddsa],
    ])),
];
$addressItem = static fn (array $case, array $extra = []): array => $extra + [
    'address' => $case['address'], 'accountIndex' => $case['accountIndex'], 'isChange' => $case['change'],
    'addressIndex' => $case['addressIndex'], 'addressFormat' => $case['addressFormatWire'], 'label' => 'TEST',
];
$btc = $caseOf('bitcoin/mainnet/P2WPKH/ecdsa-bip32-tv1-master/m/0/0/0');

$tests['address checks: without a pin store, the four operations that return addresses or vault keys fail before anything is sent'] = static function () use ($client, $gateway): void {
    $vaultody = $client(['vaultKeyStore' => null]);
    $calls = [
        'listVaults' => static fn () => $vaultody->vaults->listVaults(['networkType' => 'main']),
        'generateDepositAddress' => static fn () => $vaultody->assetsAddresses->generateDepositAddress(['vaultId' => 'V1', 'blockchain' => 'bitcoin', 'network' => 'mainnet', 'label' => 'L', 'vaultAccountId' => 'A1']),
        'listAddressesByVaultAccountId' => static fn () => $vaultody->assetsAddresses->listAddressesByVaultAccountId(['vaultId' => 'V1', 'vaultAccountId' => 'A1']),
        'addAssetToVaultAccount' => static fn () => $vaultody->vaultAccounts->addAssetToVaultAccount(['vaultId' => 'V1', 'vaultAccountId' => 'A1', 'assetId' => 'AS1']),
    ];
    foreach ($calls as $operationId => $call) {
        check(str_contains(thrown($call, ConfigurationError::class)->getMessage(), 'vaultKeysFile'), $operationId . ' says what to set');
    }
    check($gateway->requests() === [], 'nothing sent');
    // Every other operation works without one.
    $gateway->script([['status' => 200, 'body' => ['item' => ['address' => 'x', 'isValid' => true]]]]);
    check($vaultody->assetsAddresses->validateAddress(['blockchain' => 'bitcoin', 'network' => 'mainnet', 'address' => 'x'])->isValid === true, 'validateAddress');
};

$tests['address checks: vaults.listVaults pins the vault xpubs on first sight, and a changed xpub refuses the answer'] = static function () use ($client, $gateway, $vault, $btc, $xpubOf): void {
    $store = new MemoryVaultKeyStore();
    $vaultody = $client(['vaultKeyStore' => $store]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub']), $vault('smart', 'main', null)], 'test' => []]]);
    $page = $vaultody->vaults->listVaults(['networkType' => 'main']);
    check($page->meta->vaultKeys === [
        ['vaultId' => 'v-main', 'status' => 'verified', 'outcome' => 'pinned'],
        ['vaultId' => 'smart', 'status' => 'not_verifiable', 'outcome' => 'not_verifiable'],
    ], 'per-vault results on the page ' . json_encode($page->meta->vaultKeys));
    $ids = array_map(static fn (Vault $v): ?string => $v->id, iterator_to_array($page, false));
    check($ids === ['v-main', 'smart'], 'the vaults ' . json_encode($ids));
    $pins = $store->read('http://127.0.0.1:' . $gateway->port)['vaults'];
    check(array_keys($pins) === ['v-main'] && $pins['v-main']['status'] === 'verified', 'pinned from the signed list; the keyless vault not');

    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $xpubOf('ecdsa-bip32-tv1-m0h'))], 'test' => []]]);
    $error = thrown(static fn () => $vaultody->vaults->listVaults(['networkType' => 'main']), VaultKeyChangedError::class);
    check($error->alarms[0]['vaultId'] === 'v-main' && $error->alarms[0]['reason'] === 'xpub_changed', 'the alarm');
    check($store->read('http://127.0.0.1:' . $gateway->port)['vaults']['v-main']['keys']['ECDSA'] === $btc['xpub'], 'the pin is kept');
};

$tests['address checks: assetsAddresses.generateDepositAddress returns a verified address, and refuses one that does not derive from the pin'] = static function () use ($client, $gateway, $vault, $btc, $addressItem): void {
    $vaultody = $client();
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
    $params = ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet', 'label' => 'TEST', 'vaultAccountId' => 'A1'];
    $gateway->script([['status' => 200, 'body' => ['item' => $addressItem($btc)]]]);
    $address = $vaultody->assetsAddresses->generateDepositAddress($params);
    check($address->address === $btc['address'] && array_column($address->meta->addressChecks, 'status') === ['verified'], 'verified ' . json_encode($address->meta->addressChecks));

    $gateway->script([['status' => 200, 'body' => ['item' => $addressItem($btc, ['address' => 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'])]]]);
    check(thrown(static fn () => $vaultody->assetsAddresses->generateDepositAddress($params), AddressVerificationError::class)->code === 'mismatch', 'a swapped address');
};

$tests['address checks: assetsAddresses.listAddressesByVaultAccountId checks every address of every page; one wrong address refuses the page'] = static function () use ($client, $gateway, $vault, $btc, $addressItem, $caseOf): void {
    $vaultody = $client();
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
    $second = $caseOf('bitcoin/mainnet/P2WPKH/ecdsa-bip32-tv1-master/m/1/1/1');
    $gateway->script([
        ['status' => 200, 'body' => ['limit' => 1, 'hasMore' => true, 'items' => [$addressItem($btc, ['addressId' => 'a1', 'blockchain' => 'bitcoin'])]]],
        ['status' => 200, 'body' => ['limit' => 1, 'hasMore' => false, 'items' => [$addressItem($second, ['addressId' => 'a2', 'blockchain' => 'bitcoin'])]]],
    ]);
    $page = $vaultody->assetsAddresses->listAddressesByVaultAccountId(['vaultId' => 'v-main', 'vaultAccountId' => 'A1', 'limit' => 1]);
    check(array_column($page->meta->addressChecks, 'status') === ['verified'], 'first page');
    $next = $page->nextPage();
    check($next !== null && array_column($next->meta->addressChecks, 'status') === ['verified'] && $next->items[0]->address === $second['address'], 'second page');
    check($next->nextPage() === null, 'the end');

    $gateway->script([['status' => 200, 'body' => ['limit' => 50, 'hasMore' => false, 'items' => [
        $addressItem($btc, ['addressId' => 'a1', 'blockchain' => 'bitcoin']),
        $addressItem($second, ['addressId' => 'a2', 'blockchain' => 'bitcoin', 'address' => $btc['address']]),
    ]]]]);
    check(thrown(static fn () => $vaultody->assetsAddresses->listAddressesByVaultAccountId(['vaultId' => 'v-main', 'vaultAccountId' => 'A1']), AddressVerificationError::class)->code === 'mismatch', 'the page is refused');
};

$tests['address checks: vaultAccounts.addAssetToVaultAccount must answer the address sent, derived from the pin'] = static function () use ($client, $gateway, $vault, $btc, $addressItem): void {
    $vaultody = $client();
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
    $answer = ['status' => 200, 'body' => ['item' => $addressItem($btc, ['blockchain' => 'bitcoin', 'network' => 'mainnet', 'assetUnit' => 'BTC'])]];
    $gateway->script([$answer]);
    $added = $vaultody->vaultAccounts->addAssetToVaultAccount(['vaultId' => 'v-main', 'vaultAccountId' => 'A1', 'assetId' => 'AS1', 'address' => $btc['address']]);
    check($added->address === $btc['address'] && $added->assetUnit === 'BTC' && array_column($added->meta->addressChecks, 'status') === ['verified'], 'verified');
    $gateway->script([$answer]);
    check(thrown(static fn () => $vaultody->vaultAccounts->addAssetToVaultAccount(['vaultId' => 'v-main', 'vaultAccountId' => 'A1', 'assetId' => 'AS1', 'address' => 'another']), AddressVerificationError::class)->code === 'mismatch', 'another address than the one sent');
};

// Params and options, beyond what every operation's test checks.

$tests['params: types, nested fields, limits and nulls are checked against the contract before sending'] = static function () use ($client, $gateway, $requestExample): void {
    $vaultody = $client();
    $single = ['vaultId' => 'V1'] + $requestExample('createSingleTransfer')['data']['item'];
    $multiple = ['vaultId' => 'V1'] + $requestExample('createMultipleTransfer')['data']['item'];
    $refused = [
        'invalid_param' => [
            'a float amount' => static fn () => $vaultody->transactions->createSingleTransfer(['amount' => 0.1] + $single),
            'an integer path value' => static fn () => $vaultody->assetsAddresses->encodeXrpAddress(['network' => 'testnet', 'classicAddress' => 'r1', 'addressTag' => 123]),
            'a string boolean' => static fn () => $vaultody->vaultAccounts->createVaultAccount(['vaultId' => 'V1', 'name' => 'n', 'color' => '#fff', 'isHiddenInDashboard' => 'false']),
            'an object for a list' => static fn () => $vaultody->transactions->createMultipleTransfer(['recipients' => ['address' => 'a', 'amount' => '1']] + $multiple),
            'a list for an object' => static fn () => $vaultody->transactions->createSingleTransfer(['feeInput' => ['1']] + $single),
            'a nested wrong type' => static fn () => $vaultody->transactions->createSingleTransfer(['feeInput' => ['acknowledgeHighFee' => 'yes']] + $single),
            'limit 0' => static fn () => $vaultody->vaults->listTransactionsByVault(['vaultId' => 'V1', 'limit' => 0]),
            'limit above the maximum' => static fn () => $vaultody->vaults->listTransactionsByVault(['vaultId' => 'V1', 'limit' => 51]),
            'a string limit' => static fn () => $vaultody->vaults->listTransactionsByVault(['vaultId' => 'V1', 'limit' => '10']),
            'a null list item' => static fn () => $vaultody->transactions->createMultipleTransfer(['recipients' => [null]] + $multiple),
            'a value in another case than documented' => static fn () => $vaultody->vaults->listVaults(['networkType' => 'MAIN']),
            'a query value outside the documented list' => static fn () => $vaultody->assetsAddresses->listSupportedAssets(['blockchain' => 'bitcoin-sv']),
            'a body value outside the documented list' => static fn () => $vaultody->transactions->createSingleTransfer(['feePriority' => 'urgent'] + $single),
            'estimate\'s prepareStrategy spelling in createMultipleTransfer' => static fn () => $vaultody->transactions->createMultipleTransfer(['prepareStrategy' => 'minimize_dust'] + $multiple),
            'createMultipleTransfer\'s spelling in estimateTransactionFeeByAssetId' => static fn () => $vaultody->transactions->estimateTransactionFeeByAssetId(['vaultId' => 'V1', 'vaultAccountId' => 'A1', 'transactionType' => 'coin', 'prepareStrategy' => 'minimize-dust']),
        ],
        'unknown_param' => [
            'a nested undocumented field' => static fn () => $vaultody->transactions->createSingleTransfer(['feeInput' => ['totl' => '1']] + $single),
            'context as a param' => static fn () => $vaultody->transactions->createSingleTransfer(['context' => 'x'] + $single),
            'a list param' => static fn () => $vaultody->vaults->listAssetsByVault([0 => 'V1']),
        ],
        'missing_param' => [
            'a nested required field' => static fn () => $vaultody->transactions->createMultipleTransfer(['recipients' => [['address' => 'a']]] + $multiple),
            'a required field given as null' => static fn () => $vaultody->transactions->createSingleTransfer(['amount' => null] + $single),
        ],
        'invalid_option' => [
            'a context that is not a string' => static fn () => $vaultody->vaults->listAssetsByVault(['vaultId' => 'V1'], ['context' => 7]),
        ],
    ];
    foreach ($refused as $code => $calls) {
        foreach ($calls as $what => $call) {
            $error = thrown($call, ParameterError::class);
            check($error->code === $code, sprintf('%s: %s, not %s (%s)', $what, $code, $error->code, $error->getMessage()));
        }
    }
    check(str_contains(thrown(static fn () => $vaultody->transactions->createSingleTransfer(['context' => 'x'] + $single), ParameterError::class)->getMessage(), 'call option'), 'the hint');
    check($gateway->requests() === [], 'nothing sent');

    // Each operation takes its own documented spelling.
    $gateway->script([['status' => 200, 'body' => ['item' => ['feeInNative' => '0.0001']]], ['status' => 201, 'body' => ['item' => ['transactionRequestId' => 't0']]]]);
    $vaultody->transactions->estimateTransactionFeeByAssetId(['vaultId' => 'V1', 'vaultAccountId' => 'A1', 'transactionType' => 'coin', 'prepareStrategy' => 'minimize_dust']);
    $vaultody->transactions->createMultipleTransfer(['prepareStrategy' => 'minimize-dust'] + $multiple);
    check(json_decode($gateway->requests()[0]['body'], true)['data']['item']['prepareStrategy'] === 'minimize_dust', 'estimate: underscores');
    check(json_decode($gateway->requests()[1]['body'], true)['data']['item']['prepareStrategy'] === 'minimize-dust', 'multiple transfer: hyphens');
    $gateway->reset();

    // An optional null is left out; an empty object goes as {}.
    $gateway->script([['status' => 201, 'body' => ['item' => ['transactionRequestId' => 't1']]]]);
    $vaultody->transactions->createSingleTransfer(['maxFee' => null, 'feeInput' => []] + $single);
    $body = json_decode($gateway->requests()[0]['body'], false);
    check(!property_exists($body->data->item, 'maxFee'), 'a null optional left out');
    check($body->data->item->feeInput instanceof stdClass && get_object_vars($body->data->item->feeInput) === [], 'an empty object as {}');
    check(!property_exists($body, 'context'), 'no context unless given');
};

$tests['answers: a model keeps undocumented fields, never throws on a type it does not expect, and a list item that is not an object refuses the page'] = static function () use ($client, $gateway): void {
    $vaultody = $client();
    $gateway->script([['status' => 200, 'body' => ['item' => ['address' => 7, 'isValid' => 'yes', 'newField' => ['a' => 1]]]]]);
    $validation = $vaultody->assetsAddresses->validateAddress(['blockchain' => 'bitcoin', 'network' => 'mainnet', 'address' => 'x']);
    check($validation->address === null && $validation->isValid === null, 'a field of another type is null');
    check($validation->raw === ['address' => 7, 'isValid' => 'yes', 'newField' => ['a' => 1]] && $validation->jsonSerialize() === $validation->raw, 'and kept in raw, with the undocumented one');

    $gateway->script([['status' => 200, 'body' => ['limit' => 50, 'hasMore' => false, 'items' => ['not an object']]]]);
    check(str_contains(thrown(static fn () => $vaultody->transactions->listUtxos(['vaultId' => 'V1']), ApiError::class)->getMessage(), 'not an object'), 'refused');
    $gateway->script([['status' => 200, 'body' => ['item' => ['x' => 1]]]]);
    check(str_contains(thrown(static fn () => $vaultody->transactions->listUtxos(['vaultId' => 'V1']), ApiError::class)->getMessage(), 'one item where a list'), 'an item for a list');
    $gateway->script([['status' => 200, 'body' => ['limit' => 50, 'hasMore' => false, 'items' => []]]]);
    check(str_contains(thrown(static fn () => $vaultody->transactions->getTransactionRequestDetails(['transactionRequestId' => 't1']), ApiError::class)->getMessage(), 'a list where one item'), 'a list for an item');
};

// The operation table and the models against the contract.

/** The contract's schema in the operation table's notation. */
$notation = static function (array $schema) use (&$notation): mixed {
    switch ($schema['type']) {
        case 'object':
            $required = $schema['required'] ?? [];
            sort($required);

            return ['type' => 'object', 'properties' => array_map($notation, $schema['properties'] ?? []), 'required' => $required];
        case 'array':
            return ['type' => 'array', 'items' => $notation($schema['items'])];
        case 'integer':
            return isset($schema['maximum']) ? ['type' => 'integer', 'minimum' => 1, 'maximum' => $schema['maximum']] : 'integer';
        case 'string':
            if (isset($schema['enum'])) {
                $values = $schema['enum'];
                sort($values);

                return ['type' => 'string', 'enum' => $values];
            }

            return 'string';
        default:
            return $schema['type'];
    }
};
$sortRequired = static function (mixed $type) use (&$sortRequired): mixed {
    if (!is_array($type)) {
        return $type;
    }
    if (isset($type['required'])) {
        sort($type['required']);
    }
    if (isset($type['enum'])) {
        sort($type['enum']);
    }
    if (isset($type['properties'])) {
        $type['properties'] = array_map($sortRequired, $type['properties']);
    }
    if (isset($type['items'])) {
        $type['items'] = $sortRequired($type['items']);
    }

    return $type;
};

$tests['operation table: every param with its place, required flag, JSON type and documented values, at every depth, as the contract documents; the overlay fields'] = static function () use ($documented, $overlay, $notation, $sortRequired, $contract): void {
    foreach (Operations::ALL as $entry) {
        $id = $entry['operationId'];
        check(($overlay[$id]['retry'] ?? null) === $entry['retry'], $id . ' retry');
        check(array_key_exists('cursorField', $overlay[$id]) ? $overlay[$id]['cursorField'] === $entry['cursorField'] : $entry['cursorField'] === null, $id . ' cursorField');
        check(in_array($entry['addresses'], [null, Operation::ADDRESSES_IN_PATH, Operation::ADDRESSES_IN_ITEMS, Operation::ADDRESSES_ADD_ASSET], true), $id . ' addresses');
        if ($id === 'listApiKeySigningKeys') {
            // Pending: the docs declare no params; offset-paged with at most two keys (overlay).
            check($entry['params'] === [] && $entry['paging'] === ($overlay[$id]['paging'] ?? null) && $entry['maxLimit'] === 2, $id);
            continue;
        }
        $operation = $documented[$id]['operation'];
        check($entry['method'] === $documented[$id]['method'] && $entry['path'] === $documented[$id]['path'], $id . ' method and path');
        $expected = [];
        foreach ($operation['parameters'] ?? [] as $param) {
            if (isset($param['$ref'])) {
                $param = $contract['components']['parameters'][substr($param['$ref'], strlen('#/components/parameters/'))];
            }
            if ($param['in'] !== 'header' && $param['name'] !== 'context') {
                $expected[$param['name']] = ['in' => $param['in'], 'required' => ($param['required'] ?? false) === true, 'type' => $notation($param['schema'])];
            }
        }
        $item = $operation['requestBody']['content']['application/json']['schema']['properties']['data']['properties']['item'] ?? null;
        foreach ($item['properties'] ?? [] as $name => $schema) {
            $expected[$name] = ['in' => 'body', 'required' => in_array($name, $item['required'] ?? [], true), 'type' => $notation($schema)];
        }
        $actual = [];
        foreach ($entry['params'] as $param) {
            $actual[$param['name']] = ['in' => $param['in'], 'required' => $param['required'], 'type' => $sortRequired($param['type'])];
        }
        check($actual == $expected, $id . ' params differ: ' . json_encode($actual) . ' vs ' . json_encode($expected));
        $data = $operation['responses'][array_values(array_filter(array_keys($operation['responses']), static fn ($code): bool => str_starts_with((string) $code, '2')))[0]]['content']['application/json']['schema']['properties']['data'];
        $paged = isset($data['properties']['items']);
        check($entry['paging'] === ($paged ? 'cursor' : 'none'), $id . ' paging');
        check($entry['maxLimit'] === ($expected['limit']['type']['maximum'] ?? null), $id . ' maxLimit');
    }
    $withAddresses = array_column(array_filter(Operations::ALL, static fn (array $entry): bool => $entry['addresses'] !== null), 'addresses', 'operationId');
    check($withAddresses === ['addAssetToVaultAccount' => Operation::ADDRESSES_ADD_ASSET, 'generateDepositAddress' => Operation::ADDRESSES_IN_PATH, 'listAddressesByVaultAccountId' => Operation::ADDRESSES_IN_ITEMS], 'the operations whose addresses are checked');
    check(array_column(array_filter(Operations::ALL, static fn (array $entry): bool => $entry['vaultList']), 'operationId') === ['listVaults'], 'the one source of vault xpubs');
};

$tests['models: every documented answer field is a model field of its type, at every depth, and every model field is documented'] = static function () use ($documented, $root): void {
    $seen = [];
    $walk = static function (array $schema, string $class, string $at) use (&$walk, &$seen): void {
        $fields = Model::fieldsOf($class);
        $seen[$class] ??= [];
        foreach ($schema['properties'] ?? [] as $name => $property) {
            $seen[$class][$name] = true;
            check(isset($fields[$name]), sprintf('%s.%s is documented; %s has no such field', $at, $name, $class));
            $types = $fields[$name]['types'];
            $listOf = Model::listClassOf($class, $name);
            switch ($property['type']) {
                case 'object':
                    $nested = array_values(array_filter($types, static fn (string $type): bool => is_subclass_of($type, Model::class)));
                    check(count($nested) === 1, sprintf('%s.%s is an object: a model', $at, $name));
                    $walk($property, $nested[0], $at . '.' . $name);
                    break;
                case 'array':
                    check(in_array('array', $types, true), sprintf('%s.%s is a list', $at, $name));
                    if (($property['items']['type'] ?? null) === 'object') {
                        check($listOf !== null, sprintf('%s.%s: a list of objects names its model in LISTS', $at, $name));
                        $walk($property['items'], $listOf, $at . '.' . $name . '[]');
                    }
                    break;
                default:
                    $php = ['string' => 'string', 'integer' => 'int', 'boolean' => 'bool', 'number' => 'float'][$property['type']];
                    check(in_array($php, $types, true), sprintf('%s.%s is %s; %s::$%s takes %s', $at, $name, $property['type'], $class, $name, implode('|', $types)));
            }
        }
    };
    foreach (Operations::ALL as $entry) {
        $id = $entry['operationId'];
        if ($id === 'listApiKeySigningKeys') {
            // Pending: its fields are listed in the docs file, all scalars.
            $pending = (string) file_get_contents($root . '/contract/pending/api-keys/list-api-key-signing-keys.yaml');
            preg_match_all('/^  "([A-Za-z]+)": \{/m', $pending, $match);
            $names = $match[1];
            sort($names);
            check(array_keys(Model::fieldsOf(ApiKeySigningKey::class)) === $names, 'the signing key fields ' . json_encode($names));
            $seen[ApiKeySigningKey::class] = array_fill_keys($names, true);
            continue;
        }
        $operation = $documented[$id]['operation'];
        $data = $operation['responses'][array_values(array_filter(array_keys($operation['responses']), static fn ($code): bool => str_starts_with((string) $code, '2')))[0]]['content']['application/json']['schema']['properties']['data'];
        $walk(isset($data['properties']['items']) ? $data['properties']['items']['items'] : $data['properties']['item'], $entry['model'], $id);
    }
    foreach ($seen as $class => $names) {
        $extra = array_diff(array_keys(Model::fieldsOf($class)), array_keys($names));
        check($extra === [], sprintf('%s has fields no operation documents: %s', $class, implode(', ', $extra)));
        foreach (Model::fieldsOf($class) as $name => $field) {
            check($field['nullable'] || $field['types'] === ['array'], sprintf('%s::$%s is nullable (a list is never null)', $class, $name));
        }
    }
    $files = array_map(static fn (string $file): string => 'Vaultody\\Sdk\\Model\\' . basename($file, '.php'), glob($root . '/php/src/Model/*.php') ?: []);
    $unused = array_diff($files, array_keys($seen), [Model::class, Page::class]);
    check($unused === [], 'models no operation answers with: ' . implode(', ', $unused));
};

$tests['methods: one per operation, in its docs group, named by its operationId, (array $params, array $options = []), returning the table\'s model or a Page of it'] = static function (): void {
    $groups = ['vaults' => Vaults::class, 'vaultAccounts' => VaultAccounts::class, 'assetsAddresses' => AssetsAddresses::class, 'transactions' => Transactions::class, 'apiKeys' => ApiKeys::class];
    $count = 0;
    foreach ($groups as $group => $class) {
        foreach ((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            $attributes = $method->getAttributes(OperationAttribute::class);
            if ($attributes === []) {
                check(in_array($method->getName(), ['__construct', '__debugInfo'], true), $class . '::' . $method->getName() . ' is public without an operation');
                continue;
            }
            $count++;
            $id = $attributes[0]->newInstance()->operationId;
            $entry = Operations::get($id);
            check($method->getName() === $id && $entry['group'] === $group, $id . ' named and grouped');
            $parameters = $method->getParameters();
            check(count($parameters) === 2 && $parameters[0]->getName() === 'params' && $parameters[1]->getName() === 'options' && $parameters[1]->isOptional(), $id . ' signature');
            $required = array_filter($entry['params'], static fn (array $param): bool => $param['required']);
            check($parameters[0]->isOptional() === ($required === []), $id . ': params optional exactly when none is required');
            $returns = (string) $method->getReturnType();
            check($returns === ($entry['paging'] === 'none' ? $entry['model'] : Page::class), $id . ' returns ' . $returns);
        }
    }
    check($count === count(Operations::ALL), 'every operation');
};

// Model\Page runs the cursor paging of test-vectors/pagination-v1.json through the same pager.
foreach (vectors('pagination-v1.json')['cases'] as $vector) {
    if ($vector['paging'] !== 'cursor') {
        continue;
    }
    $tests['pagination-v1.json through Model\\Page: ' . $vector['name']] = static function () use ($vector): void {
        $meta = new Meta(null, null, null, false, 'verified');
        $asked = [];
        $make = static function (int $index) use (&$make, &$asked, $vector, $meta): Page {
            $response = $vector['pages'][$index]['response'];

            return new Page(
                array_map(static fn (array $raw): Vault => Vault::fromArray($raw), $response['items']),
                $response['items'],
                ($response['hasMore'] ?? null) === true,
                $response['limit'] ?? null,
                $response['startingAfter'] ?? null,
                null,
                $meta,
                $vector['cursorField'],
                $vector['limit'] ?? null,
                $vector['pages'][$index]['request']['startingAfter'],
                static function (string $cursor) use (&$make, &$asked, $index, $vector): Page {
                    $asked[] = $cursor;
                    check(isset($vector['pages'][$index + 1]), 'an extra request after ' . $cursor);
                    check($cursor === $vector['pages'][$index + 1]['request']['startingAfter'], 'cursor ' . $cursor);

                    return $make($index + 1);
                },
            );
        };
        $generator = $make(0)->autoPaging($vector['maxItems'] ?? null);
        $items = [];
        $error = null;
        try {
            foreach ($generator as $item) {
                $items[] = $item->raw[$vector['cursorField']] ?? null;
            }
        } catch (PaginationError $e) {
            $error = $e->code;
        }
        check($items === $vector['expected']['items'], 'items ' . json_encode($items));
        check(count($asked) === count($vector['pages']) - 1, 'every page and no more');
        if (isset($vector['expected']['error'])) {
            check($error === $vector['expected']['error'], 'error ' . var_export($error, true));
        } else {
            check($error === null && $generator->getReturn() === $vector['expected']['stop'], 'stop ' . ($error ?? $generator->getReturn()));
        }
    };
}

$tests['the mock gateway is stopped'] = static function () use ($gateway): void {
    $gateway->stop();
    check(true, '');
};

return $tests;
