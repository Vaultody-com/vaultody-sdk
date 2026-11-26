<?php

declare(strict_types=1);

use Vaultody\Sdk\Attribute\Operation;
use Vaultody\Sdk\Operations;
use Vaultody\Sdk\Surface;
use Vaultody\Sdk\Vaultody;
use Vaultody\Sdk\Version;

$root = dirname(__DIR__, 2);

return [
    'pins the API version of the published contract' => static function () use ($root): void {
        $contract = json_decode((string) file_get_contents($root . '/contract/openapi.json'), true, 512, JSON_THROW_ON_ERROR);
        check(Version::API_VERSION === $contract['info']['version'], 'API_VERSION differs from contract/openapi.json');
        check(Version::API_VERSION === '2026-03-20', 'API_VERSION is not 2026-03-20');
    },
    'carries the one version number of the repository' => static function () use ($root): void {
        check(Version::SDK_VERSION === trim((string) file_get_contents($root . '/VERSION')), 'SDK_VERSION differs from VERSION');
    },
    'describes a client by reflection: only methods with #[Operation] count' => static function (): void {
        $client = new class () {
            public object $vaults;
            public object $transactions;
            public string $version = '1';

            public function __construct()
            {
                $this->vaults = new class () {
                    #[Operation('listVaults')]
                    public function listVaults(array $params = []): array
                    {
                        return [];
                    }

                    public function helper(): void
                    {
                    }
                };
                $this->transactions = new class () {
                    #[Operation('createSingleTransfer')]
                    public function createSingleTransfer(array $params = []): array
                    {
                        return [];
                    }
                };
            }
        };
        $methods = Surface::clientMethods($client);
        check($methods === [
            ['namespace' => 'transactions', 'method' => 'createSingleTransfer', 'operationId' => 'createSingleTransfer'],
            ['namespace' => 'vaults', 'method' => 'listVaults', 'operationId' => 'listVaults'],
        ], 'unexpected methods: ' . json_encode($methods));
    },
    'describes the real client: one method per documented operation, and the operation table as the coverage check reads it' => static function (): void {
        $client = new Vaultody(['apiKey' => 'surface', 'apiSecret' => 'c3VyZmFjZQ==', 'passphrase' => 'surface']);
        $surface = Surface::describe($client);
        check($surface['language'] === 'php', 'language');
        $methods = $surface['clients']['php'];
        check(count($methods) === 32 && count(Operations::ALL) === 32, 'methods ' . count($methods));
        $ids = array_column($methods, 'operationId');
        sort($ids);
        $table = array_column(Operations::ALL, 'operationId');
        sort($table);
        check($ids === $table && count(array_unique($ids)) === 32, 'one method per operation of the table');
        foreach ($methods as $method) {
            check($method['method'] === $method['operationId'], 'named by its operationId: ' . $method['method']);
            check($method['namespace'] === Operations::get($method['operationId'])['group'], 'in its docs group: ' . $method['method']);
        }
        foreach ($surface['operations'] as $entry) {
            check(array_keys($entry) === ['operationId', 'method', 'path', 'params'], 'entry keys');
            foreach ($entry['params'] as $param) {
                check(array_keys($param) === ['name', 'in', 'required'], 'param keys, in the order the coverage check compares');
            }
        }
        check(Surface::describe()['clients'] === ['php' => []], 'no client, no methods');
    },
];
