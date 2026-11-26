<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

use ReflectionMethod;
use ReflectionObject;
use ReflectionProperty;
use Vaultody\Sdk\Attribute\Operation;

/**
 * What this SDK really exposes, for scripts/coverage.mjs: the client's methods found by reflection, and
 * the operation table. A method counts only when it carries #[Operation].
 */
final class Surface
{
    /**
     * @return list<array{namespace: string, method: string, operationId: string}>
     */
    public static function clientMethods(?object $client): array
    {
        if ($client === null) {
            return [];
        }

        $methods = [];
        $reflection = new ReflectionObject($client);
        foreach ($reflection->getProperties(ReflectionProperty::IS_PUBLIC) as $property) {
            $group = $property->getValue($client);
            if (!is_object($group)) {
                continue;
            }
            foreach ((new ReflectionObject($group))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                foreach ($method->getAttributes(Operation::class) as $attribute) {
                    $methods[] = [
                        'namespace' => $property->getName(),
                        'method' => $method->getName(),
                        'operationId' => $attribute->newInstance()->operationId,
                    ];
                }
            }
        }
        usort($methods, static fn (array $a, array $b): int => [$a['namespace'], $a['method']] <=> [$b['namespace'], $b['method']]);

        return $methods;
    }

    /**
     * @return array{language: string, sdkVersion: string, apiVersion: string, clients: array{php: list<array{namespace: string, method: string, operationId: string}>}, operations: list<array<string, mixed>>}
     */
    public static function describe(?object $client = null): array
    {
        return [
            'language' => 'php',
            'sdkVersion' => Version::SDK_VERSION,
            'apiVersion' => Version::API_VERSION,
            'clients' => ['php' => self::clientMethods($client)],
            'operations' => array_map(static fn (array $entry): array => [
                'operationId' => $entry['operationId'],
                'method' => $entry['method'],
                'path' => $entry['path'],
                'params' => array_map(static fn (array $param): array => [
                    'name' => $param['name'],
                    'in' => $param['in'],
                    'required' => $param['required'],
                ], $entry['params']),
            ], Operations::ALL),
        ];
    }
}
