<?php

/*
 * The PHP side of conformance/interop/run.mjs: one command on stdin, one answer on stdout, through the PHP
 * SDK's own file store (Vaultody\Sdk\VaultKeys\FileVaultKeyStore). The protocol is in run.mjs.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/php/src/autoload.php';

use Vaultody\Sdk\Exception\VaultKeyStoreError;
use Vaultody\Sdk\VaultKeys\FileVaultKeyStore;

/** JSON with every map an object (an empty one {}) and every list a list, as the other helpers write it. */
function answer(mixed $value): void
{
    echo json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), "\n";
}

/** @param array<string, mixed> $pin */
function pinObject(array $pin): object
{
    $pin['keys'] = (object) $pin['keys'];
    if ($pin['verification'] !== null) {
        $pin['verification'] = (object) $pin['verification'];
    }

    return (object) $pin;
}

try {
    $request = json_decode((string) stream_get_contents(STDIN), true, 64, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
    $store = new FileVaultKeyStore($request['file']);
    if ($request['op'] === 'write') {
        foreach ($request['steps'] as $step) {
            if (isset($step['pin'])) {
                $pin = $step['pin']['pin'];
                $store->update($step['pin']['origin'], static function (array $state) use ($pin): array {
                    $state['vaults'][$pin['vaultId']] ??= $pin;

                    return $state;
                });
            } elseif (isset($step['latch'])) {
                $latch = $step['latch']['latch'];
                $store->update($step['latch']['origin'], static function (array $state) use ($latch): array {
                    $state['responseSignature'] ??= $latch;

                    return $state;
                });
            } else {
                throw new \InvalidArgumentException('a write step is a pin or a latch');
            }
        }
        answer(['ok' => true]);
    } elseif ($request['op'] === 'read') {
        $origins = new \stdClass();
        foreach ($request['origins'] as $origin) {
            $state = $store->read($origin);
            $pins = array_values($state['vaults']);
            usort($pins, static fn (array $a, array $b): int => strcmp($a['vaultId'], $b['vaultId']));
            $origins->{$origin} = [
                'responseSignature' => $state['responseSignature'] === null ? null : (object) $state['responseSignature'],
                'pins' => array_map('pinObject', $pins),
            ];
        }
        answer(['ok' => true, 'origins' => $origins]);
    } else {
        throw new \InvalidArgumentException('op is write or read');
    }
} catch (VaultKeyStoreError $error) {
    answer(['ok' => false, 'error' => $error->code]);
} catch (\Throwable $error) {
    fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . "\n");
    exit(1);
}
