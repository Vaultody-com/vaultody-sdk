<?php

declare(strict_types=1);

// test-vectors/vault-key-pins-v1.json: signed and unsigned vault lists, verified first, and what they do to
// the vault xpub pins (stored ones, and ones given in configuration); then the file store those pins live in.

use Vaultody\Sdk\Exception\AddressVerificationError;
use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\VaultKeyChangedError;
use Vaultody\Sdk\Exception\VaultKeyStoreError;
use Vaultody\Sdk\VaultKeys\FileVaultKeyStore;
use Vaultody\Sdk\VaultKeys\MemoryVaultKeyStore;
use Vaultody\Sdk\VaultKeys\Pins;
use Vaultody\Sdk\VaultKeys\PinModel;
use Vaultody\Sdk\Verify\ResponseSignatureError;
use Vaultody\Sdk\Verify\ResponseVerifier;

$vectors = vectors('vault-key-pins-v1.json');
$tests = [];

/** Pins sorted by vault id, every array's keys sorted, so two pin sets compare whatever their key order. */
$normalise = static function (iterable $pins): array {
    $sortKeys = static function (mixed $value) use (&$sortKeys): mixed {
        if (!is_array($value)) {
            return $value;
        }
        if (!array_is_list($value)) {
            ksort($value);
        }

        return array_map($sortKeys, $value);
    };
    $list = [];
    foreach ($pins as $pin) {
        $list[] = $sortKeys($pin);
    }
    usort($list, static fn (array $a, array $b): int => strcmp($a['vaultId'], $b['vaultId']));

    return $list;
};

foreach ($vectors['cases'] as $vector) {
    $tests['vault-key-pins-v1.json ' . $vector['name']] = static function () use ($vector, $vectors, $normalise): void {
        // $pins is the store; a configured pin counts as verified and takes the place of a stored one, as the
        // transport overlays them (pinnedVaultKeys), and is never written.
        $pins = [];
        foreach ($vector['initialPins'] as $pin) {
            $pins[$pin['vaultId']] = $pin;
        }
        $configured = [];
        foreach ($vector['configuredPins'] as $pin) {
            $configured[$pin['vaultId']] = $pin + ['status' => PinModel::VERIFIED];
        }
        foreach ($vector['steps'] as $index => $step) {
            ['request' => $request, 'response' => $response, 'now' => $now, 'expected' => $expected] = $step;
            try {
                $verdict = ResponseVerifier::verify(request_of($request), response_of($response), [
                    'roots' => array_map('root_pem', $vectors['pinnedRoots']),
                    'now' => $now,
                    'requireResponseSignature' => false,
                ]);
            } catch (ResponseSignatureError $error) {
                check(['error' => $error->reason] === $expected['signature'], "step $index signature error " . $error->reason);
                check($normalise($pins) === $normalise($expected['pinsAfter']), "step $index pins untouched");
                continue;
            }
            check(($verdict['verified'] ? 'verified' : 'absent') === $expected['signature'], "step $index signature");

            $body = json_decode((string) base64_decode($response['bodyBase64'], true), true, 512, JSON_BIGINT_AS_STRING);
            $vaults = PinModel::readVaultList($body['data']['items']);
            $evidence = $verdict['verified']
                ? ['signed' => true, 'rootId' => $verdict['rootId'], 'timestamp' => $verdict['timestamp'], 'now' => $now]
                : ['signed' => false, 'now' => $now];
            if (isset($expected['alarms'])) {
                $error = thrown(static fn () => PinModel::observeVaults($configured + $pins, $vaults, $evidence), VaultKeyChangedError::class);
                check($error->alarms === $expected['alarms'], "step $index alarms " . json_encode($error->alarms));
                foreach ($vaults as $vault) {
                    foreach ($vault['keys'] as $xpub) {
                        check($xpub === null || !str_contains($error->getMessage(), $xpub), 'an xpub in the alarm message');
                    }
                }
            } else {
                $result = PinModel::observeVaults($configured + $pins, $vaults, $evidence);
                check($result['outcomes'] === $expected['outcomes'], "step $index outcomes " . json_encode($result['outcomes']));
                foreach ($result['changes'] as $pin) {
                    check(!isset($configured[$pin['vaultId']]), "step $index: a configured pin is never written");
                    $pins[$pin['vaultId']] = $pin;
                }
            }
            check($normalise($pins) === $normalise($expected['pinsAfter']), "step $index pins after");
        }
    };
}

foreach ($vectors['addressChecks'] as $check) {
    $tests['vault-key-pins-v1.json address check: ' . $check['name']] = static function () use ($check): void {
        // A configured pin counts as verified.
        $pin = match ($check['pin']) {
            null => null,
            'configured' => ['status' => PinModel::VERIFIED],
            default => ['status' => $check['pin']],
        };
        // No pathRequired: the option requireAddressPaths is off.
        $required = $check['pathRequired'] ?? null;
        $pathRequired = $required !== null && PinModel::addressPathRequired($required['requireAddressPaths'], $required['operationId'], $required['chainKnown']);
        $input = ['pin' => $pin, 'vaultHasKeys' => $check['vaultHasKeys'], 'pathFields' => $check['pathFields'], 'derivation' => $check['derivation'], 'pathRequired' => $pathRequired];
        if (isset($check['expected']['error'])) {
            check(thrown(static fn () => PinModel::addressCheckStatus($input), AddressVerificationError::class)->code === $check['expected']['error'], 'code');
        } else {
            check(PinModel::addressCheckStatus($input) === $check['expected']['status'], 'status');
        }
    };
}

// Refused on purpose (the vectors pinned_vault_gains_algorithm and vault_type_changed hold the same): the client
// confirms such a change out of band and re-pins the vault.
$tests['pins refuse a new algorithm and a type change'] = static function () use ($vectors): void {
    $first = null;
    foreach ($vectors['cases'] as $vector) {
        if ($vector['name'] === 'first_sight_signed') {
            $first = $vector['steps'][0]['expected']['pinsAfter'][0];
        }
    }
    $ecdsaOnly = ['keys' => ['ECDSA' => $first['keys']['ECDSA'], 'EDDSA' => null]] + $first;
    $error = thrown(static fn () => PinModel::observeVaults([$first['vaultId'] => $ecdsaOnly], [['vaultId' => $first['vaultId'], 'type' => 'main', 'keys' => $first['keys']]], ['signed' => true, 'rootId' => 'r', 'timestamp' => 1, 'now' => 1]), VaultKeyChangedError::class);
    check($error->alarms[0]['reason'] === 'xpub_added' && $error->alarms[0]['pinned'] === null, 'xpub_added');
    $error = thrown(static fn () => PinModel::observeVaults([$first['vaultId'] => $first], [['vaultId' => $first['vaultId'], 'type' => 'test', 'keys' => $first['keys']]], ['signed' => true, 'rootId' => 'r', 'timestamp' => 1, 'now' => 1]), VaultKeyChangedError::class);
    check($error->alarms[0]['reason'] === 'type_changed', 'type_changed');
};

$tempDir = static function (): string {
    $dir = sys_get_temp_dir() . '/vaultody-store-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);

    return $dir;
};
$origin = 'https://rest.vaultody.com';
$pinOf = static fn (string $vaultId, string $status = 'unverified', string $ecdsa = 'xpubA'): array => [
    'vaultId' => $vaultId, 'type' => 'main', 'keys' => ['ECDSA' => $ecdsa, 'EDDSA' => null], 'status' => $status, 'firstSeenAt' => 1,
    'verifiedAt' => $status === 'verified' ? 2 : null, 'verification' => $status === 'verified' ? ['rootId' => 'r', 'timestamp' => 2] : null,
];

$tests['file store: starts empty, keeps pins per origin, writes mode 0600 in a 0700 directory'] = static function () use ($tempDir, $origin, $pinOf): void {
    $dir = $tempDir() . '/nested';
    $store = new FileVaultKeyStore($dir . '/vault-keys.json');
    check($store->read($origin) === ['responseSignature' => null, 'vaults' => [], 'audit' => []], 'empty');
    check(!file_exists($dir . '/vault-keys.json'), 'reading creates no file');
    $pin = $pinOf('v1');
    $latch = ['latchedAt' => 5, 'rootId' => 'r'];
    $stored = $store->update($origin, static fn (array $state): array => ['responseSignature' => $latch, 'vaults' => ['v1' => $pin], 'audit' => []]);
    check($stored === ['responseSignature' => $latch, 'vaults' => ['v1' => $pin], 'audit' => []], 'returned');
    check($store->read($origin) === $stored, 'stored');
    check($store->read('https://qa.example') === ['responseSignature' => null, 'vaults' => [], 'audit' => []], 'other origin untouched');
    check((fileperms($dir . '/vault-keys.json') & 0777) === 0600, 'file mode ' . decoct(fileperms($dir . '/vault-keys.json') & 0777));
    check((fileperms($dir) & 0777) === 0700, 'directory mode');
    check(array_values(array_diff(scandir($dir), ['.', '..'])) === ['vault-keys.json'], 'nothing but the file: no lock or temporary file left');
    // A second store on the same file (another PHP worker) sees the pin
    check((new FileVaultKeyStore($dir . '/vault-keys.json'))->read($origin)['vaults']['v1'] === $pin, 'seen by another instance');
};

$tests['file store: a change that throws, or returns what the file can\'t hold, writes nothing'] = static function () use ($tempDir, $origin, $pinOf): void {
    $path = $tempDir() . '/vault-keys.json';
    $store = new FileVaultKeyStore($path);
    $store->update($origin, static fn (array $state): array => ['vaults' => ['a' => $pinOf('a')]] + $state);
    $before = file_get_contents($path);
    thrown(static fn () => $store->update($origin, static function (array $state): array {
        throw new VaultKeyChangedError([['vaultId' => 'a', 'algorithm' => 'ECDSA', 'reason' => 'xpub_changed', 'pinned' => 'x', 'seen' => 'y']]);
    }), VaultKeyChangedError::class);
    foreach ([
        'a pin without its fields' => static fn (array $state): array => ['vaults' => ['b' => ['vaultId' => 'b']]] + $state,
        'a pin under another id' => static fn (array $state): array => ['vaults' => ['b' => $pinOf('c')]] + $state,
        'a status that does not exist' => static fn (array $state): array => ['vaults' => ['b' => ['status' => 'trusted'] + $pinOf('b')]] + $state,
        'a time that is not an integer' => static fn (array $state): array => ['vaults' => ['b' => ['firstSeenAt' => 1.5] + $pinOf('b')]] + $state,
        'a latch as a boolean' => static fn (array $state): array => ['responseSignature' => true] + $state,
        'an audit entry without a reason' => static fn (array $state): array => ['audit' => [['vaultId' => 'a', 'at' => 1, 'reason' => ' ', 'removed' => false]]] + $state,
    ] as $what => $change) {
        check(thrown(static fn () => $store->update($origin, $change), VaultKeyStoreError::class)->code === 'invalid_pin', $what);
    }
    check(thrown(static fn () => $store->update('not an origin', static fn (array $state): array => ['vaults' => ['a' => $pinOf('a')]] + $state), VaultKeyStoreError::class)->code === 'invalid_pin', 'not an origin');
    thrown(static fn () => $store->update($origin, static fn (array $state): array => ['pins' => []]), UnexpectedValueException::class);
    check(file_get_contents($path) === $before, 'unchanged');
    check(thrown(static fn () => (new MemoryVaultKeyStore())->update($origin, static fn (array $state): array => ['vaults' => ['b' => ['vaultId' => 'b']]] + $state), VaultKeyStoreError::class)->code === 'invalid_pin', 'the memory store checks the same');
};

$tests['file store: an unreadable or foreign file fails closed, never reads as empty'] = static function () use ($tempDir, $origin): void {
    foreach ([
        'not json' => 'not_json',
        '{"origins":{}}' => 'unknown_format',
        '{"format":"vaultody vault keys v1","origins":{"https://rest.vaultody.com":{"pins":{},"signedResponses":false}}}' => 'malformed',
        '' => 'not_json',
    ] as $contents => $code) {
        $path = $tempDir() . '/vault-keys.json';
        file_put_contents($path, (string) $contents);
        chmod($path, 0600);
        check(thrown(static fn () => (new FileVaultKeyStore($path))->read($origin), VaultKeyStoreError::class)->code === $code, 'read ' . $code);
        thrown(static fn () => (new FileVaultKeyStore($path))->update($origin, static fn (array $s): array => $s), ConfigurationError::class);
        check(file_get_contents($path) === (string) $contents, 'left as it was');
    }
    $dir = $tempDir();
    check(thrown(static fn () => (new FileVaultKeyStore($dir))->read($origin), VaultKeyStoreError::class)->code === 'not_regular_file', 'a directory');
    symlink($dir . '/elsewhere.json', $dir . '/link.json');
    check(thrown(static fn () => (new FileVaultKeyStore($dir . '/link.json'))->read($origin), VaultKeyStoreError::class)->code === 'not_regular_file', 'a dangling link');
    $path = $dir . '/open.json';
    file_put_contents($path, '{"format":"vaultody vault keys v1","origins":{}}');
    chmod($path, 0666);
    check(thrown(static fn () => (new FileVaultKeyStore($path))->read($origin), VaultKeyStoreError::class)->code === 'insecure_permissions', 'others can write it');
};

$tests['file store: the lock is the shared one: created exclusively, removed after, taken over when a dead process left it'] = static function () use ($tempDir, $origin, $pinOf): void {
    $path = $tempDir() . '/vault-keys.json';
    file_put_contents($path . '.lock', '1');
    touch($path . '.lock', time() - 60);
    (new FileVaultKeyStore($path))->update($origin, static fn (array $state): array => ['vaults' => ['v1' => $pinOf('v1')]] + $state);
    check(!file_exists($path . '.lock'), 'the stale lock is gone and the new one released');
    check((new FileVaultKeyStore($path))->read($origin)['vaults']['v1'] === $pinOf('v1'), 'written');
};

$tests['file store: an update that changes nothing does not write'] = static function () use ($tempDir, $origin, $pinOf): void {
    $path = $tempDir() . '/vault-keys.json';
    $store = new FileVaultKeyStore($path);
    $store->update($origin, static fn (array $state): array => $state);
    check(!file_exists($path), 'no file for nothing');
    $store->update($origin, static fn (array $state): array => ['vaults' => ['v1' => $pinOf('v1')]] + $state);
    touch($path, time() - 100);
    clearstatcache();
    $mtime = filemtime($path);
    $store->update($origin, static fn (array $state): array => $state);
    clearstatcache();
    check(filemtime($path) === $mtime, 'not rewritten');
};

$tests['pins: replace is the only way to change a pin, and is audited'] = static function () use ($tempDir, $origin, $pinOf): void {
    foreach ([new MemoryVaultKeyStore(), new FileVaultKeyStore($tempDir() . '/vault-keys.json')] as $store) {
        $store->update($origin, static fn (array $state): array => ['vaults' => ['v1' => $pinOf('v1')]] + $state);
        thrown(static fn () => Pins::replace($store, $origin, 'v1', $pinOf('v1', 'unverified', 'xpubB'), '  '), InvalidArgumentException::class);
        thrown(static fn () => Pins::replace($store, $origin, 'v1', $pinOf('v2'), 'wrong vault'), InvalidArgumentException::class);
        Pins::replace($store, $origin, 'v1', $pinOf('v1', 'unverified', 'xpubB'), 'confirmed with support, ticket TEST-1', 100);
        check($store->read($origin)['vaults']['v1']['keys']['ECDSA'] === 'xpubB', 'replaced');
        Pins::replace($store, $origin, 'v1', null, 'vault deleted', 200);
        $state = $store->read($origin);
        check($state['vaults'] === [], 'removed');
        check($state['audit'] === [
            ['vaultId' => 'v1', 'at' => 100, 'reason' => 'confirmed with support, ticket TEST-1', 'removed' => false],
            ['vaultId' => 'v1', 'at' => 200, 'reason' => 'vault deleted', 'removed' => true],
        ], 'audited ' . json_encode($state['audit']));
    }
};

$tests['file store: concurrent writers lose no pin'] = static function () use ($tempDir): void {
    // Separate PHP processes stand in for PHP-FPM workers.
    $path = $tempDir() . '/vault-keys.json';
    $autoload = realpath(__DIR__ . '/../src/autoload.php');
    $script = sprintf('require %s; $s = new Vaultody\Sdk\VaultKeys\FileVaultKeyStore(%s); for ($i = 0; $i < 20; $i++) { $id = "v" . getmypid() . "-" . $i; $s->update("https://rest.vaultody.com", function (array $st) use ($id) { $st["vaults"][$id] = ["vaultId" => $id, "type" => "main", "keys" => ["ECDSA" => "xpubA", "EDDSA" => null], "status" => "unverified", "firstSeenAt" => 1, "verifiedAt" => null, "verification" => null]; return $st; }); }', var_export($autoload, true), var_export($path, true));
    $processes = [];
    for ($n = 0; $n < 4; $n++) {
        $processes[] = proc_open([PHP_BINARY, '-r', $script], [], $pipes);
    }
    foreach ($processes as $process) {
        check(proc_close($process) === 0, 'a writer failed');
    }
    check(count((new FileVaultKeyStore($path))->read('https://rest.vaultody.com')['vaults']) === 80, 'every pin of every writer is there');
};

return $tests;
