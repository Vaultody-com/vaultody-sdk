<?php

declare(strict_types=1);

// test-vectors/vault-keys-file-v1.json: the vault keys file every SDK shares (docs/vault-keys-file.md). Valid
// files read into the same pins and latch, refused files give the same code, file modes and links are checked
// before the bytes, and a writer writes the canonical bytes.

use Vaultody\Sdk\Exception\VaultKeyStoreError;
use Vaultody\Sdk\VaultKeys\FileVaultKeyStore;

$vectors = vectors('vault-keys-file-v1.json');
$posix = PHP_OS_FAMILY !== 'Windows';
$tests = [];

$tempDir = static function (): string {
    $dir = sys_get_temp_dir() . '/vaultody-keys-file-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);

    return $dir;
};

/** Maps with their keys sorted at every level (lists keep their order), so two documents compare whatever their key order. */
$sortMaps = static function (mixed $value) use (&$sortMaps): mixed {
    if (!is_array($value)) {
        return $value;
    }
    if (!array_is_list($value)) {
        ksort($value, SORT_STRING);
    }

    return array_map($sortMaps, $value);
};

$bytesOf = static fn (array $case): string => isset($case['base64']) ? (string) base64_decode($case['base64'], true) : $case['text'];
$writeFile = static function (string $path, string $bytes, int $mode = 0600): void {
    file_put_contents($path, $bytes);
    chmod($path, $mode);
};

/** The pins and latch of every expected origin, as the store reads them from $path. */
$checkStore = static function (string $path, array $origins, string $at) use ($sortMaps): void {
    $store = new FileVaultKeyStore($path);
    foreach ($origins as $origin => $entry) {
        $state = $store->read($origin);
        check($sortMaps($state['responseSignature']) === $sortMaps($entry['responseSignature']), "$at: the latch of $origin");
        check($sortMaps($state['vaults']) === $sortMaps($entry['vaults']), "$at: the pins of $origin");
        check($sortMaps($state['audit']) === $sortMaps($entry['audit']), "$at: the audit of $origin");
    }
    check($store->read('https://other.example.test') === FileVaultKeyStore::emptyState(), "$at: an origin not in the file is empty");
};

$validByName = [];
foreach ($vectors['valid'] as $case) {
    $validByName[$case['name']] = $case;
    $tests['vault-keys-file-v1.json valid ' . $case['name']] = static function () use ($case, $sortMaps, $tempDir, $writeFile, $checkStore): void {
        $document = FileVaultKeyStore::parse($case['text']);
        check($document['format'] === 'vaultody vault keys v1', 'format');
        check($sortMaps($document['origins']) === $sortMaps($case['expected']['origins']), 'origins ' . json_encode($document['origins']));
        $path = $tempDir() . '/vault-keys.json';
        $writeFile($path, $case['text']);
        $checkStore($path, $case['expected']['origins'], 'through the store');
    };
}

$invalidByName = [];
foreach ($vectors['invalid'] as $case) {
    $invalidByName[$case['name']] = $case;
    $tests['vault-keys-file-v1.json invalid ' . $case['name']] = static function () use ($case, $bytesOf, $tempDir, $writeFile): void {
        $bytes = $bytesOf($case);
        $code = $case['expected']['error'];
        check(thrown(static fn () => FileVaultKeyStore::parse($bytes), VaultKeyStoreError::class)->code === $code, 'parse: ' . $code);
        $path = $tempDir() . '/vault-keys.json';
        $writeFile($path, $bytes);
        $store = new FileVaultKeyStore($path);
        $read = thrown(static fn () => $store->read('https://rest.vaultody.com'), VaultKeyStoreError::class);
        check($read->code === $code, 'read: ' . $read->code . ' ' . $read->getMessage());
        // A refused file is never taken for an empty store: a change fails too and leaves it as it was.
        thrown(static fn () => $store->update('https://rest.vaultody.com', static fn (array $state): array => $state), VaultKeyStoreError::class);
        check(file_get_contents($path) === $bytes, 'left as it was');
    };
}

foreach ($vectors['files'] as $case) {
    $tests['vault-keys-file-v1.json files ' . $case['name']] = static function () use ($case, $posix, $validByName, $invalidByName, $tempDir, $writeFile, $checkStore): void {
        if ($case['posixOnly'] && !$posix) {
            return;
        }
        $dir = $tempDir();
        $path = $dir . '/vault-keys.json';
        $content = static function (string $name) use ($validByName, $invalidByName): string {
            return str_starts_with($name, 'invalid:') ? $invalidByName[substr($name, 8)]['text'] : $validByName[$name]['text'];
        };
        if (isset($case['mode'])) {
            $writeFile($path, $content($case['content']), octdec($case['mode']));
        } elseif (isset($case['symlinkTo'])) {
            $writeFile($dir . '/target.json', $content($case['symlinkTo']));
            symlink($dir . '/target.json', $path);
        } elseif (!empty($case['directory'])) {
            mkdir($path, 0700);
        }
        if (isset($case['expected']['error'])) {
            $error = thrown(static fn () => (new FileVaultKeyStore($path))->read('https://rest.vaultody.com'), VaultKeyStoreError::class);
            check($error->code === $case['expected']['error'], 'code ' . $error->code);
        } else {
            $checkStore($path, $case['expected']['origins'], $case['name']);
        }
    };
}

foreach ($vectors['canonical'] as $case) {
    $tests['vault-keys-file-v1.json canonical ' . $case['name']] = static function () use ($case, $tempDir): void {
        check(FileVaultKeyStore::encode($case['document']) === $case['text'], 'encode: ' . FileVaultKeyStore::encode($case['document']));
        check(FileVaultKeyStore::encode(FileVaultKeyStore::parse($case['text'])) === $case['text'], 'parse, then encode');
        // The store writes exactly those bytes for the same content, whatever order it is stored in.
        $path = $tempDir() . '/vault-keys.json';
        $store = new FileVaultKeyStore($path);
        foreach (array_reverse($case['document']['origins'], true) as $origin => $entry) {
            $store->update((string) $origin, static fn (array $state): array => $entry);
        }
        if ($case['document']['origins'] === []) {
            check(!file_exists($path), 'nothing to store: no file');
        } else {
            check(file_get_contents($path) === $case['text'], 'the store wrote ' . file_get_contents($path));
            check((fileperms($path) & 0777) === 0600 || PHP_OS_FAMILY === 'Windows', 'mode 0600');
        }
    };
}

return $tests;
