<?php

declare(strict_types=1);

// Prints this SDK's surface as JSON for scripts/coverage.mjs: the methods of a real client, found by
// reflection, and the operation table. The client is built with throwaway credentials and an in-memory pin
// store; it makes no request.

require __DIR__ . '/../src/autoload.php';

$client = new \Vaultody\Sdk\Vaultody([
    'apiKey' => 'surface',
    'apiSecret' => 'c3VyZmFjZQ==',
    'passphrase' => 'surface',
    'vaultKeyStore' => new \Vaultody\Sdk\VaultKeys\MemoryVaultKeyStore(),
]);

echo json_encode(\Vaultody\Sdk\Surface::describe($client), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
