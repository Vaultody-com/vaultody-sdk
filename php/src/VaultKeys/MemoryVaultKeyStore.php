<?php

declare(strict_types=1);

namespace Vaultody\Sdk\VaultKeys;

/**
 * Pins kept in this object only. Under PHP-FPM every request is a new process, so pins kept in memory are
 * forgotten after each request and every vault would be trusted on first use again: the client never picks
 * this store by itself. It is for tests, long-running workers that pass it explicitly, and as the base of a
 * custom store. It holds what the file would hold, checked the same way.
 */
final class MemoryVaultKeyStore implements VaultKeyStore
{
    /** @var array<string, array{responseSignature: ?array{latchedAt: int, rootId: ?string}, vaults: array<string, array<string, mixed>>, audit: list<array<string, mixed>>}> */
    private array $origins = [];

    public function read(string $origin): array
    {
        return $this->origins[$origin] ?? FileVaultKeyStore::emptyState();
    }

    public function update(string $origin, callable $change): array
    {
        return $this->origins[$origin] = FileVaultKeyStore::checkState($origin, $change($this->read($origin)));
    }
}
