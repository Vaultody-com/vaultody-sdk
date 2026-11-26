<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * A vault's xpub differs from the one pinned (stored or configured), a pinned one is gone, the vault gained an
 * algorithm, or its type changed. Nothing in the response was used and no pin was changed. Each alarm names the
 * vault, the algorithm and short hashes of both xpubs, never an xpub itself. Only an explicit re-pin, after an
 * out-of-band check with Vaultody, ends it: `npx @vaultody/sdk vault-keys accept` on the pin file,
 * Pins::replace() on a store, or a new pinnedVaultKeys entry.
 */
final class VaultKeyChangedError extends VaultodyError
{
    /**
     * @param list<array{vaultId: string, algorithm: ?string, reason: string, pinned: ?string, seen: ?string}> $alarms
     */
    public function __construct(public readonly array $alarms)
    {
        $names = array_map(static fn (array $alarm): string => sprintf('vault %s (%s)', $alarm['vaultId'], $alarm['algorithm'] ?? $alarm['reason']), $alarms);
        parent::__construct(sprintf('the xpub of %s differs from the one pinned; nothing in the response was used', implode(', ', $names)));
    }
}
