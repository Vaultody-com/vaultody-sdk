<?php

declare(strict_types=1);

namespace Vaultody\Sdk\VaultKeys;

/**
 * Where the vault xpub pins live, per API origin (such as https://rest.vaultody.com), so that test and
 * production pins never mix. The state of an origin is the origin entry of the vault keys file
 * (docs/vault-keys-file.md), the same in every SDK:
 *   [
 *     'responseSignature' => null | ['latchedAt' => int, 'rootId' => ?string], // the latch
 *     'vaults' => [vaultId => pin],                                             // pins as PinModel describes them
 *     'audit' => [['vaultId' => string, 'at' => int, 'reason' => string, 'removed' => bool], ...],
 *   ]
 * responseSignature is set once a response carrying a signature came from the origin, with the root that verified
 * it, or rootId null when it did not verify (from then on an unsigned one is refused); audit records every
 * administrative replacement or removal of a pin (Pins::replace).
 *
 * A store must fail closed: a state that can't be read or parsed is an error, never an empty state, because
 * an empty state would let the next vault list pin whatever xpub it carries. FileVaultKeyStore::checkState()
 * checks a state as the file format would.
 */
interface VaultKeyStore
{
    /**
     * @return array{responseSignature: ?array{latchedAt: int, rootId: ?string}, vaults: array<string, array<string, mixed>>, audit: list<array<string, mixed>>}
     * @throws \Vaultody\Sdk\Exception\VaultKeyStoreError the state can't be read
     */
    public function read(string $origin): array;

    /**
     * Runs $change on the current state of the origin while no other writer can change it, and stores what it
     * returns. When $change throws, nothing is written and the exception passes through.
     *
     * @param callable(array{responseSignature: ?array{latchedAt: int, rootId: ?string}, vaults: array<string, array<string, mixed>>, audit: list<array<string, mixed>>}): array<string, mixed> $change
     * @return array{responseSignature: ?array{latchedAt: int, rootId: ?string}, vaults: array<string, array<string, mixed>>, audit: list<array<string, mixed>>} the state stored
     * @throws \Vaultody\Sdk\Exception\VaultKeyStoreError the state can't be read or written, or what $change
     *         returned can't be stored (invalid_pin)
     */
    public function update(string $origin, callable $change): array;
}
