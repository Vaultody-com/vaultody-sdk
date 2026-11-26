<?php

declare(strict_types=1);

namespace Vaultody\Sdk\VaultKeys;

/**
 * The administrative change of a pin. The transport never calls it: a pinned xpub changes only after the new
 * one was confirmed out of band (with Vaultody support), and each change is kept in the origin's audit list.
 */
final class Pins
{
    /**
     * Sets (or, with $pin null, removes) the pin of a vault and records why.
     *
     * @param array<string, mixed>|null $pin the new pin, as PinModel describes it
     * @throws \InvalidArgumentException no reason, or a pin of another vault
     * @throws \Vaultody\Sdk\Exception\VaultKeyStoreError the store can't be read or written, or the pin is malformed
     */
    public static function replace(VaultKeyStore $store, string $origin, string $vaultId, ?array $pin, string $reason, ?int $now = null): void
    {
        if (preg_match('/(*UCP)\S/u', $reason) !== 1) {
            throw new \InvalidArgumentException('say why the pin is replaced; it is kept in the store\'s audit list');
        }
        if ($pin !== null && ($pin['vaultId'] ?? null) !== $vaultId) {
            throw new \InvalidArgumentException('the pin is not the pin of vault ' . $vaultId);
        }
        $at = $now ?? time();
        $store->update($origin, static function (array $state) use ($vaultId, $pin, $reason, $at): array {
            if ($pin === null) {
                unset($state['vaults'][$vaultId]);
            } else {
                $state['vaults'][$vaultId] = $pin;
            }
            $state['audit'][] = ['vaultId' => $vaultId, 'at' => $at, 'reason' => $reason, 'removed' => $pin === null];

            return $state;
        });
    }
}
