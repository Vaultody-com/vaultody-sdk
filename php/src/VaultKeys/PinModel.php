<?php

declare(strict_types=1);

namespace Vaultody\Sdk\VaultKeys;

use Vaultody\Sdk\Exception\AddressVerificationError;
use Vaultody\Sdk\Exception\VaultKeyChangedError;

/**
 * Vault xpub pins: the data model and the decisions, without storage (test-vectors/vault-key-pins-v1.json).
 *
 * A pin records the xpub of each MPC algorithm of a vault, as first seen in GET /vaults/{networkType}:
 *  - verified: a signed answer, checked against a pinned root, showed these xpubs;
 *  - unverified: only an unsigned answer did (trust on first use), allowed for release candidates while
 *    production does not sign. It is never reported as verified, and becomes verified when a signed answer
 *    shows the same xpubs.
 * A pin can also be given in configuration (the transport's pinnedVaultKeys): it counts as verified, is never
 * stored, and is compared with every answer the same way.
 * An xpub that differs from its pin, or a pinned one that is gone, is an alarm: the whole answer is refused
 * and no pin changes. So is an algorithm added to a pinned vault, or a vault type change. Only an explicit
 * re-pin (the command line's vault-keys accept, Pins::replace(), or the configuration) ever changes a pin.
 *
 * A vault without MPC keys (SMART, AUTOMATION) has nothing to pin: its addresses are not verifiable, never
 * verified.
 */
final class PinModel
{
    public const VERIFIED = 'verified';
    public const UNVERIFIED = 'unverified';
    public const NOT_VERIFIABLE = 'not_verifiable';

    /** The MPC algorithms pinned, in the order alarms list them. */
    public const ALGORITHMS = ['ECDSA', 'EDDSA'];

    public const PINNED = 'pinned';
    public const UNCHANGED = 'unchanged';
    public const UPGRADED = 'upgraded';

    /** What an alarm names instead of an xpub: the first 16 hex characters of its SHA-256. */
    public static function xpubHash(string $xpub): string
    {
        return substr(hash('sha256', $xpub), 0, 16);
    }

    /**
     * The vaults of one answer of GET /vaults/{networkType}: data.items.
     *
     * @param mixed $items
     * @return list<array{vaultId: string, type: mixed, keys: array{ECDSA: ?string, EDDSA: ?string}}>
     * @throws \UnexpectedValueException an answer that is not a vault list
     */
    public static function readVaultList(mixed $items): array
    {
        if (!is_array($items) || !array_is_list($items)) {
            throw new \UnexpectedValueException('expected the items of a vault list');
        }

        $vaults = [];
        foreach ($items as $item) {
            if (!is_array($item) || !is_string($item['id'] ?? null) || $item['id'] === '') {
                throw new \UnexpectedValueException('a vault in the list has no id');
            }
            $keys = ['ECDSA' => null, 'EDDSA' => null];
            $mpcKeys = $item['mpcKeys'] ?? [];
            if (!is_array($mpcKeys) || !array_is_list($mpcKeys)) {
                throw new \UnexpectedValueException(sprintf('vault %s has a malformed mpcKeys list', $item['id']));
            }
            foreach ($mpcKeys as $entry) {
                if (!is_array($entry) || !is_string($entry['algorithm'] ?? null) || !is_string($entry['xpub'] ?? null) || $entry['xpub'] === '') {
                    throw new \UnexpectedValueException(sprintf('vault %s has an mpcKeys entry without an algorithm and an xpub', $item['id']));
                }
                $algorithm = strtoupper($entry['algorithm']);
                // As on the server (mpcKeys.find): the first key of an algorithm counts; others are ignored.
                if (in_array($algorithm, self::ALGORITHMS, true) && $keys[$algorithm] === null) {
                    $keys[$algorithm] = $entry['xpub'];
                }
            }
            $vaults[] = ['vaultId' => $item['id'], 'type' => $item['type'] ?? null, 'keys' => $keys];
        }

        return $vaults;
    }

    /** @param array{ECDSA: ?string, EDDSA: ?string} $keys */
    public static function hasKeys(array $keys): bool
    {
        foreach (self::ALGORITHMS as $algorithm) {
            if (($keys[$algorithm] ?? null) !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compares the vaults of one answer with the pins of its origin.
     *
     * @param array<string, array<string, mixed>> $pins vaultId => pin, the current pins of this API origin
     * @param list<array{vaultId: string, type: mixed, keys: array{ECDSA: ?string, EDDSA: ?string}}> $vaults from readVaultList
     * @param array{signed: bool, rootId?: string, timestamp?: int, now: int} $evidence whether the answer was
     *        signed and verified, the root that certified it and its response time, and the time now
     * @return array{outcomes: list<array{vaultId: string, outcome: string}>, changes: list<array<string, mixed>>}
     *         the pins to write: new ones and upgraded ones, in the order of the answer
     * @throws VaultKeyChangedError when any xpub differs from its pin; nothing may be written then
     */
    public static function observeVaults(array $pins, array $vaults, array $evidence): array
    {
        $outcomes = [];
        $changes = [];
        $alarms = [];
        $verification = $evidence['signed'] ? ['rootId' => $evidence['rootId'], 'timestamp' => $evidence['timestamp']] : null;

        foreach ($vaults as $vault) {
            $pin = $pins[$vault['vaultId']] ?? null;
            if ($pin === null) {
                if (!self::hasKeys($vault['keys'])) {
                    $outcomes[] = ['vaultId' => $vault['vaultId'], 'outcome' => self::NOT_VERIFIABLE];
                    continue;
                }
                $created = [
                    'vaultId' => $vault['vaultId'],
                    'type' => $vault['type'],
                    'keys' => ['ECDSA' => $vault['keys']['ECDSA'], 'EDDSA' => $vault['keys']['EDDSA']],
                    'status' => $evidence['signed'] ? self::VERIFIED : self::UNVERIFIED,
                    'firstSeenAt' => $evidence['now'],
                    'verifiedAt' => $evidence['signed'] ? $evidence['now'] : null,
                    'verification' => $verification,
                ];
                $pins[$vault['vaultId']] = $created;
                $changes[] = $created;
                $outcomes[] = ['vaultId' => $vault['vaultId'], 'outcome' => self::PINNED];
                continue;
            }

            $found = [];
            foreach (self::ALGORITHMS as $algorithm) {
                $pinned = $pin['keys'][$algorithm] ?? null;
                $seen = $vault['keys'][$algorithm];
                if ($pinned !== null && $seen !== $pinned) {
                    $found[] = ['vaultId' => $vault['vaultId'], 'algorithm' => $algorithm, 'reason' => $seen === null ? 'xpub_missing' : 'xpub_changed', 'pinned' => self::xpubHash($pinned), 'seen' => $seen === null ? null : self::xpubHash($seen)];
                } elseif ($pinned === null && $seen !== null) {
                    // Refused on purpose, like any change: the client confirms a new algorithm out of band and
                    // re-pins the vault (the command line's vault-keys accept, or Pins::replace()).
                    $found[] = ['vaultId' => $vault['vaultId'], 'algorithm' => $algorithm, 'reason' => 'xpub_added', 'pinned' => null, 'seen' => self::xpubHash($seen)];
                }
            }
            if ($vault['type'] !== ($pin['type'] ?? null)) {
                // A type change is refused the same way until the client re-pins the vault.
                $found[] = ['vaultId' => $vault['vaultId'], 'algorithm' => null, 'reason' => 'type_changed', 'pinned' => null, 'seen' => null];
            }
            if ($found !== []) {
                array_push($alarms, ...$found);
                continue;
            }

            if (($pin['status'] ?? null) === self::UNVERIFIED && $evidence['signed']) {
                $upgraded = array_replace($pin, ['status' => self::VERIFIED, 'verifiedAt' => $evidence['now'], 'verification' => $verification]);
                $pins[$vault['vaultId']] = $upgraded;
                $changes[] = $upgraded;
                $outcomes[] = ['vaultId' => $vault['vaultId'], 'outcome' => self::UPGRADED];
            } else {
                $outcomes[] = ['vaultId' => $vault['vaultId'], 'outcome' => self::UNCHANGED];
            }
        }

        if ($alarms !== []) {
            throw new VaultKeyChangedError($alarms);
        }

        return ['outcomes' => $outcomes, 'changes' => $changes];
    }

    /**
     * Whether an address must come with its derivation path (accountIndex, isChange, addressIndex): only with the
     * option requireAddressPaths on, only for a new address (generateDepositAddress: a list or an added asset may
     * hold older rows without one), and only on a chain this SDK can derive. Whether the vault has MPC keys is
     * decided by addressCheckStatus.
     */
    public static function addressPathRequired(bool $requireAddressPaths, string $operationId, bool $chainKnown): bool
    {
        return $requireAddressPaths && $operationId === 'generateDepositAddress' && $chainKnown;
    }

    /**
     * The status of one returned address, once its derivation was compared with the vault's pinned xpub.
     *
     * @param array{pin: ?array{status: string}, vaultHasKeys: bool, pathFields: bool, derivation: ?string, pathRequired?: bool} $check
     *        pathRequired: addressPathRequired()
     * @return 'verified'|'unverified'|'not_verifiable'
     * @throws AddressVerificationError mismatch when the address does not derive from the pinned xpub; path_missing
     *         when it comes without the path it must have
     */
    public static function addressCheckStatus(array $check): string
    {
        if (!$check['vaultHasKeys']) {
            return self::NOT_VERIFIABLE;
        }
        if (!$check['pathFields']) {
            if ($check['pathRequired'] ?? false) {
                throw new AddressVerificationError('path_missing', 'the address came without its derivation path (accountIndex, isChange, addressIndex), '
                    . 'so it can\'t be checked against the vault\'s pinned xpub');
            }

            return self::NOT_VERIFIABLE;
        }
        if ($check['pin'] === null) {
            throw new \LogicException('a vault with MPC keys is pinned before its addresses are checked');
        }
        if ($check['derivation'] !== 'match') {
            throw new AddressVerificationError('mismatch', 'the address does not derive from the vault\'s pinned xpub');
        }

        return $check['pin']['status'] === self::VERIFIED ? self::VERIFIED : self::UNVERIFIED;
    }
}
