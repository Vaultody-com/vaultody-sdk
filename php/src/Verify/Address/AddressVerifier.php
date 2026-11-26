<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Checks that an address the Vaultody API returned really belongs to a vault.
 *
 * Every vault address is derived from the vault's extended public key (xpub) with public math only, at
 * path m/{account index}/{0 deposit | 1 change}/{address index}. Given the xpub, a client can derive the
 * address itself and compare. A changed address then fails however it was changed, in a proxy, a CDN or
 * anywhere else on the way.
 *
 * The xpub must not come from the same channel unchecked, or whoever swaps the address could swap the
 * xpub too. This class does not decide where it comes from: it is handed the vault's pinned keys (taken
 * from GET /vaults/{main|test} and kept by the SDK's pin store), and only does the math.
 *
 * verify() runs its checks in a fixed order, shared with the other languages. The order decides which
 * reason a caller sees:
 *  0. argument types and ranges, else InvalidArgumentException;
 *  1. the chain and network are known, else `unsupported`;
 *  2. the vault's keys are given, else `unknown_vault`;
 *  3. "mainnet" goes with a main vault and any other network with a test vault, else `network_mismatch`;
 *  4. accountIndex, isChange and addressIndex are all present, else `not_verifiable` (returned instead of
 *     thrown with $allowUnverifiable);
 *  5. addressFormat, when given, is a format of the chain and not a refused one (p2sh on bitcoin-cash,
 *     dogecoin and dash, p2sh-cash on bitcoin-cash), else `unsupported`;
 *  6. the vault has a readable key for the chain's algorithm, else `missing_key`;
 *  7. the address derived at the path, in the given format or in any format of the chain when none is
 *     given (refused formats are skipped), equals the address (EVM chains: ignoring letter case), else
 *     `mismatch`.
 */
final class AddressVerifier
{
    // A canonical decimal, as the API writes an index it returns as a string: no sign, no leading zero.
    private const DECIMAL = '/^(0|[1-9][0-9]{0,9})$/D';

    /** @var array<string, DerivedNode|KeyDerivationError> parsed vault keys, by algorithm and xpub */
    private array $roots = [];

    /** @var array<string, DerivedNode> derived nodes, by algorithm, xpub and path */
    private array $nodes = [];

    /**
     * @param int $cacheLimit how many parsed keys and derived nodes to keep. Bounded, because the indexes
     *        come from API responses.
     */
    public function __construct(private readonly int $cacheLimit = 1024)
    {
        if ($cacheLimit < 1) {
            throw new \InvalidArgumentException('cacheLimit must be at least 1');
        }
    }

    /**
     * Checks that an address is the one the vault's key derives at its path.
     *
     * @param array{type: string, keys: array{ECDSA?: ?string, EDDSA?: ?string}}|null $vault the vault's
     *        pinned keys, type "main" or "test"; null when the vault is not known
     * @param array<string, mixed> $params the address as the API returned it, wire names: blockchain,
     *        network, address, accountIndex, isChange, addressIndex, addressFormat (any case; when absent,
     *        every format of the chain is tried), and optionally vaultId for the messages. Other fields
     *        are ignored.
     * @param bool $allowUnverifiable return ['verified' => false, 'reason' => 'not_verifiable'] for an
     *        address without a derivation path instead of throwing
     * @return array{verified: true, algorithm: string, path: string, address: string, addressFormat: string}|array{verified: false, reason: string}
     * @throws AddressVerificationError when the address is not verified
     * @throws \InvalidArgumentException for arguments of the wrong type or range
     */
    public function verify(?array $vault, array $params, bool $allowUnverifiable = false): array
    {
        $p = self::readParams($params);
        $v = $vault === null ? null : self::readVault($vault);
        $label = $p['vaultId'] === null ? 'the vault' : "vault {$p['vaultId']}";

        $main = Chains::isMainNetwork($p['blockchain'], $p['network']);
        if ($main === null) {
            throw new AddressVerificationError(AddressVerificationError::UNSUPPORTED, "{$p['blockchain']} on {$p['network']} is not a chain and network this version knows");
        }
        if ($v === null) {
            throw new AddressVerificationError(AddressVerificationError::UNKNOWN_VAULT, "the keys of {$label} are not known");
        }
        if (($v['type'] === 'main') !== $main) {
            throw new AddressVerificationError(AddressVerificationError::NETWORK_MISMATCH, "{$p['network']} does not belong with {$label}, a {$v['type']} vault");
        }

        if ($p['accountIndex'] === null || $p['isChange'] === null || $p['addressIndex'] === null) {
            if ($allowUnverifiable) {
                return ['verified' => false, 'reason' => AddressVerificationError::NOT_VERIFIABLE];
            }
            throw new AddressVerificationError(AddressVerificationError::NOT_VERIFIABLE, 'the address has no derivation path (accountIndex, isChange and addressIndex), so it cannot be checked against the vault key');
        }

        $formats = Chains::formats($p['blockchain']);
        if ($p['addressFormat'] !== null) {
            $format = strtolower($p['addressFormat']);
            if (!in_array($format, $formats, true)) {
                throw new AddressVerificationError(AddressVerificationError::UNSUPPORTED, "{$p['addressFormat']} is not an address format of {$p['blockchain']}");
            }
            if (Chains::isRefusedFormat($p['blockchain'], $format)) {
                throw new AddressVerificationError(AddressVerificationError::UNSUPPORTED, "{$p['addressFormat']} on {$p['blockchain']} is refused: it is P2SH-wrapped SegWit on a chain without SegWit, which anyone can spend");
            }
            $formats = [$format];
        } else {
            $formats = array_values(array_filter($formats, static fn (string $format): bool => !Chains::isRefusedFormat($p['blockchain'], $format)));
        }

        $algorithm = (string) Chains::algorithmOf($p['blockchain']);
        $xpub = $v['keys'][$algorithm];
        if ($xpub === null) {
            throw new AddressVerificationError(AddressVerificationError::MISSING_KEY, "{$label} has no {$algorithm} key");
        }
        $root = $this->root($xpub, $algorithm);
        if ($root instanceof KeyDerivationError) {
            throw new AddressVerificationError(AddressVerificationError::MISSING_KEY, "the {$algorithm} key of {$label} could not be read: {$root->getMessage()}");
        }

        $path = "m/{$p['accountIndex']}/{$p['isChange']}/{$p['addressIndex']}";
        try {
            $node = $this->node($xpub, $root, [$p['accountIndex'], $p['isChange'], $p['addressIndex']]);
        } catch (KeyDerivationError $error) {
            // Only possible past the last non-hardened index; the server cannot derive such an address
            // either.
            throw new AddressVerificationError(AddressVerificationError::MISMATCH, "the vault key derives no address at {$path}: {$error->getMessage()}");
        }

        $caseInsensitive = Chains::isCaseInsensitive($p['blockchain']);
        foreach ($formats as $format) {
            $derived = Chains::encode($p['blockchain'], $p['network'], $format, $node);
            // EVM addresses are hex, so a checksummed (EIP-55) spelling is the same address; every other
            // chain's encoding is case-sensitive.
            $same = $caseInsensitive ? strtolower($derived) === strtolower($p['address']) : $derived === $p['address'];
            if ($same) {
                return ['verified' => true, 'algorithm' => $algorithm, 'path' => $path, 'address' => $p['address'], 'addressFormat' => $format];
            }
        }

        throw new AddressVerificationError(AddressVerificationError::MISMATCH, "{$p['address']} is not the " . implode(' or ', $formats) . " address of {$label} at {$path}");
    }

    /** The parsed vault key, or why it can't be read; kept, so each vault key is read once. */
    private function root(string $xpub, string $algorithm): DerivedNode|KeyDerivationError
    {
        $cacheKey = $algorithm . "\0" . $xpub;
        if (!array_key_exists($cacheKey, $this->roots)) {
            try {
                $parsed = ExtendedPublicKey::parse($xpub, $algorithm);
            } catch (KeyDerivationError $error) {
                $parsed = $error;
            }
            self::remember($this->roots, $cacheKey, $parsed, $this->cacheLimit);
        }

        return $this->roots[$cacheKey];
    }

    /**
     * The node at a path below the vault key. Every prefix of the path is kept, so the addresses of one
     * account cost one derivation step each.
     *
     * @param list<int> $indexes
     */
    private function node(string $xpub, DerivedNode $root, array $indexes): DerivedNode
    {
        $node = $root;
        $cacheKey = $root->algorithm . "\0" . $xpub;
        foreach ($indexes as $index) {
            $cacheKey .= "\0" . $index;
            if (!array_key_exists($cacheKey, $this->nodes)) {
                self::remember($this->nodes, $cacheKey, Derivation::deriveChild($node, $index), $this->cacheLimit);
            }
            $node = $this->nodes[$cacheKey];
        }

        return $node;
    }

    /** Adds an entry, dropping the oldest when the cache is full. */
    private static function remember(array &$cache, string $key, mixed $value, int $limit): void
    {
        while (count($cache) >= $limit) {
            unset($cache[array_key_first($cache)]);
        }
        $cache[$key] = $value;
    }

    /**
     * @return array{type: string, keys: array{ECDSA: ?string, EDDSA: ?string}}
     */
    private static function readVault(array $vault): array
    {
        $type = $vault['type'] ?? null;
        if ($type !== 'main' && $type !== 'test') {
            throw new \InvalidArgumentException('the vault type must be "main" or "test"');
        }
        $keys = $vault['keys'] ?? null;
        if (!is_array($keys)) {
            throw new \InvalidArgumentException('the vault keys must be an array of ECDSA and EDDSA xpubs');
        }
        $read = [];
        foreach ([Chains::ECDSA, Chains::EDDSA] as $algorithm) {
            $xpub = $keys[$algorithm] ?? null;
            if ($xpub !== null && (!is_string($xpub) || $xpub === '')) {
                throw new \InvalidArgumentException("the vault's {$algorithm} xpub must be a non-empty string, or null");
            }
            $read[$algorithm] = $xpub;
        }

        return ['type' => $type, 'keys' => $read];
    }

    /**
     * @return array{vaultId: ?string, blockchain: string, network: string, address: string, addressFormat: ?string, accountIndex: ?int, isChange: ?int, addressIndex: ?int}
     */
    private static function readParams(array $params): array
    {
        $vaultId = $params['vaultId'] ?? null;
        if ($vaultId !== null && (!is_string($vaultId) || $vaultId === '')) {
            throw new \InvalidArgumentException('vaultId must be a non-empty string, or absent');
        }
        $addressFormat = $params['addressFormat'] ?? null;
        if ($addressFormat !== null && !is_string($addressFormat)) {
            throw new \InvalidArgumentException('addressFormat must be a string, or absent');
        }

        return [
            'vaultId' => $vaultId,
            'blockchain' => self::readString($params, 'blockchain'),
            'network' => self::readString($params, 'network'),
            'address' => self::readString($params, 'address'),
            'addressFormat' => $addressFormat,
            'accountIndex' => self::readIndex($params['accountIndex'] ?? null, 'accountIndex'),
            'isChange' => self::readChange($params['isChange'] ?? null),
            'addressIndex' => self::readIndex($params['addressIndex'] ?? null, 'addressIndex'),
        ];
    }

    private static function readString(array $params, string $name): string
    {
        $value = $params[$name] ?? null;
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException("{$name} must be a non-empty string");
        }

        return $value;
    }

    private static function readIndex(mixed $value, string $name): ?int
    {
        if ($value === null) {
            return null;
        }
        if (is_string($value) && preg_match(self::DECIMAL, $value) === 1) {
            $value = (int) $value;
        }
        if (!is_int($value) || $value < 0 || $value > Derivation::MAX_INDEX) {
            throw new \InvalidArgumentException("{$name} must be an integer from 0 to " . Derivation::MAX_INDEX . ', as an int or a decimal string');
        }

        return $value;
    }

    private static function readChange(mixed $value): ?int
    {
        return match (true) {
            $value === null => null,
            $value === true, $value === 1 => 1,
            $value === false, $value === 0 => 0,
            default => throw new \InvalidArgumentException('isChange must be true, false, 0 or 1'),
        };
    }
}
