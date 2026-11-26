<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * Thrown when an address cannot be verified. `reason` is one of the constants below; callers branch on
 * it, so the strings are part of the public API and the same in every language. The message adds detail
 * for logs but is not meant to be matched on, and never holds an xpub.
 */
final class AddressVerificationError extends \RuntimeException
{
    // The address is not the one the vault's key derives at the given path and format.
    public const MISMATCH = 'mismatch';
    // The address has no derivation path (account index, change or address index is absent), as for
    // addresses a smart-contract vault creates. It cannot be checked against the vault's key.
    public const NOT_VERIFIABLE = 'not_verifiable';
    // The vault's keys are not known.
    public const UNKNOWN_VAULT = 'unknown_vault';
    // The vault has no key for the algorithm this chain uses, or its key cannot be read.
    public const MISSING_KEY = 'missing_key';
    // The network does not belong with the vault's type: "mainnet" needs a main vault, any other
    // network a test vault.
    public const NETWORK_MISMATCH = 'network_mismatch';
    // A chain, network or address format this version does not know, or one it refuses.
    public const UNSUPPORTED = 'unsupported';

    public const REASONS = [
        self::MISMATCH,
        self::NOT_VERIFIABLE,
        self::UNKNOWN_VAULT,
        self::MISSING_KEY,
        self::NETWORK_MISMATCH,
        self::UNSUPPORTED,
    ];

    public function __construct(public readonly string $reason, string $detail)
    {
        parent::__construct(sprintf('Vaultody address check failed (%s): %s', $reason, $detail));
    }
}
