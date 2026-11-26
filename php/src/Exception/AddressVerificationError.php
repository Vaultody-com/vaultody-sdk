<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * An address in a response does not derive from its vault's pinned xpub, or can't be checked where it must
 * be. The whole response is refused: a caller never gets part of a page. $code is the reason, the same in
 * every language (test-vectors/security-events-v1.json addressCodes): mismatch (the address, or the chain an item
 * names, is not the one asked for or derived), network_mismatch (the network an item names is not the one asked
 * for, or does not go with the vault type), invalid (an item without an address or with unreadable path
 * fields), unsupported, unknown_vault, path_missing (with requireAddressPaths on, a new deposit address came without
 * its derivation path), or another reason of the derivation. The security event address_verification_failed comes
 * first.
 */
final class AddressVerificationError extends VaultodyError
{
    /** @var string */
    public $code;

    public function __construct(string $code, string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->code = $code;
    }
}
