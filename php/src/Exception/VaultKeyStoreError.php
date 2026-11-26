<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * The vault key store can't be read, parsed or written (docs/vault-keys-file.md). A store that fails is never
 * treated as empty: an empty store would pin whatever xpub comes next. $code says why, with the same codes in
 * every language:
 *  - the file: not_json, unknown_format, malformed, insecure_permissions, not_regular_file, too_large;
 *  - reading and writing it: unreadable, unwritable, locked;
 *  - invalid_pin: a pin or latch handed to the store that the file format can't hold;
 *  - store_conflict: a pin changed in the store between the client's read and its write (another writer); the
 *    answer is refused, and calling again reads afresh.
 */
final class VaultKeyStoreError extends ConfigurationError
{
    /** @var string */
    public $code;

    public function __construct(string $code, string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->code = $code;
    }
}
