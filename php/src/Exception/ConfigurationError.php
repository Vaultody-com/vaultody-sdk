<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * The client is set up wrongly: no root keys for a signed response, no vault key store where addresses must
 * be checked, an unusable signer, a non-https base URL. Raised before anything is sent where possible.
 */
class ConfigurationError extends VaultodyError
{
    /**
     * A string code where callers need one, the same in every language: no_root_keys (a signed response and no
     * response-signing root key to check it with). VaultKeyStoreError sets its own codes. Otherwise Exception's 0.
     *
     * @var string|int
     */
    public $code;

    /** A signed response and no root key to check it with: what a release without the production root does once responses are signed. */
    public static function noRootKeys(string $message, ?\Throwable $previous = null): self
    {
        $error = new self($message, 0, $previous);
        $error->code = 'no_root_keys';

        return $error;
    }
}
