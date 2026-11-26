<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * The client is set up wrongly: no root keys for a signed response, no vault key store where addresses must
 * be checked, an unusable signer, a non-https base URL. Raised before anything is sent where possible.
 */
class ConfigurationError extends VaultodyError
{
}
