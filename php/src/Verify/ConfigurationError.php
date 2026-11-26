<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * The verification module itself is set up wrongly, for example with no root keys to check a signed
 * response against. A separate class, so that a broken setup can never be mistaken for, or handled like,
 * a bad response.
 */
final class ConfigurationError extends \RuntimeException
{
}
