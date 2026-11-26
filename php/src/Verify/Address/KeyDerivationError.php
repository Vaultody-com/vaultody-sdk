<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify\Address;

/**
 * An extended public key that can't be read, or a child that can't be derived from it. The address
 * check turns the first into `missing_key` and the second into `mismatch`; neither is ever a pass. The
 * message never holds the key itself.
 */
final class KeyDerivationError extends \RuntimeException
{
}
