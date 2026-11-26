<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Exception;

/**
 * The base of every error the SDK raises on purpose. The class names are the same in every language the SDK
 * ships in; callers branch on the class and on a string $code where there is one, never on the message.
 */
class VaultodyError extends \RuntimeException
{
}
