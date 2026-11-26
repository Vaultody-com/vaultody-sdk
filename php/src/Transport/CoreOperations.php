<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Transport;

use Vaultody\Sdk\Operations;

/**
 * The operations the transport itself calls: the vault list, the only source of vault xpubs, and the
 * signing keys of the calling API key, which confirm that a key pair is active before a write is resent.
 * Both come from the operation table the client methods use, so the two can't differ.
 *
 * @internal
 */
final class CoreOperations
{
    public static function listVaults(): Operation
    {
        return Operations::transportOperation('listVaults');
    }

    /**
     * The docs declare no parameter: the list holds at most two keys, which is also the route's default
     * page size, so it is always whole on one page.
     */
    public static function listApiKeySigningKeys(): Operation
    {
        return Operations::transportOperation('listApiKeySigningKeys');
    }
}
