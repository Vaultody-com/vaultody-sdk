<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Attribute;

use Attribute;

/**
 * Binds a client method to the documented operation it implements, so scripts/coverage.mjs can find it by
 * reflection: #[Operation('listVaults')].
 */
#[Attribute(Attribute::TARGET_METHOD)]
final class Operation
{
    public function __construct(public readonly string $operationId)
    {
    }
}
