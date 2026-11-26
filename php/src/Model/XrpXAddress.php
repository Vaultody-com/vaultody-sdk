<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** An XRP X-address (encodeXrpAddress). */
final class XrpXAddress extends Model
{
    /**
     * @param ?string $xAddress The X-address that holds both the classic address and the tag.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $xAddress = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
