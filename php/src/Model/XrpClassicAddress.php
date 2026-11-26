<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** An XRP classic address and tag (decodeXrpAddress). */
final class XrpClassicAddress extends Model
{
    /**
     * @param ?string $classicAddress The classic XRP address inside the X-address.
     * @param ?string $tag The destination tag inside the X-address.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $classicAddress = null,
        public readonly ?string $tag = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
