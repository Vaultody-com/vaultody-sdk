<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Transport;

/** One item: data.item of the answer, with unknown fields kept and amounts as strings. */
final class Item
{
    /** @param array<string, mixed> $data */
    public function __construct(
        public readonly array $data,
        public readonly Meta $meta,
    ) {
    }
}
