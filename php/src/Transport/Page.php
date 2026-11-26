<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Transport;

/** One page of a list. Transport::paginate() pages through all of them. */
final class Page
{
    /**
     * @param list<mixed> $items
     * @param 'cursor'|'offset' $paging
     */
    public function __construct(
        public readonly array $items,
        public readonly string $paging,
        public readonly int|float|null $limit,
        public readonly bool $hasMore,
        public readonly ?string $startingAfter,
        public readonly int|float|null $offset,
        public readonly int|float|null $total,
        public readonly Meta $meta,
    ) {
    }
}
