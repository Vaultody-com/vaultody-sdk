<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

use Vaultody\Sdk\Exception\PaginationError;

/**
 * Paging through a list operation (test-vectors/pagination-v1.json). Each page is fetched by the caller's
 * $fetchPage, which in the client is an ordinary call: signed, verified and checked like any other.
 */
final class Pagination
{
    /**
     * Yields every item of a list, page by page. The generator's return value (getReturn()) says why it
     * stopped: 'end', 'empty_page' or 'max_items'.
     *
     * @param array{paging?: 'cursor'|'offset', cursorField?: ?string, limit?: ?int, maxLimit: int, maxItems?: ?int} $options
     *        cursorField: for cursor paging, the item field sent as startingAfter (contract/overlay.json)
     * @param callable(array{startingAfter?: ?string, offset?: int, limit: int}): array{items: list<mixed>, hasMore?: bool, total?: int|float|null} $fetchPage
     * @return \Generator<int, mixed, mixed, 'end'|'empty_page'|'max_items'>
     * @throws PaginationError missing_cursor or pagination_loop
     */
    public static function paginate(array $options, callable $fetchPage): \Generator
    {
        $paging = $options['paging'] ?? 'cursor';
        $pageLimit = $options['limit'] ?? $options['maxLimit'];
        $maxItems = $options['maxItems'] ?? null;
        $yielded = 0;
        $full = static function () use (&$yielded, $maxItems): bool {
            return $maxItems !== null && $yielded >= $maxItems;
        };

        if ($paging === 'offset') {
            $offset = 0;
            while (true) {
                $page = $fetchPage(['offset' => $offset, 'limit' => $pageLimit]);
                foreach ($page['items'] as $item) {
                    if ($full()) {
                        return 'max_items';
                    }
                    yield $item;
                    $yielded++;
                }
                if ($full()) {
                    return 'max_items';
                }
                $offset += count($page['items']);
                $total = $page['total'] ?? null;
                if ((is_int($total) || is_float($total)) && $offset >= $total) {
                    return 'end';
                }
                if ($page['items'] === []) {
                    return 'empty_page';
                }
            }
        }

        $cursorField = $options['cursorField'] ?? null;
        if (!is_string($cursorField) || $cursorField === '') {
            throw new \InvalidArgumentException('cursor paging needs the operation\'s cursorField');
        }
        $startingAfter = null;
        $used = [];
        while (true) {
            $page = $fetchPage(['startingAfter' => $startingAfter, 'limit' => $pageLimit]);
            foreach ($page['items'] as $item) {
                if ($full()) {
                    return 'max_items';
                }
                yield $item;
                $yielded++;
            }
            if ($full()) {
                return 'max_items';
            }
            if (($page['hasMore'] ?? null) !== true) {
                return 'end';
            }
            if ($page['items'] === []) {
                return 'empty_page';
            }
            $last = $page['items'][count($page['items']) - 1];
            $cursor = is_array($last) ? ($last[$cursorField] ?? null) : null;
            if (!is_string($cursor) || $cursor === '') {
                throw new PaginationError('missing_cursor', sprintf('the last item of the page has no %s to continue from', $cursorField));
            }
            if (isset($used[$cursor])) {
                throw new PaginationError('pagination_loop', sprintf('the cursor %s came back a second time; stopping instead of looping', $cursor));
            }
            $used[$cursor] = true;
            $startingAfter = $cursor;
        }
    }
}
