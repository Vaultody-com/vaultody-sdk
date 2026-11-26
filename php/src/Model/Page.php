<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Exception\PaginationError;
use Vaultody\Sdk\Pagination;
use Vaultody\Sdk\Transport\Meta;

/**
 * One page of a list, as a list method returns it, and the way to every item after it.
 *
 *   $page = $vaultody->vaults->listVaults(['networkType' => 'main']);
 *   $page->items;               // this page: Vault[]
 *   $page->hasMore;             // whether the API has more after it
 *   $next = $page->nextPage();  // the following page, or null
 *   foreach ($page as $vault) { ... }  // every item from this page on, the following pages fetched as needed
 *
 * Each page is an ordinary call: signed, its signature verified, its addresses checked. Paging stops when
 * the API says there is no more or answers an empty page, and throws PaginationError when the same cursor
 * comes back twice or an item has no cursor field. A list the SDK can't continue on its own (the docs don't
 * name the cursor field, or document no parameter to ask for the rest) throws PaginationError
 * cannot_continue instead of stopping quietly, so a partial list is never taken for the whole.
 *
 * @template T of Model
 * @implements \IteratorAggregate<int, T>
 */
final class Page implements \IteratorAggregate
{
    /**
     * @param list<T> $items the items of this page
     * @param list<array<string, mixed>> $rawItems the same items as they came
     * @param bool $hasMore whether the API has more items after this page
     * @param int|float|null $limit the page size the API answered with
     * @param ?string $startingAfter the cursor the API says this page started after
     * @param int|float|null $total offset-paged lists: how many items there are in all
     * @param Meta $meta what the SDK knows about this page's answer: request id, signature, address checks
     * @param ?string $cursorField the item field whose value of the last item continues the list
     * @param ?int $requestLimit the page size asked for
     * @param ?string $requestCursor the cursor this page was asked for with
     * @param (\Closure(string): Page<T>)|null $continue fetches the page after a cursor; null when the SDK
     *        can't continue this list on its own
     * @internal built by the client methods
     */
    public function __construct(
        public readonly array $items,
        private readonly array $rawItems,
        public readonly bool $hasMore,
        public readonly int|float|null $limit,
        public readonly ?string $startingAfter,
        public readonly int|float|null $total,
        public readonly Meta $meta,
        private readonly ?string $cursorField,
        private readonly ?int $requestLimit,
        private readonly ?string $requestCursor,
        private readonly ?\Closure $continue,
    ) {
    }

    /**
     * The page after this one, or null when this is the last.
     *
     * @return Page<T>|null
     * @throws PaginationError cannot_continue, missing_cursor or pagination_loop
     */
    public function nextPage(): ?self
    {
        if (!$this->hasMore || $this->items === []) {
            return null;
        }
        $continue = $this->continueOrThrow();
        $cursor = $this->cursorOf($this->rawItems[count($this->rawItems) - 1]);
        if ($cursor === $this->requestCursor) {
            throw new PaginationError('pagination_loop', sprintf('the cursor %s came back a second time; stopping instead of looping', $cursor));
        }

        return $continue($cursor);
    }

    /**
     * Every item from this page on; the following pages are fetched as the loop reaches them. Its
     * getReturn() says why it stopped: end, empty_page or max_items.
     *
     * @return \Generator<int, T, mixed, string>
     * @throws PaginationError
     */
    public function autoPaging(?int $maxItems = null): \Generator
    {
        if ($this->continue === null) {
            $yielded = 0;
            foreach ($this->items as $item) {
                if ($maxItems !== null && $yielded >= $maxItems) {
                    return 'max_items';
                }
                yield $item;
                $yielded++;
            }
            if ($maxItems !== null && $yielded >= $maxItems) {
                return 'max_items';
            }
            if ($this->hasMore && $this->items !== []) {
                $this->continueOrThrow();
            }

            return $this->items === [] && $this->hasMore ? 'empty_page' : 'end';
        }

        // The vector-tested pager (test-vectors/pagination-v1.json) does the paging; this page is its first.
        $first = $this;
        $page = $this;
        $index = 0;
        $raw = Pagination::paginate([
            'paging' => 'cursor',
            'cursorField' => $this->cursorField,
            'limit' => $this->requestLimit,
            'maxLimit' => $this->requestLimit ?? 50,
            'maxItems' => $maxItems,
        ], function (array $request) use (&$first, &$page, &$index): array {
            if ($first !== null) {
                $page = $first;
                $first = null;
            } else {
                $page = $page->continueOrThrow()((string) $request['startingAfter']);
            }
            $index = 0;

            return ['items' => $page->rawItems, 'hasMore' => $page->hasMore];
        });
        foreach ($raw as $unused) {
            yield $page->items[$index++];
        }

        return $raw->getReturn();
    }

    /** @return \Generator<int, T, mixed, string> every item from this page on */
    public function getIterator(): \Generator
    {
        return $this->autoPaging();
    }

    /** @return \Closure(string): Page<T> */
    private function continueOrThrow(): \Closure
    {
        if ($this->continue === null) {
            throw new PaginationError('cannot_continue', $this->cursorField === null && $this->total === null
                ? 'the API has more items, but its docs do not say which field continues this list: ask for the next page with startingAfter yourself'
                : 'the API has more items, but this operation documents no parameter to ask for them');
        }

        return $this->continue;
    }

    /** @param array<string, mixed> $item */
    private function cursorOf(array $item): string
    {
        $cursor = $this->cursorField === null ? null : ($item[$this->cursorField] ?? null);
        if (!is_string($cursor) || $cursor === '') {
            throw new PaginationError('missing_cursor', sprintf('the last item of the page has no %s to continue from', (string) $this->cursorField));
        }

        return $cursor;
    }
}
