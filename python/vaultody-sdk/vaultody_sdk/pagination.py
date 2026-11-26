"""Paging through a list operation (test-vectors/pagination-v1.json).

Each page is fetched by the caller's ``fetch_page``, which in the client is an ordinary call: signed,
verified and checked like any other. ``paginate`` drives a sync fetch, ``apaginate`` an async one; both
yield every item and record why they stopped in ``stop`` once exhausted. ``pages()`` walks the same list
page by page instead, for what each answer says besides its items (``meta``, such as the address checks).
"""

from typing import TYPE_CHECKING, AsyncIterator, Generic, Iterator, Optional, TypeVar

from .errors import PaginationError

if TYPE_CHECKING:
    from ._core import Page

T = TypeVar("T")


class _Pager:
    """The paging rules, shared by the sync and the async iterator."""

    def __init__(self, paging, cursor_field, limit, max_limit, max_items, starting_after=None, cursor_unknown=False):
        if paging not in ("cursor", "offset"):
            raise ValueError("paging must be 'cursor' or 'offset'")
        if paging == "cursor" and not cursor_unknown and (not isinstance(cursor_field, str) or not cursor_field):
            raise TypeError("cursor paging needs the operation's cursor_field")
        self.paging = paging
        self.cursor_field = cursor_field
        self.cursor_unknown = cursor_unknown
        self.page_limit = max_limit if limit is None else limit
        self.max_items = max_items
        self.yielded = 0
        self.starting_after = starting_after
        self.offset = 0
        self.used = set() if starting_after is None else {starting_after}

    def request(self):
        if self.paging == "offset":
            return {"offset": self.offset, "limit": self.page_limit}
        return {"startingAfter": self.starting_after, "limit": self.page_limit}

    def full(self):
        return self.max_items is not None and self.yielded >= self.max_items

    def after_page(self, page):
        """None to fetch the next page, or why to stop."""
        if self.full():
            return "max_items"
        items = page["items"]
        if self.paging == "offset":
            self.offset += len(items)
            total = page.get("total")
            if isinstance(total, int) and not isinstance(total, bool) and self.offset >= total:
                return "end"
            if not items:
                return "empty_page"
            return None
        if page.get("hasMore") is not True:
            return "end"
        if not items:
            return "empty_page"
        if self.cursor_unknown:
            # The docs don't say which field of the last item continues the list. Guessing could skip or
            # repeat items, so the list ends here with an error rather than looking complete.
            raise PaginationError(
                "cursor_unknown",
                "the API has more items, but which item field continues this list is not documented; "
                "pass startingAfter yourself to read further",
            )
        last = items[-1]
        cursor = last.get(self.cursor_field) if isinstance(last, dict) else None
        if not isinstance(cursor, str) or not cursor:
            raise PaginationError("missing_cursor", "the last item of the page has no {} to continue from".format(self.cursor_field))
        if cursor in self.used:
            raise PaginationError("pagination_loop", "the cursor {} came back a second time; stopping instead of looping".format(cursor))
        self.used.add(cursor)
        self.starting_after = cursor
        return None


def _page_of(fetched):
    """What ``pages()`` yields for a fetched page: the client's Page when the fetch kept it, else the page."""
    return fetched.get("page", fetched) if isinstance(fetched, dict) else fetched


class _Options:
    def __init__(self, paging, cursor_field, limit, max_limit, max_items, starting_after, cursor_unknown):
        self.args = (paging, cursor_field, limit, max_limit, max_items, starting_after, cursor_unknown)
        _Pager(*self.args)  # refuses bad options at once, not on the first iteration

    def pager(self):
        return _Pager(*self.args)


class Pages(Generic[T]):
    """Every item of a list, fetched page by page with a sync ``fetch_page``.

    Iterate it like any iterable (each loop starts again from the first page). Once exhausted, ``stop``
    is ``"end"``, ``"empty_page"`` or ``"max_items"``; a list that can't be paged safely raises
    PaginationError (``missing_cursor``, ``pagination_loop``, ``cursor_unknown``, ``not_paged``).
    ``pages()`` yields the pages themselves.
    """

    def __init__(
        self,
        fetch_page,
        *,
        paging="cursor",
        cursor_field=None,
        limit=None,
        max_limit,
        max_items=None,
        starting_after=None,
        cursor_unknown=False,
    ):
        self._fetch_page = fetch_page
        self._options = _Options(paging, cursor_field, limit, max_limit, max_items, starting_after, cursor_unknown)
        self.stop: Optional[str] = None

    def __iter__(self) -> Iterator[T]:
        pager = self._options.pager()
        self.stop = None
        while True:
            page = self._fetch_page(pager.request())
            for item in page["items"]:
                if pager.full():
                    break
                yield item
                pager.yielded += 1
            reason = pager.after_page(page)
            if reason is not None:
                self.stop = reason
                return

    def pages(self) -> "Iterator[Page[T]]":
        """Every page in turn: the client's ``Page`` objects, with ``items`` and ``meta``. ``max_items``
        stops the fetching once that many items have been fetched; the last page comes whole."""
        pager = self._options.pager()
        self.stop = None
        while True:
            page = self._fetch_page(pager.request())
            yield _page_of(page)
            pager.yielded += len(page["items"])
            reason = pager.after_page(page)
            if reason is not None:
                self.stop = reason
                return


class AsyncPages(Generic[T]):
    """Every item of a list, fetched page by page with an async ``fetch_page``; ``async for`` over it.

    ``stop`` and ``pages()`` (an async iterator here) as for Pages.
    """

    def __init__(
        self,
        fetch_page,
        *,
        paging="cursor",
        cursor_field=None,
        limit=None,
        max_limit,
        max_items=None,
        starting_after=None,
        cursor_unknown=False,
    ):
        self._fetch_page = fetch_page
        self._options = _Options(paging, cursor_field, limit, max_limit, max_items, starting_after, cursor_unknown)
        self.stop: Optional[str] = None

    async def _items(self):
        pager = self._options.pager()
        self.stop = None
        while True:
            page = await self._fetch_page(pager.request())
            for item in page["items"]:
                if pager.full():
                    break
                yield item
                pager.yielded += 1
            reason = pager.after_page(page)
            if reason is not None:
                self.stop = reason
                return

    def __aiter__(self) -> AsyncIterator[T]:
        return self._items()

    async def _pages(self):
        pager = self._options.pager()
        self.stop = None
        while True:
            page = await self._fetch_page(pager.request())
            yield _page_of(page)
            pager.yielded += len(page["items"])
            reason = pager.after_page(page)
            if reason is not None:
                self.stop = reason
                return

    def pages(self) -> "AsyncIterator[Page[T]]":
        """Every page in turn; see Pages.pages."""
        return self._pages()


def paginate(fetch_page, **options):
    """A Pages over a sync ``fetch_page``; see Pages."""
    return Pages(fetch_page, **options)


def apaginate(fetch_page, **options):
    """An AsyncPages over an async ``fetch_page``; see AsyncPages."""
    return AsyncPages(fetch_page, **options)


__all__ = ["AsyncPages", "Pages", "apaginate", "paginate"]
