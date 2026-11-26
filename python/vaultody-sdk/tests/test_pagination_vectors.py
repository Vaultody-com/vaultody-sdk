"""test-vectors/pagination-v1.json: sequences of pages → the requests made, the items yielded, why it
stopped; with a sync and with an async fetch."""

import asyncio

import pytest

from vaultody_sdk import PaginationError, apaginate, paginate

from sdk_vectors import ids, load

VECTORS = load("pagination-v1.json")


def options(vector):
    return {
        "paging": vector["paging"],
        "cursor_field": vector["cursorField"],
        "limit": vector["limit"],
        "max_limit": vector["maxLimit"],
        "max_items": vector.get("maxItems"),
    }


def field_of(vector):
    return vector["itemField"] if vector["paging"] == "offset" else vector["cursorField"]


def check(vector, items, requests, stop, error):
    assert items == vector["expected"]["items"]
    assert len(requests) == len(vector["pages"]), "every page and no more"
    if "error" in vector["expected"]:
        assert error == vector["expected"]["error"]
    else:
        assert error is None
        assert stop == vector["expected"]["stop"]


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=ids(VECTORS["cases"]))
def test_sync(vector):
    requests = []

    def fetch_page(request):
        assert len(requests) < len(vector["pages"]), "an extra request: {}".format(request)
        page = vector["pages"][len(requests)]
        requests.append(request)
        assert request == page["request"]
        return page["response"]

    pages = paginate(fetch_page, **options(vector))
    items, error = [], None
    try:
        for item in pages:
            items.append(item.get(field_of(vector)))
    except PaginationError as e:
        error = e.code
    check(vector, items, requests, pages.stop, error)


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=ids(VECTORS["cases"]))
def test_async(vector):
    requests = []

    async def fetch_page(request):
        assert len(requests) < len(vector["pages"]), "an extra request: {}".format(request)
        page = vector["pages"][len(requests)]
        requests.append(request)
        assert request == page["request"]
        await asyncio.sleep(0)
        return page["response"]

    async def run():
        pages = apaginate(fetch_page, **options(vector))
        items, error = [], None
        try:
            async for item in pages:
                items.append(item.get(field_of(vector)))
        except PaginationError as e:
            error = e.code
        return items, pages.stop, error

    items, stop, error = asyncio.run(run())
    check(vector, items, requests, stop, error)


def test_stop_is_none_until_exhausted():
    vector = next(case for case in VECTORS["cases"] if case["name"] == "listVaults_three_pages")
    pages_iter = iter(vector["pages"])
    pages = paginate(lambda request: next(pages_iter)["response"], cursor_field="id", limit=2, max_limit=50)
    iterator = iter(pages)
    next(iterator)
    assert pages.stop is None
    assert len(list(iterator)) == len(vector["expected"]["items"]) - 1
    assert pages.stop == "end"
