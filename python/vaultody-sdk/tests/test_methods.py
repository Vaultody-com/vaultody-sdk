"""Every API method, on both clients, against the mock gateway.

Each operation is called with the docs' own example (contract/openapi.json: every path and query
parameter's example, the documented request body) and answered with the docs' own answer, signed by the
mock gateway. Checked: the HTTP method, the path, where each parameter went (path, query or body), the
request envelope, the result (an Item, or the items of every page), a documented error answer as its typed
error, paging, the retry class (a read is retried re-signed, a write is never signed twice), and that bad
arguments are refused before anything is sent. tests/test_method_addresses.py covers the address and
vault key checks of the operations that return them.
"""

import copy
import json
import re
import typing
from urllib.parse import parse_qsl

import pytest

from vaultody_sdk import (
    ApiError,
    AsyncPages,
    Item,
    Page,
    Pages,
    PaginationError,
    ParameterError,
    RequestOutcomeUnknownError,
    error_class_for,
)
from vaultody_sdk._operations import OPERATION_BY_ID, OPERATIONS

from conftest import make_client, run
from contract_examples import documented_error, example_call, success

ALL = sorted(OPERATION_BY_ID)
CONTEXT = "order-1842"
PENDING = "listApiKeySigningKeys"

SIGNING_KEY = {
    "fingerprint": "SHA256:1K9sRW4V/tM+To9K/9728DyV3Qg2kE7x/9UELb/Nixg",
    "algorithm": "ed25519",
    "status": "active",
    "createdTimestamp": 1795000000,
    "approvedTimestamp": 1795000300,
}


def signing_keys_answer(items, total=None):
    return {
        "apiVersion": "2026-03-20",
        "requestId": "6630f1c2a9e4b5d7c8e9f0e1",
        "data": {"limit": 2, "offset": 0, "total": len(items) if total is None else total, "items": items},
    }


def documented_call(operation_id):
    """``(params, path, query, body, (status, answer))`` of the operation's documented call."""
    if operation_id == PENDING:
        # contract/pending/ has no examples: the docs' fields, and no parameter at all.
        return {}, "/api-keys/current/signing-keys", {}, None, (200, signing_keys_answer([SIGNING_KEY]))
    params, path, query, body = example_call(operation_id)
    return params, path, query, body, success(operation_id)


class Route:
    """The mock gateway's route for one operation: records every request it runs, answers from a queue."""

    def __init__(self, gateway, operation):
        gateway.route(operation.method, re.sub(r"\{[^}]+\}", "[^/]+", operation.path), self)
        self.calls = []
        self.answers = []

    def __call__(self, request, match, body):
        self.calls.append((request, body))
        return self.answers.pop(0)

    def target(self, index):
        path, _, query = self.calls[index][0].url.raw_path.decode("ascii").partition("?")
        pairs = parse_qsl(query, keep_blank_values=True)
        assert len(pairs) == len(dict(pairs)), "no parameter twice"
        return path, dict(pairs)


def method_of(api, operation):
    return getattr(getattr(api.client, operation.namespace), operation.method_name)


async def call(api, operation, params, **options):
    """The method's result: an Item (awaited on the async client), or the Pages / AsyncPages of a list."""
    result = method_of(api, operation)(**options, **params)
    if operation.paging is not None:
        return result
    return (await result) if api.is_async else result


async def drain(api, pages):
    """The items of a list, and the error that ended it early (None at the end)."""
    items = []
    try:
        if api.is_async:
            async for item in pages:
                items.append(item)
        else:
            for item in pages:
                items.append(item)
    except Exception as error:  # noqa: BLE001 - returned for the test to check
        return items, error
    return items, None


def expect_parameter_error(kind, client, operation, params, code, **options):
    async def scenario(api):
        with pytest.raises(ParameterError) as raised:
            await call(api, operation, params, **options)
        return raised.value

    error = run(kind, client, scenario)
    assert error.code == code, str(error)
    return error


# -- one test per operation, per client -----------------------------------------------------------------


@pytest.mark.parametrize("operation_id", ALL)
def test_operation(kind, gateway, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    params, path, query, body, (status, answer) = documented_call(operation_id)
    context = None if operation_id == PENDING else CONTEXT
    error_status, error_answer = documented_error(operation_id) if operation_id != PENDING else (403, {
        "requestId": "6630f1c2a9e4b5d7c8e9f0e2", "error": {"code": "endpoint_not_allowed_for_api_key", "message": "TEST"},
    })
    route = Route(gateway, operation)
    paged = operation.paging is not None
    cursor = operation.cursor_field

    if paged:
        first = copy.deepcopy(answer)
        second = copy.deepcopy(answer)
        if cursor is not None:
            # Cursors of their own: the docs' startingAfter example is the cursor of the docs' answer item.
            first["data"]["hasMore"] = True
            second["data"]["hasMore"] = False
            for item in first["data"]["items"]:
                item[cursor] = item[cursor] + "-first"
            for item in second["data"]["items"]:
                item[cursor] = item[cursor] + "-next"
            route.answers = [(status, first), (status, second)]
        else:
            # getAddressBalance (cursor not documented) and listApiKeySigningKeys: one page.
            route.answers = [(status, first)]
        route.answers.append((error_status, error_answer))
    else:
        route.answers = [(status, answer), (error_status, error_answer)]

    async def scenario(api):
        options = {} if context is None else {"context": context}
        result = await call(api, operation, params, **options)
        if paged:
            items, failure = await drain(api, result)
            assert failure is None, failure
            result = (result, items)
        with pytest.raises(ApiError) as raised:
            again = await call(api, operation, params, **options)
            if paged:
                _, failure = await drain(api, again)
                raise failure
        return result, raised.value

    result, error = run(kind, make_client(kind, gateway), scenario)

    # The request: method, path, query and body exactly as documented.
    request, sent = route.calls[0]
    assert request.method == operation.method
    sent_path, sent_query = route.target(0)
    assert sent_path == path
    expected_query = dict(query)
    if operation.method == "GET" and context is not None:
        expected_query["context"] = context
    assert sent_query == expected_query
    if operation.method == "GET":
        assert request.content == b"" and sent is None
    else:
        assert sent == body, "the documented request body, context included"
        assert json.loads(request.content) == body
        assert request.headers["content-type"] == "application/json"
    assert request.headers["x-api-version"] == "2026-03-20"

    # The result.
    if paged:
        pages, items = result
        assert isinstance(pages, AsyncPages if kind == "async" else Pages)
        expected_items = first["data"]["items"] + (second["data"]["items"] if cursor is not None else [])
        assert items == expected_items
        assert pages.stop == "end"
        if cursor is not None:
            assert len(route.calls) == 3, "two pages, then the error call"
            next_path, next_query = route.target(1)
            assert next_path == path
            assert next_query == dict(expected_query, startingAfter=first["data"]["items"][-1][cursor]), "the cursor of the last item"
    else:
        assert isinstance(result, Item)
        assert result.item == answer["data"]["item"], "returned as documented, unknown fields kept"
        assert result.meta.status == status
        assert result.meta.request_id == answer["requestId"]
        assert result.meta.context == answer.get("context")
        assert result.meta.api_version == answer.get("apiVersion")
        assert result.meta.signature == "verified"

    # A documented error answer: its typed error.
    error_code = error_answer["error"]["code"]
    assert type(error) is error_class_for(error_status, error_code)
    assert (error.status, error.code, error.request_id) == (error_status, error_code, error_answer["requestId"])


# -- retry classes ----------------------------------------------------------------------------------------


def first_page_or_item(operation, answer):
    if operation.paging is not None:
        answer = copy.deepcopy(answer)
        answer["data"]["hasMore"] = False
    return answer


# The clients have response-signing roots: before their first write they make one signed read, which comes
# first in what the gateway received and to which nothing happens.
SIGNED_READ = None
SIGNED_READ_PATH = "/api-keys/current/signing-keys"


def after_the_signed_read(gateway):
    signed_read, *sent = gateway.received
    assert signed_read.method == "GET" and signed_read.url.path == SIGNED_READ_PATH
    return sent


@pytest.mark.parametrize("operation_id", ALL)
def test_a_5xx_is_retried_re_signed_for_a_read_and_never_for_a_write(kind, gateway, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    params, _, _, _, (status, answer) = documented_call(operation_id)
    route = Route(gateway, operation)
    route.answers = [(status, first_page_or_item(operation, answer))]
    if operation.retry == "write":
        gateway.intervene(SIGNED_READ)
    gateway.intervene(("status", 503))

    async def scenario(api):
        result = await call(api, operation, params)
        if operation.paging is not None:
            return await drain(api, result)
        return result, None

    if operation.retry == "read":
        result, failure = run(kind, make_client(kind, gateway), scenario)
        assert failure is None
        nonces = [request.headers["x-api-nonce"] for request in gateway.received]
        assert len(nonces) == 2 and len(set(nonces)) == 2, "retried, signed again"
        assert len(route.calls) == 1
    else:
        async def write(api):
            with pytest.raises(RequestOutcomeUnknownError):
                await call(api, operation, params)

        run(kind, make_client(kind, gateway), write)
        assert len(after_the_signed_read(gateway)) == 1, "a write that may have run is never sent again without a confirmed key pair"
        assert route.calls == []


@pytest.mark.parametrize("operation_id", [op.operation_id for op in OPERATIONS if op.retry == "write"])
def test_a_write_that_never_left_is_resent_unchanged(kind, gateway, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    params, _, _, _, (status, answer) = documented_call(operation_id)
    route = Route(gateway, operation)
    route.answers = [(status, answer)]
    gateway.intervene(SIGNED_READ, "connect_error")
    result = run(kind, make_client(kind, gateway), lambda api: call(api, operation, params))
    assert result.item == answer["data"]["item"]
    first, second = after_the_signed_read(gateway)
    for name in ("x-api-nonce", "x-api-timestamp", "x-api-sign"):
        assert first.headers[name] == second.headers[name], "the same signed request"
    assert len(route.calls) == 1, "carried out once"


# -- arguments refused before anything is sent ------------------------------------------------------------


@pytest.mark.parametrize("operation_id", ALL)
def test_an_undocumented_parameter_is_refused(kind, gateway, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    params = documented_call(operation_id)[0]
    error = expect_parameter_error(kind, make_client(kind, gateway), operation, dict(params, notAField="x"), "unknown_param")
    assert error.param == "notAField" and "notAField" in str(error)
    assert gateway.received == []


@pytest.mark.parametrize("operation_id", [op.operation_id for op in OPERATIONS if op.model.__required_keys__])
def test_each_required_parameter_is_required(kind, gateway, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    params = documented_call(operation_id)[0]
    for name in sorted(operation.model.__required_keys__):
        for missing in (dict((k, v) for k, v in params.items() if k != name), dict(params, **{name: None})):
            error = expect_parameter_error(kind, make_client(kind, gateway), operation, missing, "missing_param")
            assert error.param == name and name in str(error)
    assert gateway.received == []


@pytest.mark.parametrize("operation_id", [op.operation_id for op in OPERATIONS if op.params])
def test_a_mistyped_parameter_is_refused(kind, gateway, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    params = documented_call(operation_id)[0]
    hints = {name: type(value) for name, value in params.items()}
    for name, value in params.items():
        wrong = 1 if not isinstance(value, int) or isinstance(value, bool) else "1"
        if isinstance(value, (list, dict)):
            wrong = "not a list or an object"
        error = expect_parameter_error(kind, make_client(kind, gateway), operation, dict(params, **{name: wrong}), "invalid_param")
        assert error.param == name
    assert hints and gateway.received == []


ENUM_FIELDS = [
    (op.operation_id, name)
    for op in OPERATIONS
    for name, hint in typing.get_type_hints(op.model).items()
    if typing.get_origin(hint) is typing.Literal
]


@pytest.mark.parametrize("operation_id,name", ENUM_FIELDS)
def test_a_value_outside_the_documented_list_is_refused(kind, gateway, operation_id, name):
    operation = OPERATION_BY_ID[operation_id]
    params = documented_call(operation_id)[0]
    allowed = typing.get_args(typing.get_type_hints(operation.model)[name])
    value = params.get(name, allowed[0])
    assert value in allowed, "the docs' own example is one of the documented values"
    for wrong in (value.upper(), value + " ", "not-documented"):
        error = expect_parameter_error(kind, make_client(kind, gateway), operation, dict(params, **{name: wrong}), "invalid_param")
        assert error.param == name
        assert wrong not in str(error), "the value passed is never echoed"
        assert all(choice in str(error) for choice in allowed), "the error lists the documented values"
    assert gateway.received == []


def test_each_operation_takes_its_own_spelling_of_prepare_strategy(kind, gateway):
    multiple = OPERATION_BY_ID["createMultipleTransfer"]
    estimate = OPERATION_BY_ID["estimateTransactionFeeByAssetId"]
    multiple_params = documented_call("createMultipleTransfer")[0]
    estimate_params = documented_call("estimateTransactionFeeByAssetId")[0]
    for operation, params, foreign in ((multiple, multiple_params, "minimize_dust"), (estimate, estimate_params, "minimize-dust")):
        error = expect_parameter_error(kind, make_client(kind, gateway), operation, dict(params, prepareStrategy=foreign), "invalid_param")
        assert error.param == "prepareStrategy"
    assert gateway.received == []
    route = Route(gateway, estimate)
    route.answers = [success("estimateTransactionFeeByAssetId")]
    run(kind, make_client(kind, gateway), lambda api: call(api, estimate, dict(estimate_params, prepareStrategy="optimize_size")))
    assert route.calls[0][1]["data"]["item"]["prepareStrategy"] == "optimize_size"


def test_the_signing_keys_list_takes_no_parameter(kind, gateway):
    operation = OPERATION_BY_ID[PENDING]
    for name in ("limit", "offset"):
        expect_parameter_error(kind, make_client(kind, gateway), operation, {name: 1}, "unknown_param")
    assert gateway.received == []


@pytest.mark.parametrize("operation_id", [op.operation_id for op in OPERATIONS if "limit" in op.names("query")])
def test_limit_is_from_one_to_the_largest_page(kind, gateway, operation_id):
    operation = OPERATION_BY_ID[operation_id]
    params = documented_call(operation_id)[0]
    for limit in (0, -1, operation.max_limit + 1, True):
        expect_parameter_error(kind, make_client(kind, gateway), operation, dict(params, limit=limit), "invalid_param")
    expect_parameter_error(kind, make_client(kind, gateway), operation, params, "invalid_option", max_items=0)
    assert gateway.received == []


def test_nested_fields_are_checked_too(kind, gateway):
    operation = OPERATION_BY_ID["createMultipleTransfer"]
    params = documented_call("createMultipleTransfer")[0]
    recipient = params["recipients"][0]
    cases = [
        ([dict(recipient, amount=0.1)], "invalid_param", "recipients[0].amount"),
        ([dict(recipient, memo="x")], "unknown_param", "recipients[0].memo"),
        ([{"address": recipient["address"]}], "missing_param", "recipients[0].amount"),
        ([recipient, "not an object"], "invalid_param", "recipients[1]"),
    ]
    for recipients, code, where in cases:
        error = expect_parameter_error(kind, make_client(kind, gateway), operation, dict(params, recipients=recipients), code)
        assert error.param == where and where in str(error)
    error = expect_parameter_error(kind, make_client(kind, gateway), operation, dict(params, feeInput={"gasPrice": 5}), "invalid_param")
    assert error.param == "feeInput.gasPrice"
    expect_parameter_error(kind, make_client(kind, gateway), operation, params, "invalid_context", context=1842)
    assert gateway.received == []


def test_an_optional_parameter_passed_as_none_is_left_out(kind, gateway):
    operation = OPERATION_BY_ID["createSingleTransfer"]
    params, _, _, body, (status, answer) = documented_call("createSingleTransfer")
    route = Route(gateway, operation)
    route.answers = [(status, answer)]
    run(kind, make_client(kind, gateway), lambda api: call(api, operation, dict(params, maxFee=None, feeInput=None), context=CONTEXT))
    expected = copy.deepcopy(body)
    del expected["data"]["item"]["maxFee"]
    assert route.calls[0][1] == expected


# -- lists ------------------------------------------------------------------------------------------------


def test_pages_gives_every_page_with_its_meta_and_max_items_stops_early(kind, gateway):
    operation = OPERATION_BY_ID["listUtxos"]
    _, _, _, _, (status, answer) = documented_call("listUtxos")
    item = answer["data"]["items"][0]
    first = copy.deepcopy(answer)
    first["data"].update(hasMore=True, items=[dict(item, utxoId="u1"), dict(item, utxoId="u2")])
    second = copy.deepcopy(answer)
    second["data"].update(hasMore=False, items=[dict(item, utxoId="u3")], startingAfter="u2")
    route = Route(gateway, operation)
    route.answers = [(status, first), (status, second), (status, first)]

    async def scenario(api):
        pages = method_of(api, operation)(vaultId="v1", limit=2)
        if api.is_async:
            collected = [page async for page in pages.pages()]
        else:
            collected = list(pages.pages())
        limited = method_of(api, operation)(vaultId="v1", max_items=1)
        items, failure = await drain(api, limited)
        return pages, collected, limited, items, failure

    pages, collected, limited, items, failure = run(kind, make_client(kind, gateway), scenario)
    assert [type(page) for page in collected] == [Page, Page]
    assert [[entry["utxoId"] for entry in page.items] for page in collected] == [["u1", "u2"], ["u3"]]
    assert [page.has_more for page in collected] == [True, False]
    assert all(page.meta.signature == "verified" and page.meta.request_id == answer["requestId"] for page in collected)
    assert pages.stop == "end"
    assert [route.target(i)[1] for i in range(3)] == [
        {"limit": "2"}, {"limit": "2", "startingAfter": "u2"}, {"limit": "50"},
    ], "the documented largest page when no limit is given"
    assert failure is None and [entry["utxoId"] for entry in items] == ["u1"] and limited.stop == "max_items"


def test_a_list_without_a_documented_cursor_is_not_paged_past_its_first_page(kind, gateway):
    operation = OPERATION_BY_ID["getAddressBalance"]
    params, _, _, _, (status, answer) = documented_call("getAddressBalance")
    more = copy.deepcopy(answer)
    more["data"]["hasMore"] = True
    route = Route(gateway, operation)
    route.answers = [(status, more)]

    async def scenario(api):
        return await drain(api, await call(api, operation, params))

    items, failure = run(kind, make_client(kind, gateway), scenario)
    assert items == more["data"]["items"], "the first page is given"
    assert isinstance(failure, PaginationError) and failure.code == "cursor_unknown", "then an error, never a list that looks complete"
    assert len(route.calls) == 1


def test_a_signing_keys_list_longer_than_one_page_is_refused(kind, gateway):
    operation = OPERATION_BY_ID[PENDING]
    route = Route(gateway, operation)
    route.answers = [(200, signing_keys_answer([SIGNING_KEY, dict(SIGNING_KEY, fingerprint="SHA256:other")], total=3))]

    async def scenario(api):
        return await drain(api, await call(api, operation, {}))

    items, failure = run(kind, make_client(kind, gateway), scenario)
    assert len(items) == 2
    assert isinstance(failure, PaginationError) and failure.code == "not_paged"
    assert len(route.calls) == 1, "no offset is sent: the docs name no parameter"


def test_a_single_item_operation_answered_with_a_list_is_refused(kind, gateway):
    operation = OPERATION_BY_ID["getTransactionRequestDetails"]
    route = Route(gateway, operation)
    route.answers = [(200, {"apiVersion": "2026-03-20", "requestId": "r1", "data": {"limit": 1, "hasMore": False, "items": [{}]}})]

    async def scenario(api):
        with pytest.raises(ApiError) as raised:
            await call(api, operation, {"transactionRequestId": "t1"})
        return raised.value

    assert "instead of one item" in str(run(kind, make_client(kind, gateway), scenario))


def test_path_values_are_percent_encoded(kind, gateway):
    operation = OPERATION_BY_ID["getTransactionDetails"]
    route = Route(gateway, operation)
    route.answers = [success("getTransactionDetails")]
    run(kind, make_client(kind, gateway), lambda api: call(api, operation, {"vaultId": "a/b c", "blockchain": "ethereum", "transactionId": "0x?#"}))
    assert route.target(0)[0] == "/vaults/a%2Fb%20c/ethereum/transactions/0x%3F%23"
