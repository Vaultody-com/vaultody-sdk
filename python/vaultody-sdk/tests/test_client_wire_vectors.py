"""The remaining vector sets through both clients:

- envelope-errors-v1.json: an answer → the result, or the typed error raised by _request();
- pagination-v1.json: _paginate() makes exactly the vector's requests and yields its items;
- path-encoding-v1.json: the request line each client sends;
- transport-errors-v1.json (Python rows): an httpx failure → TransportError.sent, and for a write the
  difference between "never sent" (resent) and "may have run" (RequestOutcomeUnknownError);
- webhook-v1.json: client.webhooks.verify.
"""

import base64
import json

import httpx
import pytest

import vaultody_sdk
from vaultody_sdk import PaginationError, ParameterError, RequestOutcomeUnknownError, TransportError, WebhookPayloadError, errors
from vaultody_sdk.webhooks import IncomingTransactionRevertedEvent, OutgoingTransactionEvent, UnknownWebhookEvent
from vaultody_verify import WebhookSignatureError

from conftest import make_client, run
from mock_gateway import FakeClock, envelope_page
from sdk_vectors import ids, load

ENVELOPE = load("envelope-errors-v1.json")
PAGINATION = load("pagination-v1.json")
PATHS = load("path-encoding-v1.json")
TRANSPORT = load("transport-errors-v1.json")
WEBHOOKS = load("webhook-v1.json")


# Every answer here is unsigned: the clients have no response-signing roots (a release candidate before the API
# signs), so they accept it. A client with roots would refuse it as missing (test_client_response_vectors.py).
UNSIGNED = {"roots": None}


def transport(handler, log):
    def recorded(request):
        log.append(request)
        return handler(request)

    return httpx.MockTransport(recorded)


# -- envelope-errors-v1.json ------------------------------------------------------------------------

_META = {"apiVersion": "api_version", "requestId": "request_id", "context": "context", "replayed": "replayed"}


@pytest.mark.parametrize("vector", ENVELOPE["cases"], ids=ids(ENVELOPE["cases"]))
def test_envelope(kind, vector):
    log = []
    answer = lambda request: httpx.Response(vector["status"], headers=vector["headers"], content=vector["body"].encode("utf-8"))  # noqa: E731
    client = make_client(kind, None, transport=transport(answer, log), **UNSIGNED)
    expected = vector["expected"]

    async def scenario(api):
        if expected["kind"] == "error":
            with pytest.raises(errors.ApiError) as raised:
                await api.request("GET", "/answer")
            return raised.value
        return await api.request("GET", "/answer")

    result = run(kind, client, scenario)
    if expected["kind"] == "error":
        assert type(result).__name__ == expected["class"]
        assert isinstance(result, getattr(vaultody_sdk, expected["class"]))
        assert (result.status, result.code, result.message) == (vector["status"], expected["code"], expected["message"])
        assert (result.request_id, result.api_version, result.replayed, result.retryable) == (
            expected["requestId"], expected["apiVersion"], expected["replayed"], expected["retryable"]
        )
        if "details" in expected:
            assert result.details == expected["details"]
        return
    actual = {"kind": "item" if isinstance(result, vaultody_sdk.Item) else "page"}
    for camel, snake in _META.items():
        actual[camel] = getattr(result.meta, snake)
    if actual["kind"] == "page":
        actual.update(paging=result.paging, limit=result.limit, count=len(result.items))
        if result.paging == "cursor":
            actual.update(hasMore=result.has_more, startingAfter=result.starting_after)
        else:
            actual.update(offset=result.offset, total=result.total)
    assert actual == expected


# -- pagination-v1.json -----------------------------------------------------------------------------


def page_answers(vector, log):
    def handler(request):
        index = len(log) - 1
        assert index < len(vector["pages"]), "an extra request"
        page = vector["pages"][index]
        query = dict(httpx.QueryParams(request.url.query))
        expected = {key: str(value) for key, value in page["request"].items() if value is not None}
        assert query == expected
        data = dict(page["response"])
        return httpx.Response(200, json={"apiVersion": "2026-03-20", "requestId": "r", "data": data})

    return handler


@pytest.mark.parametrize("vector", PAGINATION["cases"], ids=ids(PAGINATION["cases"]))
def test_paginate(kind, vector):
    log = []
    client = make_client(kind, None, transport=transport(page_answers(vector, log), log), **UNSIGNED)
    field = vector["itemField"] if vector["paging"] == "offset" else vector["cursorField"]

    async def scenario(api):
        pages = api.client._paginate(
            "GET", "/things", cursor_field=vector["cursorField"], paging=vector["paging"],
            limit=vector["limit"], max_limit=vector["maxLimit"], max_items=vector.get("maxItems"),
        )
        items, error = [], None
        try:
            if api.is_async:
                async for item in pages:
                    items.append(item.get(field))
            else:
                for item in pages:
                    items.append(item.get(field))
        except PaginationError as raised:
            error = raised.code
        return items, pages.stop, error

    items, stop, error = run(kind, client, scenario)
    assert items == vector["expected"]["items"]
    assert len(log) == len(vector["pages"])
    if "error" in vector["expected"]:
        assert error == vector["expected"]["error"]
    else:
        assert (error, stop) == (None, vector["expected"]["stop"])


# -- path-encoding-v1.json --------------------------------------------------------------------------


@pytest.mark.parametrize("vector", PATHS["cases"], ids=ids(PATHS["cases"]))
def test_request_line(kind, vector):
    log = []
    client = make_client(kind, None, transport=transport(lambda request: httpx.Response(200, json=envelope_page([])), log), **UNSIGNED)
    query = [tuple(pair) for pair in vector["query"]]

    async def scenario(api):
        if "error" in vector["expected"]:
            with pytest.raises(ParameterError) as raised:
                await api.request("GET", vector["template"], path_params=vector["pathParams"], query=query)
            return raised.value.code
        await api.request("GET", vector["template"], path_params=vector["pathParams"], query=query)

    outcome = run(kind, client, scenario)
    if "error" in vector["expected"]:
        assert outcome == vector["expected"]["error"]
        assert log == []
    else:
        assert log[0].url.raw_path.decode("ascii") == vector["expected"]["target"]


# -- transport-errors-v1.json -----------------------------------------------------------------------


def failing(name):
    def handler(request):
        raise getattr(httpx, name.partition(".")[2])("TEST failure", request=request) if name != "httpx.TransportError" else httpx.TransportError("TEST failure")

    return handler


@pytest.mark.parametrize("vector", TRANSPORT["python"], ids=ids(TRANSPORT["python"]))
def test_transport_error_on_a_read(kind, vector):
    log = []
    client = make_client(kind, None, transport=transport(failing(vector["exception"]), log), **UNSIGNED)

    async def scenario(api):
        with pytest.raises(TransportError) as raised:
            await api.request("GET", "/answer")
        return raised.value

    error = run(kind, client, scenario)
    assert error.sent == vector["expected"]["sent"]
    assert type(error.__cause__).__name__ == vector["exception"].partition(".")[2]
    assert len(log) == 5, "a read is retried up to the attempt limit"


@pytest.mark.parametrize("vector", TRANSPORT["python"], ids=ids(TRANSPORT["python"]))
def test_transport_error_on_a_write(kind, vector):
    log = []
    client = make_client(kind, None, transport=transport(failing(vector["exception"]), log), **UNSIGNED)

    async def scenario(api):
        with pytest.raises((TransportError, RequestOutcomeUnknownError)) as raised:
            await api.request("POST", "/vaults/{vaultId}/transaction-requests/single-transfer", path_params={"vaultId": "v1"}, item={"amount": "1"})
        return raised.value

    error = run(kind, client, scenario)
    if vector["expected"]["sent"] is False:
        # Never sent, so it can't have run: the same signed request again, until the attempts run out.
        assert isinstance(error, TransportError) and error.sent is False
        assert len(log) == 5
        assert len({request.headers["x-api-nonce"] for request in log}) == 1
    else:
        # It may have run, and a legacy key's duplicate may not be refused: never sent again.
        assert isinstance(error, RequestOutcomeUnknownError)
        assert len(log) == 1
        assert error.nonce == log[0].headers["x-api-nonce"]


# -- webhook-v1.json --------------------------------------------------------------------------------


@pytest.mark.parametrize("vector", WEBHOOKS["cases"], ids=ids(WEBHOOKS["cases"]))
def test_webhook(kind, vector):
    client = make_client(kind, None, clock=FakeClock())
    body = base64.b64decode(vector["bodyBase64"])
    try:
        if vector["expected"]["valid"]:
            event = client.webhooks.verify(body, vector["headers"], vector["secrets"])
            assert event.secret_index == vector["expected"]["secretIndex"]
            payload = json.loads(body)
            assert isinstance(event, OutgoingTransactionEvent) and event.known
            assert event.event == payload["data"]["event"]
            assert dict(event.item) == payload["data"]["item"]
            assert (event.vault_id, event.webhook_id, event.idempotency_key) == (payload["walletId"], payload["webhookId"], payload["idempotencyKey"])
        else:
            with pytest.raises(WebhookSignatureError) as raised:
                client.webhooks.verify(body, vector["headers"], vector["secrets"])
            assert raised.value.reason == vector["expected"]["reason"]
    finally:
        run(kind, client, lambda api: _noop())


async def _noop():
    return None


def _signed(payload, secret="TEST-secret"):
    import hashlib
    import hmac

    body = json.dumps(payload).encode("utf-8")
    return body, {"X-Signature": hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}


def test_webhook_event_types():
    body, headers = _signed({"walletId": "w", "data": {"event": "INCOMING_TX_REVERTED", "item": {"inclusion": {"blockHeight": 7}}}})
    event = vaultody_sdk.webhooks.verify(body, headers, ["other", "TEST-secret"])
    assert isinstance(event, IncomingTransactionRevertedEvent) and event.inclusion == {"blockHeight": 7} and event.secret_index == 1
    body, headers = _signed({"data": {"event": "SOMETHING_NEW", "item": {"x": 1}}})
    event = vaultody_sdk.webhooks.verify(body, headers, "TEST-secret")
    assert isinstance(event, UnknownWebhookEvent) and not event.known and event.item["x"] == 1


def test_webhook_payload_checked_only_after_the_signature():
    body, headers = _signed({"data": {}})
    with pytest.raises(WebhookPayloadError):
        vaultody_sdk.webhooks.verify(body, headers, "TEST-secret")
    with pytest.raises(WebhookSignatureError):
        vaultody_sdk.webhooks.verify(b"not json", headers, "TEST-secret")
    with pytest.raises(TypeError):
        vaultody_sdk.webhooks.verify(json.loads(body), headers, "TEST-secret")
