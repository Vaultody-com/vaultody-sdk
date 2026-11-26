"""test-vectors/transport-errors-v1.json, the Python rows: an httpx exception → may the request have been sent."""

import httpx
import pytest

from vaultody_sdk import classify_transport_error

from sdk_vectors import load

VECTORS = load("transport-errors-v1.json")


@pytest.mark.parametrize("vector", VECTORS["python"], ids=[vector["name"] for vector in VECTORS["python"]])
def test_httpx_exception(vector):
    module, _, name = vector["exception"].partition(".")
    assert module == "httpx"
    error = getattr(httpx, name)("TEST failure")
    assert classify_transport_error(error) == vector["expected"]


def test_a_cause_is_followed():
    try:
        try:
            raise httpx.ConnectError("TEST refused")
        except httpx.ConnectError as inner:
            raise RuntimeError("wrapped") from inner
    except RuntimeError as outer:
        assert classify_transport_error(outer) == {"sent": False}


def test_a_real_refused_connection_is_not_sent():
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(httpx.TransportError) as raised:
        httpx.get("http://127.0.0.1:{}/".format(port), timeout=5)
    assert classify_transport_error(raised.value) == {"sent": False}


@pytest.mark.parametrize("value", [None, "ConnectError", 42, ValueError("x")])
def test_anything_else_is_unknown(value):
    assert classify_transport_error(value) == {"sent": "unknown"}
