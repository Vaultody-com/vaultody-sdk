"""test-vectors/envelope-errors-v1.json: status, headers and raw body → result kind or typed error."""

import pickle

import pytest

import vaultody_sdk
from vaultody_sdk import errors

from sdk_vectors import ids, load

VECTORS = load("envelope-errors-v1.json")

# The vector's field names → read_envelope's
_META = {"apiVersion": "api_version", "requestId": "request_id", "context": "context", "replayed": "replayed"}
_PAGE = {"paging": "paging", "limit": "limit", "hasMore": "has_more", "startingAfter": "starting_after", "offset": "offset", "total": "total"}


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=ids(VECTORS["cases"]))
def test_envelope(vector):
    expected = vector["expected"]
    body = vector["body"].encode("utf-8")
    if expected["kind"] != "error":
        result = errors.read_envelope(vector["status"], vector["headers"], body)
        actual = {"kind": result["kind"]}
        for camel, snake in {**_META, **_PAGE}.items():
            if snake in result:
                actual[camel] = result[snake]
        if result["kind"] == "page":
            actual["count"] = len(result["items"])
        assert actual == expected
        return

    with pytest.raises(errors.ApiError) as raised:
        errors.read_envelope(vector["status"], vector["headers"], body)
    error = raised.value
    assert type(error).__name__ == expected["class"]
    assert isinstance(error, getattr(vaultody_sdk, expected["class"]))
    assert isinstance(error, errors.VaultodyError)
    assert error.status == vector["status"]
    assert error.code == expected["code"]
    assert error.message == expected["message"]
    assert str(error)
    assert error.request_id == expected["requestId"]
    assert error.api_version == expected["apiVersion"]
    assert error.replayed is expected["replayed"]
    assert error.retryable is expected["retryable"]
    if "details" in expected:
        assert error.details == expected["details"]
    else:
        assert not hasattr(error, "details")


def test_str_body_and_any_mapping_of_headers():
    vector = next(case for case in VECTORS["cases"] if case["name"] == "item_replayed_header_case")
    result = errors.read_envelope(vector["status"], dict(vector["headers"]), vector["body"])
    assert result["replayed"] is True


def test_an_api_error_survives_pickling():
    vector = next(case for case in VECTORS["cases"] if case["name"] == "error_with_details")
    with pytest.raises(errors.ApiError) as raised:
        errors.read_envelope(vector["status"], vector["headers"], vector["body"].encode("utf-8"))
    copy = pickle.loads(pickle.dumps(raised.value))
    assert type(copy) is type(raised.value)
    assert (copy.status, copy.code, copy.message, copy.details) == (raised.value.status, raised.value.code, raised.value.message, raised.value.details)


# -- sdkErrors: the errors the SDK raises with no answer of the API --------------------------------------

_SDK_ERRORS = VECTORS["sdkErrors"]


def _snake(name):
    return "".join("_" + letter.lower() if letter.isupper() else letter for letter in name)


@pytest.mark.parametrize("name", _SDK_ERRORS["classes"])
def test_sdk_error_is_exported_from_the_package_root(name):
    cls = getattr(vaultody_sdk, name)
    assert name in vaultody_sdk.__all__
    assert issubclass(cls, vaultody_sdk.VaultodyError)


@pytest.mark.parametrize("vector", _SDK_ERRORS["cases"], ids=ids(_SDK_ERRORS["cases"]))
def test_sdk_error(vector):
    import base64

    sent = []

    def refuse(request):
        sent.append(request)
        raise AssertionError("nothing may be sent")

    with pytest.raises(vaultody_sdk.VaultodyError) as raised:
        if "call" in vector:
            import httpx

            client = vaultody_sdk.Vaultody(
                api_key="TEST-ONLY-key", api_secret="VEVTVC1PTkxZ", passphrase="TEST-ONLY-passphrase",
                vault_key_store=vaultody_sdk.MemoryVaultKeyStore(), transport=httpx.MockTransport(refuse),
            )
            group = getattr(client, _snake(vector["call"]["group"]))
            getattr(group, _snake(vector["call"]["operationId"]))(**vector["call"]["params"])
        else:
            webhook = vector["webhook"]
            vaultody_sdk.webhooks.verify(base64.b64decode(webhook["bodyBase64"]), webhook["headers"], webhook["secrets"])
    error = raised.value
    assert sent == []
    assert type(error).__name__ == vector["expected"]["class"]
    assert isinstance(error, getattr(vaultody_sdk, vector["expected"]["class"]))
    for field, value in vector["expected"]["fields"].items():
        assert getattr(error, _snake(field)) == value, field
