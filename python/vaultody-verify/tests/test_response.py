"""verify_response behaviour beyond the shared vectors: header mappings, inputs, modes, errors."""

import base64
import email.parser
import hashlib
import http.client
import io
import pickle
import types
from collections.abc import Mapping
from http import HTTPStatus

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import vaultody_verify.response as response_module
from vaultody_verify import ConfigurationError, ResponseSignatureError, VerificationResult, verify_response
from vaultody_verify import roots as roots_module

from vaultody_vectors import VECTORS, case, inputs, root_der, root_id, root_pem


def valid_inputs(name="valid_current_root"):
    return inputs(case(name))


def reason_of(request, response, **options):
    with pytest.raises(ResponseSignatureError) as failure:
        verify_response(request, response, **options)
    return failure.value.reason


class ReadOnlyHeaders(Mapping):
    """A Mapping that is not a dict, as some HTTP clients hand out."""

    def __init__(self, values):
        self._values = dict(values)

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


def http_message(pairs):
    """http.client's header object, which keeps repeated headers as separate entries."""
    text = "".join("{}: {}\r\n".format(name, value) for name, value in pairs) + "\r\n"
    return email.parser.Parser(_class=http.client.HTTPMessage).parsestr(text)


# Header mappings


@pytest.mark.parametrize(
    "wrap",
    [
        pytest.param(lambda headers: {name.upper(): value for name, value in headers.items()}, id="upper-case-dict"),
        pytest.param(lambda headers: {name.title(): value for name, value in headers.items()}, id="title-case-dict"),
        pytest.param(ReadOnlyHeaders, id="custom-mapping"),
        pytest.param(types.MappingProxyType, id="mapping-proxy"),
        pytest.param(lambda headers: http_message(headers.items()), id="http-client-message"),
    ],
)
def test_header_names_match_in_any_case_and_any_mapping(wrap):
    request, response, options = valid_inputs()
    response["headers"] = wrap(dict(response["headers"], **{"Content-Type": "application/json"}))
    assert verify_response(request, response, **options).verified is True


def test_requests_case_insensitive_dict():
    requests = pytest.importorskip("requests")
    request, response, options = valid_inputs()
    response["headers"] = requests.structures.CaseInsensitiveDict(
        {name.upper(): value for name, value in response["headers"].items()}
    )
    assert verify_response(request, response, **options).verified is True


def test_same_header_twice_in_different_case_is_invalid():
    request, response, options = valid_inputs()
    response["headers"]["X-Api-Response-Sign"] = response["headers"]["x-api-response-sign"]
    assert reason_of(request, response, **options) == "invalid"


def test_repeated_header_in_http_client_message_is_invalid():
    request, response, options = valid_inputs()
    pairs = list(response["headers"].items()) + [("x-api-response-cert", response["headers"]["x-api-response-cert"])]
    response["headers"] = http_message(pairs)
    assert reason_of(request, response, **options) == "invalid"


def test_repeated_header_joined_by_client_is_invalid():
    request, response, options = valid_inputs()
    sign = response["headers"]["x-api-response-sign"]
    response["headers"]["x-api-response-sign"] = sign + ", " + sign
    assert reason_of(request, response, **options) == "invalid"


def test_header_value_none_counts_as_absent():
    request, response, options = valid_inputs()
    response["headers"]["x-api-response-cert"] = None
    assert reason_of(request, response, **options) == "missing"


def test_non_text_header_value_is_invalid():
    request, response, options = valid_inputs()
    response["headers"]["x-api-response-sign"] = response["headers"]["x-api-response-sign"].encode("ascii")
    assert reason_of(request, response, **options) == "invalid"


def test_headers_none_is_an_unsigned_response():
    request, response, options = valid_inputs()
    response["headers"] = None
    assert reason_of(request, response, **options) == "missing"
    assert verify_response(request, response, require_response_signature=False, **options) == VerificationResult(
        verified=False, reason="missing"
    )


# Strict and non-strict modes


def test_strict_is_the_default():
    request, response, options = inputs(case("missing_all"))
    assert reason_of(request, response, **options) == "missing"


def test_non_strict_accepts_only_a_fully_unsigned_response():
    request, response, options = inputs(case("missing_all"))
    result = verify_response(request, response, require_response_signature=False, **options)
    assert result == VerificationResult(verified=False, reason="missing", key_id=None, root_id=None, timestamp=None)


def test_non_strict_treats_all_headers_empty_as_unsigned():
    request, response, options = valid_inputs()
    response["headers"] = {name: "" for name in response["headers"]}
    assert verify_response(request, response, require_response_signature=False, **options).verified is False


@pytest.mark.parametrize("stripped", ["missing_sign", "missing_cert", "empty_sign_header"])
def test_non_strict_still_rejects_a_partly_stripped_signature(stripped):
    request, response, options = inputs(case(stripped))
    assert reason_of(request, response, require_response_signature=False, **options) == "missing"


def test_non_strict_still_rejects_a_tampered_response():
    request, response, options = inputs(case("tampered_response_body"))
    assert reason_of(request, response, require_response_signature=False, **options) == "invalid"


# Inputs


def test_str_bodies_are_utf8():
    request, response, options = valid_inputs("valid_utf8_body")
    request["body"] = request["body"].decode("utf-8")
    response["body"] = response["body"].decode("utf-8")
    assert verify_response(request, response, **options).verified is True


def test_bytearray_and_memoryview_bodies():
    request, response, options = valid_inputs()
    request["body"] = bytearray(request["body"])
    response["body"] = memoryview(response["body"])
    assert verify_response(request, response, **options).verified is True


def test_no_body_and_no_api_sign_keys_mean_empty():
    request, response, options = valid_inputs("valid_unauthenticated_error")
    assert request["api_sign"] == ""
    del request["api_sign"]
    request.pop("body")
    assert verify_response(request, response, **options).verified is True


def test_api_sign_none_means_empty():
    request, response, options = valid_inputs("valid_unauthenticated_error")
    request["api_sign"] = None
    assert verify_response(request, response, **options).verified is True


@pytest.mark.parametrize("absent", ["missing", None, ""])
def test_no_keypair_sign_means_empty(absent):
    request, response, options = valid_inputs()
    assert request["keypair_sign"] == ""
    if absent == "missing":
        del request["keypair_sign"]
    else:
        request["keypair_sign"] = absent
    assert verify_response(request, response, **options).verified is True


@pytest.mark.parametrize("sent", ["missing", None, "", "other"])
def test_keypair_sign_is_bound(sent):
    request, response, options = valid_inputs("valid_with_keypair_sign")
    assert verify_response(request, response, **options).verified is True
    if sent == "missing":
        del request["keypair_sign"]
    elif sent == "other":
        request["keypair_sign"] = request["api_sign"]
    else:
        request["keypair_sign"] = sent
    assert reason_of(request, response, **options) == "invalid"


def test_keypair_sign_must_be_str_or_none():
    request, response, options = valid_inputs("valid_with_keypair_sign")
    request["keypair_sign"] = request["keypair_sign"].encode("ascii")
    with pytest.raises(TypeError):
        verify_response(request, response, **options)


def test_url_splits_at_the_first_question_mark():
    request, response, options = valid_inputs("valid_get_with_query")
    path, query = request["url"].split("?", 1)
    request["url"] = path + "?" + query + "?"
    assert reason_of(request, response, **options) == "invalid"


def test_empty_query_with_question_mark_is_an_empty_query():
    request, response, options = valid_inputs("valid_empty_query")
    request["url"] += "?"
    assert verify_response(request, response, **options).verified is True


def test_full_url_is_refused_as_a_caller_mistake():
    request, response, options = valid_inputs()
    request["url"] = "https://rest.vaultody.com" + request["url"]
    with pytest.raises(ValueError):
        verify_response(request, response, **options)


def test_http_status_enum():
    request, response, options = valid_inputs()
    response["status"] = HTTPStatus.CREATED
    assert verify_response(request, response, **options).verified is True


@pytest.mark.parametrize("status", ["201", 201.0, True, None])
def test_status_must_be_an_int(status):
    request, response, options = valid_inputs()
    response["status"] = status
    with pytest.raises(TypeError):
        verify_response(request, response, **options)


@pytest.mark.parametrize("field", ["method", "url"])
def test_method_and_url_are_required(field):
    request, response, options = valid_inputs()
    del request[field]
    with pytest.raises(TypeError):
        verify_response(request, response, **options)


def test_streamed_body_is_refused():
    request, response, options = valid_inputs()
    request["body"] = io.BytesIO(request["body"])
    with pytest.raises(TypeError):
        verify_response(request, response, **options)


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(lambda request: request.update(url=request["url"].replace("addresses", "addr\nesses")), id="newline-in-path"),
        pytest.param(lambda request: request.update(url=request["url"].replace("addresses", "adrèsses")), id="non-ascii-path"),
        pytest.param(lambda request: request.update(api_sign=request["api_sign"] + "\n"), id="newline-in-api-sign"),
        pytest.param(lambda request: request.update(keypair_sign="kp\tsign"), id="tab-in-keypair-sign"),
        pytest.param(lambda request: request.update(keypair_sign="ü"), id="non-ascii-keypair-sign"),
        pytest.param(lambda request: request.update(method=""), id="empty-method"),
    ],
)
def test_request_fields_the_gateway_cannot_sign_are_invalid(change):
    request, response, options = valid_inputs()
    change(request)
    assert reason_of(request, response, **options) == "invalid"


def test_overlong_timestamp_is_invalid_not_a_crash():
    request, response, options = valid_inputs()
    response["headers"]["x-api-response-timestamp"] = "1" * 5000
    assert reason_of(request, response, **options) == "invalid"


def test_timestamp_above_2_53_is_invalid():
    request, response, options = valid_inputs()
    response["headers"]["x-api-response-timestamp"] = str(2 ** 53)
    assert reason_of(request, response, **options) == "invalid"


@pytest.mark.parametrize("value", ["1794201000\n", "١٧٩٤٢٠١٠٠٠", " 1794201000"])
def test_timestamp_with_newline_or_non_ascii_digits_is_invalid(value):
    request, response, options = valid_inputs()
    response["headers"]["x-api-response-timestamp"] = value
    assert reason_of(request, response, **options) == "invalid"


@pytest.mark.parametrize("suffix", ["\n", " "])
def test_signature_with_trailing_whitespace_is_invalid(suffix):
    request, response, options = valid_inputs()
    response["headers"]["x-api-response-sign"] += suffix
    assert reason_of(request, response, **options) == "invalid"


# Time


def test_now_defaults_to_the_system_clock(monkeypatch):
    request, response, options = valid_inputs()
    vector_now = options.pop("now")
    monkeypatch.setattr(response_module.time, "time", lambda: vector_now + 0.9)
    assert verify_response(request, response, **options).verified is True

    not_after = case("valid_current_root")["signed"]["certificate"]["notAfter"]
    monkeypatch.setattr(response_module.time, "time", lambda: not_after + 301.0)
    assert reason_of(request, response, **options) == "expired"


def test_skew_is_configurable():
    request, response, options = inputs(case("now_beyond_skew"))
    options["max_clock_skew_seconds"] = 301
    assert verify_response(request, response, **options).verified is True
    options["max_clock_skew_seconds"] = 0
    assert reason_of(request, response, **options) == "expired"


def test_negative_skew_is_refused():
    request, response, options = valid_inputs()
    options["max_clock_skew_seconds"] = -1
    with pytest.raises(ValueError):
        verify_response(request, response, **options)


# The certificate's lifetime


def minted(not_before, not_after, ts):
    """A GET /ping answer signed now (``ts``) by TEST pod key 1, under a certificate from the TEST current root
    of v1.json valid from ``not_before`` to ``not_after``."""
    keys = VECTORS["keys"]
    root_key = serialization.load_pem_private_key(keys["roots"]["current"]["privateKeyPkcs8Pem"].encode("ascii"), password=None)
    pod = keys["podKeys"]["pod1"]
    pod_key = serialization.load_pem_private_key(pod["privateKeyPkcs8Pem"].encode("ascii"), password=None)
    cert = "\n".join(
        ("vaultody-response-key-v1", root_id("current"), pod["publicKeyBase64"], pod["keyId"], str(not_before), str(not_after))
    ).encode("ascii")
    cert_header = base64.b64encode(cert).decode("ascii") + "." + base64.b64encode(root_key.sign(cert, ec.ECDSA(hashes.SHA256()))).decode("ascii")
    body = b'{"data":{"item":{"pong":true}}}'
    head = "\n".join(("vaultody-response-v1", str(ts), "200", "GET", "/ping", "", hashlib.sha256(b"").hexdigest(), "TEST-sign", ""))
    headers = {
        "x-api-response-sign": base64.b64encode(pod_key.sign(head.encode("ascii") + b"\n" + body)).decode("ascii"),
        "x-api-response-timestamp": str(ts),
        "x-api-response-sign-version": "1",
        "x-api-response-cert": cert_header,
    }
    request = {"method": "GET", "url": "/ping", "body": b"", "api_sign": "TEST-sign", "keypair_sign": None}
    return request, {"status": 200, "headers": headers, "body": body}, {"roots": [root_der("current")], "now": ts}


def test_a_certificate_valid_for_an_hour_is_accepted():
    assert response_module.MAX_CERT_LIFETIME_SECONDS == 3600
    ts = 1794201000
    request, response, options = minted(ts - 60, ts - 60 + 3600, ts)
    assert verify_response(request, response, **options).verified


@pytest.mark.parametrize("lifetime", [3601, 10 * 365 * 24 * 3600])
def test_a_certificate_valid_for_longer_than_an_hour_is_invalid(lifetime):
    ts = 1794201000
    request, response, options = minted(ts - 60, ts - 60 + lifetime, ts)
    with pytest.raises(ResponseSignatureError) as raised:
        verify_response(request, response, **options)
    assert raised.value.reason == "invalid"
    assert "more than 3600 seconds" in str(raised.value)


# Roots


def test_no_roots_configured_is_a_configuration_error(monkeypatch):
    monkeypatch.setattr(roots_module, "EMBEDDED_ROOTS", ())
    request, response, options = valid_inputs()
    del options["roots"]
    with pytest.raises(ConfigurationError):
        verify_response(request, response, **options)


def test_this_build_embeds_no_roots_so_the_default_never_passes():
    """Until production roots are filled in at release, a call without roots= must raise."""
    if roots_module.EMBEDDED_ROOTS:
        pytest.skip("production roots are embedded in this build")
    request, response, options = valid_inputs()
    del options["roots"]
    with pytest.raises(ConfigurationError):
        verify_response(request, response, **options)


def test_an_unsigned_response_needs_no_root_in_non_strict_mode(monkeypatch):
    monkeypatch.setattr(roots_module, "EMBEDDED_ROOTS", ())
    request, response, options = inputs(case("missing_all"))
    del options["roots"]
    result = verify_response(request, response, require_response_signature=False, **options)
    assert result == VerificationResult(verified=False, reason="missing")
    options["roots"] = {"current": "", "next": None}
    result = verify_response(request, response, require_response_signature=False, **options)
    assert result == VerificationResult(verified=False, reason="missing")


def test_an_unsigned_response_is_missing_not_a_setup_mistake_in_strict_mode(monkeypatch):
    monkeypatch.setattr(roots_module, "EMBEDDED_ROOTS", ())
    request, response, options = inputs(case("missing_all"))
    del options["roots"]
    with pytest.raises(ResponseSignatureError) as raised:
        verify_response(request, response, **options)
    assert raised.value.reason == "missing"


def test_a_signed_response_still_fails_closed_when_the_roots_hold_no_key():
    request, response, options = valid_inputs()
    options["roots"] = {"current": "", "next": None}
    with pytest.raises(ConfigurationError):
        verify_response(request, response, **options)


def test_a_malformed_root_is_reported_at_once_even_for_an_unsigned_response():
    request, response, options = inputs(case("missing_all"))
    options["roots"] = ["not a key"]
    with pytest.raises(ConfigurationError):
        verify_response(request, response, require_response_signature=False, **options)


def test_empty_roots_override_is_a_configuration_error():
    request, response, options = valid_inputs()
    options["roots"] = []
    with pytest.raises(ConfigurationError):
        verify_response(request, response, **options)


def test_embedded_roots_are_used_when_no_override_is_given(monkeypatch):
    monkeypatch.setattr(roots_module, "EMBEDDED_ROOTS", (roots_module.load_root(root_pem("current")),))
    request, response, options = valid_inputs()
    del options["roots"]
    assert verify_response(request, response, **options).root_id == root_id("current")

    request, response, options = valid_inputs("valid_next_root")
    del options["roots"]
    assert reason_of(request, response, **options) == "unknown_root"


@pytest.mark.parametrize(
    "make_root",
    [
        pytest.param(lambda: root_pem("current"), id="pem-str"),
        pytest.param(lambda: root_pem("current").encode("ascii"), id="pem-bytes"),
        pytest.param(lambda: root_der("current"), id="der-bytes"),
        pytest.param(lambda: roots_module.load_root(root_der("current")).public_key, id="key-object"),
        pytest.param(lambda: roots_module.load_root(root_der("current")), id="root-object"),
    ],
)
def test_roots_override_accepts_pem_der_and_keys(make_root):
    request, response, options = valid_inputs()
    options["roots"] = [make_root()]
    assert verify_response(request, response, **options).root_id == root_id("current")


def test_roots_override_accepts_a_mapping_of_named_roots():
    request, response, options = valid_inputs("valid_next_root")
    options["roots"] = {"current": root_pem("current"), "next": root_pem("next")}
    assert verify_response(request, response, **options).root_id == root_id("next")


def test_roots_override_replaces_the_embedded_roots(monkeypatch):
    monkeypatch.setattr(roots_module, "EMBEDDED_ROOTS", (roots_module.load_root(root_pem("current")),))
    request, response, options = valid_inputs()
    options["roots"] = [root_pem("next")]
    assert reason_of(request, response, **options) == "unknown_root"


def test_a_single_pem_instead_of_a_list_is_refused():
    request, response, options = valid_inputs()
    options["roots"] = root_pem("current")
    with pytest.raises(TypeError):
        verify_response(request, response, **options)


@pytest.mark.parametrize(
    "make_key",
    [
        pytest.param(lambda: ec.generate_private_key(ec.SECP384R1()).public_key(), id="p384"),
        pytest.param(lambda: ed25519.Ed25519PrivateKey.generate().public_key(), id="ed25519"),
    ],
)
def test_roots_must_be_p256(make_key):
    request, response, options = valid_inputs()
    options["roots"] = [root_pem("current"), make_key()]
    with pytest.raises(ConfigurationError):
        verify_response(request, response, **options)


def test_unreadable_root_is_a_configuration_error():
    request, response, options = valid_inputs()
    options["roots"] = ["-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n"]
    with pytest.raises(ConfigurationError):
        verify_response(request, response, **options)


# Errors


def test_error_carries_reason_and_detail():
    request, response, options = inputs(case("tampered_response_body"))
    with pytest.raises(ResponseSignatureError) as failure:
        verify_response(request, response, **options)
    error = failure.value
    assert error.reason == "invalid"
    assert str(error).startswith("invalid: ")
    copy = pickle.loads(pickle.dumps(error))
    assert (copy.reason, copy.detail) == (error.reason, error.detail)


def test_unknown_reason_is_refused():
    with pytest.raises(ValueError):
        ResponseSignatureError("tampered")


def test_reasons():
    assert ResponseSignatureError.REASONS == (
        "missing",
        "invalid",
        "expired",
        "unknown_root",
        "request_unbound",
        "unsupported_version",
    )


def test_missing_roots_do_not_matter_in_non_strict_mode_for_an_unsigned_response(monkeypatch):
    from vaultody_verify import roots as roots_module

    monkeypatch.setattr(roots_module, "EMBEDDED_ROOTS", ())
    request, response, options = valid_inputs()
    del options["roots"]
    response["headers"] = {}
    unsigned = VerificationResult(verified=False, reason="missing")
    assert verify_response(request, response, require_response_signature=False, **options) == unsigned
    assert verify_response(request, response, require_response_signature=False, roots=[], **options) == unsigned
