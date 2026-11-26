"""Client setup and the rules around every call: base URL and TLS, credentials, secrets kept out of
everything printable, request building and its limits, the rate limiter."""

import logging
import pickle
import ssl

import httpx
import pytest

from vaultody_sdk import (
    AsyncVaultody,
    AuthenticationError,
    ConfigurationError,
    MemoryVaultKeyStore,
    ParameterError,
    PemSigner,
    RequestOutcomeUnknownError,
    ResponseVerificationError,
    TransportError,
    Vaultody,
)
from vaultody_sdk._core import MAX_REQUEST_BODY_BYTES, RateLimiter, _Credentials

from conftest import make_client, run
from mock_gateway import API_KEY, API_SECRET, CLIENT_KEYS, PASSPHRASE, MockGateway, envelope_error

SECRETS = (API_KEY, API_SECRET, PASSPHRASE)


@pytest.mark.parametrize("base_url,code", [
    ("http://rest.vaultody.com", "insecure_base_url"),
    ("ftp://rest.vaultody.com", "invalid_base_url"),
    ("https://user:pw@rest.vaultody.com", "invalid_base_url"),
    ("https://rest.vaultody.com/?x=1", "invalid_base_url"),
    ("https://rest.vaultody.com/v2/../x", "invalid_base_url"),
    ("https://rest.vaultody.com:99999", "invalid_base_url"),
    ("rest.vaultody.com", "invalid_base_url"),
])
def test_base_url_rules(kind, base_url, code):
    with pytest.raises(ConfigurationError) as raised:
        make_client(kind, None, base_url=base_url)
    assert raised.value.code == code


@pytest.mark.parametrize("base_url,origin", [
    ("https://rest.vaultody.com", "https://rest.vaultody.com"),
    ("https://REST.vaultody.com:8443/v2/", "https://rest.vaultody.com:8443"),
    ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
    ("http://localhost", "http://localhost"),
    ("http://[::1]:9000", "http://[::1]:9000"),
    # The scheme's default port is left out, as a URL's origin (and the other SDKs) write it: one pin
    # file entry for one API, however its address is written.
    ("https://rest.vaultody.com:443", "https://rest.vaultody.com"),
    ("http://127.0.0.1:80/", "http://127.0.0.1"),
    ("https://rest.vaultody.com:80", "https://rest.vaultody.com:80"),
])
def test_plain_http_only_to_this_machine(kind, base_url, origin):
    client = make_client(kind, None, base_url=base_url)
    assert client.origin == origin
    run(kind, client, lambda api: _none())


async def _none():
    return None


def test_tls_checks_can_not_be_switched_off(kind):
    with pytest.raises(ConfigurationError):
        make_client(kind, None, verify=False, transport=None)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ConfigurationError):
        make_client(kind, None, verify=context, transport=None)
    run(kind, make_client(kind, None, verify=ssl.create_default_context(), transport=None), lambda api: _none())


def test_a_transport_of_the_wrong_kind_is_refused():
    with pytest.raises(ConfigurationError):
        make_client("sync", None, transport=httpx.AsyncHTTPTransport())
    with pytest.raises(ConfigurationError):
        make_client("async", None, transport=httpx.HTTPTransport())


@pytest.mark.parametrize("credentials,code", [
    (("", API_SECRET, PASSPHRASE), "invalid_api_key"),
    ((API_KEY, API_SECRET, "line\nbreak"), "invalid_passphrase"),
    ((API_KEY, "not base64!", PASSPHRASE), "invalid_api_secret"),
])
def test_credentials_are_checked_at_once(kind, credentials, code):
    with pytest.raises(ConfigurationError) as raised:
        make_client(kind, None, credentials=credentials)
    assert raised.value.code == code
    for secret in credentials:
        if len(secret) > 4:
            assert secret not in str(raised.value)


@pytest.mark.parametrize("option,value", [
    ("max_requests_per_second", 0), ("max_requests_per_second", True), ("timeout", -1),
    ("response_signature", "sometimes"), ("max_clock_skew_seconds", -5), ("on_security_event", "print"),
    ("store", object()), ("roots", ["not a key"]),
])
def test_bad_options_are_configuration_errors(kind, option, value):
    with pytest.raises(ConfigurationError):
        make_client(kind, None, **{option: value})


XPUB = "xpub-TEST-NOT-A-REAL-KEY"
PIN = {"vaultId": "v1", "type": "main", "keys": {"ECDSA": XPUB, "EDDSA": None}}


@pytest.mark.parametrize("value", [
    "v1",
    {"v1": PIN},
    [PIN, dict(PIN)],
    [dict(PIN, status="verified")],
    [{"vaultId": "v1", "type": "main"}],
    [dict(PIN, vaultId="")],
    [dict(PIN, type="MAIN")],
    [dict(PIN, keys={"ECDSA": XPUB})],
    [dict(PIN, keys={"ECDSA": XPUB, "EDDSA": None, "SCHNORR": None})],
    [dict(PIN, keys={"ECDSA": None, "EDDSA": None})],
    [dict(PIN, keys={"ECDSA": "", "EDDSA": None})],
    [dict(PIN, keys={"ECDSA": 1, "EDDSA": None})],
    ["v1"],
])
def test_bad_pinned_vault_keys_are_refused(kind, value):
    with pytest.raises(ConfigurationError) as raised:
        make_client(kind, None, pinned_vault_keys=value)
    assert raised.value.code == "invalid_pinned_vault_keys"
    assert XPUB not in str(raised.value)


def test_pinned_vault_keys_are_copied(kind, clock):
    entry = {"vaultId": "v1", "type": "main", "keys": {"ECDSA": XPUB, "EDDSA": None}}
    client = make_client(kind, MockGateway(clock), pinned_vault_keys=(entry,))
    entry["keys"]["ECDSA"] = "xpub-CHANGED"
    assert client._core._configured["v1"]["keys"] == {"ECDSA": XPUB, "EDDSA": None}
    assert client._core._configured["v1"]["status"] == "verified"


# -- secrets ------------------------------------------------------------------------------------------


def test_no_secret_in_repr_str_errors_or_logs(kind, clock, caplog):
    caplog.set_level(logging.DEBUG)
    gateway = MockGateway(clock)
    # 401 to the first call; the key-pair check before the write; the write's answer lost; a stripped signature.
    gateway.intervene(("status", 401), None, "read_timeout", "strip")
    events = []
    client = make_client(kind, gateway, signer=PemSigner(CLIENT_KEYS["ed25519"]["privateKeyPkcs8Pem"]), on_security_event=events.append)
    gateway.registered = []
    texts = [repr(client), str(client), repr(client._core), repr(client._core._credentials), repr(vars(client._core))]

    async def scenario(api):
        for call, error_class in (
            (lambda: api.request("GET", "/ping"), AuthenticationError),
            (lambda: api.request("POST", "/vaults/{vaultId}/transaction-requests/single-transfer", path_params={"vaultId": "v"}, item={}), RequestOutcomeUnknownError),
            (lambda: api.request("GET", "/ping"), ResponseVerificationError),
        ):
            with pytest.raises(error_class) as raised:
                await call()
            texts.extend([repr(raised.value), str(raised.value), repr(vars(raised.value))])

    run(kind, client, scenario)
    texts.extend(record.getMessage() for record in caplog.records)
    texts.append(repr(events))
    blob = "\n".join(texts)
    for secret in SECRETS + (CLIENT_KEYS["ed25519"]["privateKeyPkcs8Pem"].split("\n")[1],):
        assert secret not in blob


def test_credentials_can_not_be_pickled():
    with pytest.raises(TypeError):
        pickle.dumps(_Credentials(*SECRETS))


# -- building a request -------------------------------------------------------------------------------


def _send(kind, clock, call):
    gateway = MockGateway(clock)
    client = make_client(kind, gateway)

    async def scenario(api):
        return await call(api)

    return run(kind, client, scenario), gateway


def test_context_goes_in_the_query_of_a_get_and_the_body_of_a_post(kind, clock):
    _, gateway = _send(kind, clock, lambda api: api.request("GET", "/ping", context="order-7"))
    assert gateway.received[0].url.raw_path == b"/ping?context=order-7"
    _, gateway = _send(kind, clock, lambda api: api.request("POST", "/vaults/{vaultId}/transaction-requests/single-transfer", path_params={"vaultId": "v"}, item={"amount": "0.1"}, context="order-7"))
    assert gateway.received[-1].content == b'{"context":"order-7","data":{"item":{"amount":"0.1"}}}'


@pytest.mark.parametrize("arguments,code", [
    (dict(method="DELETE", path="/ping"), "invalid_method"),
    (dict(method="GET", path="ping"), "invalid_path"),
    (dict(method="GET", path="/ping?x=1"), "invalid_path"),
    (dict(method="GET", path="/ping", item={}), "invalid_body"),
    (dict(method="POST", path="/ping", item={"x": float("nan")}), "invalid_body"),
    (dict(method="POST", path="/ping", item={"x": object()}), "invalid_body"),
    (dict(method="POST", path="/ping", item={"x": "a" * MAX_REQUEST_BODY_BYTES}), "request_too_large"),
    (dict(method="GET", path="/vaults/{vaultId}/utxos"), "missing_path_param"),
    (dict(method="GET", path="/ping", query="limit=1"), "invalid_query_param"),
    (dict(method="POST", path="/ping", item={}, retry="sometimes"), "invalid_retry"),
])
def test_a_call_that_cant_be_built_is_refused_before_sending(kind, clock, arguments, code):
    gateway = MockGateway(clock)
    client = make_client(kind, gateway)

    async def scenario(api):
        options = dict(arguments)
        with pytest.raises(ParameterError) as raised:
            await api.request(options.pop("method"), options.pop("path"), **options)
        return raised.value.code

    assert run(kind, client, scenario) == code
    assert gateway.received == []


def test_a_read_only_post_is_retried_like_a_get(kind, clock):
    gateway = MockGateway(clock)
    gateway.route("POST", r"/info/([^/]+)/([^/]+)/addresses/validate", lambda request, match, body: (200, {"data": {"item": {"isValid": True}}}))
    gateway.intervene("read_timeout")
    client = make_client(kind, gateway)

    async def scenario(api):
        return await api.request("POST", "/info/{blockchain}/{network}/addresses/validate", path_params={"blockchain": "bitcoin", "network": "mainnet"}, item={"address": "x"}, retry="read")

    assert run(kind, client, scenario).item == {"isValid": True}
    first, second = gateway.received
    assert first.headers["x-api-nonce"] != second.headers["x-api-nonce"], "re-signed"


def test_redirects_are_not_followed(kind, clock):
    def redirect(request):
        return httpx.Response(302, headers={"location": "https://elsewhere.test/"}, content=b"")

    client = make_client(kind, None, transport=httpx.MockTransport(redirect))

    async def scenario(api):
        with pytest.raises(Exception) as raised:
            await api.request("GET", "/ping")
        return raised.value

    error = run(kind, client, scenario)
    assert getattr(error, "status", None) == 302


def test_a_real_refused_connection_is_a_transport_error(kind):
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    sleeps = []
    client = (Vaultody if kind == "sync" else AsyncVaultody)(*SECRETS, base_url="http://127.0.0.1:{}".format(port), vault_key_store=MemoryVaultKeyStore(), timeout=5)
    client._core.hooks.sleep = sleeps.append

    async def scenario(api):
        with pytest.raises(TransportError) as raised:
            await api.request("GET", "/ping")
        return raised.value

    assert run(kind, client, scenario).sent is False
    assert len(sleeps) == 4


def test_errors_are_typed_on_both_clients(kind, clock):
    gateway = MockGateway(clock)
    gateway.route("GET", r"/ping", lambda request, match, body: (403, envelope_error("wallet_as_a_service_wallet_balance_not_enough")))
    client = make_client(kind, gateway)

    async def scenario(api):
        from vaultody_sdk import PermissionDeniedError

        with pytest.raises(PermissionDeniedError) as raised:
            await api.request("GET", "/ping")
        return raised.value

    error = run(kind, client, scenario)
    assert (error.status, error.code) == (403, "wallet_as_a_service_wallet_balance_not_enough")


# -- the rate limiter ---------------------------------------------------------------------------------


def test_the_limiter_allows_the_rate_in_any_one_second_window():
    limiter = RateLimiter(5)
    waits = [limiter.reserve(0.0) for _ in range(12)]
    assert waits == [0.0] * 5 + [1.0] * 5 + [2.0, 2.0]
    later = RateLimiter(5)
    for at in (0.0, 0.1, 0.2, 0.3, 0.4):
        assert later.reserve(at) == 0.0
    assert later.reserve(0.5) == pytest.approx(0.5)
    assert later.reserve(1.6) == 0.0


def test_a_rate_below_one_spaces_calls_out():
    limiter = RateLimiter(0.5)
    assert limiter.reserve(0.0) == 0.0
    assert limiter.reserve(0.0) == 2.0


def test_no_secret_in_the_effects_the_core_yields(kind, clock):
    gateway = MockGateway(clock, registered_keys=["ed25519"])
    client = make_client(kind, gateway, signer=PemSigner(CLIENT_KEYS["ed25519"]["privateKeyPkcs8Pem"]))
    seen = []
    perform = client._perform

    def recording(effect):
        seen.append(repr(effect))
        return perform(effect)

    async def recording_async(effect):
        seen.append(repr(effect))
        return await perform(effect)

    client._perform = recording_async if kind == "async" else recording
    run(kind, client, lambda api: api.request("POST", "/vaults/{vaultId}/transaction-requests/single-transfer", path_params={"vaultId": "v"}, item={}))
    assert any(text.startswith("Send(POST") for text in seen) and any(text.startswith("Sign(") for text in seen)
    for secret in SECRETS:
        assert secret not in "\n".join(seen)
