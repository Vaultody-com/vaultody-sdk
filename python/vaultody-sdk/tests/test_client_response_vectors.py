"""Response signature verification in both clients.

test-vectors/v1.json: the gateway generator made up the x-api-sign of each request (an HMAC over a label),
so no client can send those requests. Each case therefore goes through the client's own verification step
(Core._outcome, driven by that client's effect loop, latch writes included) with the vector's request as
sent. Then every failure reason runs end to end through both clients against the mock gateway, which
signs live with the same TEST-ONLY roots.
"""

import asyncio
import base64
import json

import pytest

from vaultody_sdk import ConfigurationError, MemoryVaultKeyStore, ResponseVerificationError, TransportError
from vaultody_sdk._core import Headers, RawResponse, _Signed, run_async, run_sync

from conftest import make_client, run
from mock_gateway import ORIGIN, PINNED_ROOTS, T0, FakeClock, MockGateway, ResponseSigner, envelope_error
from sdk_vectors import ids, load

VECTORS = load("v1.json")
ROOT_DER = {name: base64.b64decode(root["publicKeySpkiDerBase64"]) for name, root in VECTORS["keys"]["roots"].items()}


def verify_through(kind, vector):
    verify = vector["verify"]
    sent, received = verify["request"], verify["response"]
    client = make_client(
        kind, None, clock=FakeClock(verify["now"]), roots=[ROOT_DER[name] for name in verify["pinnedRoots"]],
        response_signature="required",
    )
    core = client._core
    url = sent["path"] + ("?" + sent["query"] if sent["query"] else "")
    signed = _Signed(headers=(), url_target=url, timestamp="0", nonce="n", api_sign=sent["apiSign"], keypair_sign=sent["keypairSign"], signed_at_ms=0)
    body = base64.b64decode(sent["bodyBase64"])
    raw = RawResponse(received["status"], Headers(received["headers"].items()), base64.b64decode(received["bodyBase64"]))
    generator = core._outcome(sent["method"], signed, body, raw)
    if kind == "sync":
        result = run_sync(generator, client._perform)
        client.close()
    else:
        async def main():
            try:
                return await run_async(generator, client._perform)
            finally:
                await client.aclose()

        result = asyncio.run(main())
    return result


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=ids(VECTORS["cases"]))
def test_v1(kind, vector):
    outcome, exchange, error = verify_through(kind, vector)
    if vector["expected"]["valid"]:
        assert error is None
        assert exchange.signature == "verified"
        assert outcome["type"] == "response"
    else:
        assert exchange is None
        assert outcome == {"type": "verification_failed"}
        assert isinstance(error, ResponseVerificationError)
        assert error.reason == vector["expected"]["reason"]


# -- end to end, live-signed --------------------------------------------------------------------------


def call_ping(kind, gateway, **options):
    events = []
    options.setdefault("on_security_event", events.append)
    client = make_client(kind, gateway, **options)

    async def scenario(api):
        return await api.request("GET", "/ping")

    return run(kind, client, scenario), events


def expect_refusal(kind, gateway, reason, *, latches=False, **options):
    """One GET refused with ``reason``, never retried. ``latches``: the answer carried (part of) a signature to an
    origin not latched yet, so it is latched first, with rootId None, as it did not verify."""
    events = []
    store = options.pop("store", None) or MemoryVaultKeyStore()
    client = make_client(kind, gateway, on_security_event=events.append, store=store, **options)

    async def scenario(api):
        with pytest.raises(ResponseVerificationError) as raised:
            await api.request("GET", "/ping")
        return raised.value

    error = run(kind, client, scenario)
    assert error.reason == reason
    assert [event["type"] for event in events] == (["response_signature_latched"] if latches else []) + ["response_verification_failed"]
    assert events[-1]["reason"] == reason
    if latches:
        assert events[0]["rootId"] is None and store.get_strict_latch(ORIGIN) == {"latchedAt": events[0]["latchedAt"], "rootId": None}
    assert len(gateway.received) == 1, "a verification failure is never retried"
    return error


def test_a_signed_answer_verifies_and_latches(kind, gateway):
    store = MemoryVaultKeyStore()
    result, events = call_ping(kind, gateway, store=store)
    assert result.meta.signature == "verified"
    assert result.meta.signature_root_id == VECTORS["keys"]["roots"]["current"]["rootId"]
    assert store.get_strict_latch(ORIGIN)["rootId"] == result.meta.signature_root_id
    assert [event["type"] for event in events] == ["response_signature_latched"]


def test_an_unsigned_answer_passes_until_the_origin_signed_once(kind, clock):
    gateway = MockGateway(clock, sign_responses=False)
    # A client without roots (a release candidate): a client with roots refuses it from the first answer.
    result, events = call_ping(kind, gateway, roots=None)
    assert result.meta.signature == "absent"
    # Outside the API methods there is no operation id.
    assert events == [{"type": "unsigned_response_accepted", "origin": ORIGIN, "operationId": None}]


def test_an_accepted_unsigned_answer_is_reported_once_per_client(kind, clock, caplog):
    """The event, then one warning, for the first unsigned answer each client accepts; never again."""
    def make(events):
        # A gateway each: the clients' test nonces repeat, which a shared one would take for a replay.
        return make_client(kind, MockGateway(clock, sign_responses=False), on_security_event=events.append, roots=None)

    async def scenario(api):
        for _ in range(3):
            await api.request("GET", "/ping")
        await api.collect(api.client.vaults.list_vaults(networkType="main"))

    first, second = [], []
    with caplog.at_level("WARNING", logger="vaultody_sdk"):
        run(kind, make(first), scenario)
        run(kind, make(second), lambda api: api.collect(api.client.vaults.list_vaults(networkType="test")))
    assert first == [{"type": "unsigned_response_accepted", "origin": ORIGIN, "operationId": None}]
    assert second == [{"type": "unsigned_response_accepted", "origin": ORIGIN, "operationId": "listVaults"}]
    warnings = [record.getMessage() for record in caplog.records if "are not signed" in record.getMessage()]
    assert len(warnings) == 2, warnings
    assert warnings[0].startswith("Vaultody API responses from {} are not signed".format(ORIGIN))


def test_a_signed_answer_raises_no_unsigned_notice(kind, gateway, caplog):
    with caplog.at_level("WARNING", logger="vaultody_sdk"):
        result, events = call_ping(kind, gateway)
    assert result.meta.signature == "verified"
    assert "unsigned_response_accepted" not in [event["type"] for event in events]
    assert not [record for record in caplog.records if "are not signed" in record.getMessage()]


def test_after_the_latch_an_unsigned_answer_is_refused_even_after_a_restart(kind, clock):
    store = MemoryVaultKeyStore()
    call_ping(kind, MockGateway(clock), store=store)
    # A new client on the same store (a restart): the stripped signature is caught.
    gateway = MockGateway(clock)
    gateway.intervene("strip")
    expect_refusal(kind, gateway, "missing", store=store)


def test_required_refuses_an_unsigned_answer_from_the_first_call(kind, clock):
    gateway = MockGateway(clock, sign_responses=False)
    expect_refusal(kind, gateway, "missing", response_signature="required", roots=None)


def test_roots_refuse_an_unsigned_answer_from_the_first_call(kind, clock):
    expect_refusal(kind, MockGateway(clock, sign_responses=False), "missing")


def test_the_mode_can_come_from_the_environment(kind, clock, monkeypatch):
    monkeypatch.setenv("VAULTODY_RESPONSE_SIGNATURE", "required")
    expect_refusal(kind, MockGateway(clock, sign_responses=False), "missing", roots=None)
    monkeypatch.setenv("VAULTODY_RESPONSE_SIGNATURE", "off")
    with pytest.raises(ConfigurationError):
        make_client(kind, MockGateway(clock))


def test_a_partly_stripped_signature_is_refused_and_latches(kind, gateway):
    gateway.intervene(("strip_one", "x-api-response-cert"))
    expect_refusal(kind, gateway, "missing", latches=True)


def test_a_partly_stripped_signature_latches_a_client_without_roots(kind, gateway):
    gateway.intervene(("strip_one", "x-api-response-sign"))
    expect_refusal(kind, gateway, "missing", latches=True, roots=None)


def test_a_tampered_body_is_refused(kind, gateway):
    gateway.intervene(("tamper", lambda body: body.replace(b"true", b"false")))
    expect_refusal(kind, gateway, "invalid", latches=True)


def test_a_tampered_error_answer_is_refused_and_not_retried(kind, gateway):
    """A forged 429 or 5xx could steer retries: error answers are verified too, and a 503 that fails its
    check is not retried."""
    gateway.route("GET", r"/ping", lambda request, match, body: (503, envelope_error("unexpected_server_error")))
    gateway.intervene(("tamper", lambda body: body.replace(b"unexpected_server_error", b"request_limit_reached")))
    expect_refusal(kind, gateway, "invalid", latches=True)


def test_an_expired_certificate_is_refused(kind, clock):
    gateway = MockGateway(clock, signer=ResponseSigner(not_before=T0 - 7200, not_after=T0 - 3600))
    expect_refusal(kind, gateway, "expired", latches=True)


def test_an_unpinned_root_is_refused(kind, clock):
    expect_refusal(kind, MockGateway(clock, signer=ResponseSigner(root="unpinned")), "unknown_root", latches=True)


def test_a_response_not_bound_to_the_body_is_refused(kind, clock):
    class Unread(ResponseSigner):
        # The signed read before the write is bound; the write's answer is not.
        def headers(self, request, request_body, status, body, ts, unread=False):
            return super().headers(request, request_body, status, body, ts, unread=request.method == "POST")

    gateway = MockGateway(clock, signer=Unread())
    events = []
    client = make_client(kind, gateway, on_security_event=events.append)

    async def scenario(api):
        with pytest.raises(ResponseVerificationError) as raised:
            await api.request("POST", "/vaults/{vaultId}/transaction-requests/single-transfer", path_params={"vaultId": "v1"}, item={"amount": "1"})
        return raised.value

    assert run(kind, client, scenario).reason == "request_unbound"
    assert [request.method for request in gateway.received] == ["GET", "POST"]


def test_an_unknown_signature_version_is_refused(kind, clock):
    class Version2(ResponseSigner):
        def headers(self, *args, **kwargs):
            headers = super().headers(*args, **kwargs)
            headers["x-api-response-sign-version"] = "2"
            return headers

    expect_refusal(kind, MockGateway(clock, signer=Version2()), "unsupported_version", latches=True)


def test_a_signed_answer_without_any_root_fails_closed(kind, gateway):
    client = make_client(kind, gateway, roots=None)

    async def scenario(api):
        with pytest.raises(ConfigurationError) as raised:
            await api.request("GET", "/ping")
        return raised.value

    assert run(kind, client, scenario).code == "no_roots"


def test_an_unsigned_answer_needs_no_root(kind, clock):
    gateway = MockGateway(clock, sign_responses=False)
    result, _ = call_ping(kind, gateway, roots=None)
    assert result.meta.signature == "absent"


def test_a_hook_that_raises_does_not_hide_the_error(kind, gateway):
    gateway.intervene("strip")

    def broken(event):
        raise RuntimeError("TEST hook failure")

    client = make_client(kind, gateway, on_security_event=broken, response_signature="required")

    async def scenario(api):
        with pytest.raises(ResponseVerificationError):
            await api.request("GET", "/ping")

    run(kind, client, scenario)


def test_an_oversized_answer_is_not_read(kind, clock):
    def huge(request, match, body):
        return 200, b'{"data":{"item":{"blob":"' + b"x" * (10 * 1024 * 1024) + b'"}}}'

    gateway = MockGateway(clock, sign_responses=False)
    gateway.route("GET", r"/huge", huge)
    gateway.route("POST", r"/huge", huge)
    client = make_client(kind, gateway, roots=None)

    async def scenario(api):
        with pytest.raises(TransportError) as raised:
            await api.request("GET", "/huge")
        assert raised.value.sent == "unknown"
        from vaultody_sdk import RequestOutcomeUnknownError

        with pytest.raises(RequestOutcomeUnknownError):
            await api.request("POST", "/huge", item={})

    run(kind, client, scenario)
    assert len(gateway.received) == 2, "neither is retried"


def test_the_latch_survives_in_a_file_store(kind, clock, tmp_path):
    from vaultody_sdk import FileVaultKeyStore

    path = tmp_path / "keys" / "vault-keys.json"
    call_ping(kind, MockGateway(clock), store=FileVaultKeyStore(path))
    latch = json.loads(path.read_text())["origins"][ORIGIN]["responseSignature"]
    assert set(latch) == {"latchedAt", "rootId"} and latch["rootId"] and isinstance(latch["latchedAt"], int)
    gateway = MockGateway(clock)
    gateway.intervene("strip")
    expect_refusal(kind, gateway, "missing", store=FileVaultKeyStore(path))
    assert PINNED_ROOTS
