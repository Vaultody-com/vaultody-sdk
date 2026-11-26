"""test-vectors/response-mode-v1.json: the response-signature mode in force and the latch, then the same rules end
to end against the mock gateway.

- ``config``: response_signature_config, and real clients (Vaultody and AsyncVaultody) built from the case: the
  roots option and the embedded roots are the TEST roots of v1.json (the embedded ones through the unsupported test
  hooks, as is the version);
- ``answers``: the client's own verification step (Core._outcome, after the latch is read from the store, driven by
  run_sync and run_async) on the v1.json case the answer names, with what it leaves in a memory store and the
  security events it raises, in order;
- against the mock gateway: a release candidate that meets a signing origin, a client with roots that meets an
  origin that does not sign, and the signed read before the first write.
"""

import asyncio
import base64
import logging
import re

import pytest

from vaultody_sdk import (
    ConfigurationError,
    MemoryVaultKeyStore,
    PemSigner,
    ResponseVerificationError,
    TransportError,
)
from vaultody_sdk._core import (
    WHEN_PRESENT_IGNORED,
    Core,
    Headers,
    Hooks,
    RawResponse,
    StoreOp,
    _Signed,
    carries_signature,
    response_signature_config,
    run_async,
    run_sync,
)
from vaultody_sdk._defaults import DEFAULT_RESPONSE_SIGNATURE

from conftest import make_client, run
from mock_gateway import API_KEY, API_SECRET, CLIENT_KEYS, ORIGIN, PASSPHRASE, PINNED_ROOTS, FakeClock, MockGateway, Nonces
from sdk_vectors import ids, load

MODES = load("response-mode-v1.json")
RESPONSES = load("v1.json")
ROOT_DER = {name: base64.b64decode(root["publicKeySpkiDerBase64"]) for name, root in RESPONSES["keys"]["roots"].items()}
TEST_ROOTS = [ROOT_DER["current"], ROOT_DER["next"]]
RELEASE_CANDIDATE = "0.9.0rc1"
SIGNED_READ_PATH = "/api-keys/current/signing-keys"
TRANSFER = "/vaults/{vaultId}/transaction-requests/single-transfer"


def pep440(version):
    """The PEP 440 form of a version: 0.9.0-rc.1 → 0.9.0rc1."""
    return re.sub(r"-rc\.([0-9]+)$", r"rc\1", version)


def warnings_of(caplog):
    return [record for record in caplog.records if record.getMessage() == WHEN_PRESENT_IGNORED]


# -- config -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", MODES["config"], ids=ids(MODES["config"]))
def test_config(case):
    result = response_signature_config(
        case["option"], roots_option=case["rootsOption"], embedded_roots=case["embeddedRoots"], version=pep440(case["version"]),
        build_default=case["buildDefault"],
    )
    assert result == (case["expected"]["mode"], case["expected"]["warning"])


def test_the_versions_are_converted():
    assert [pep440(version) for version in ("0.9.0-rc.1", "1.0.0-rc.12", "1.0.0")] == ["0.9.0rc1", "1.0.0rc12", "1.0.0"]


# A real client always takes its build's default, so a case with another one is for the function alone.
CLIENT_CONFIG = [case for case in MODES["config"] if case["buildDefault"] == DEFAULT_RESPONSE_SIGNATURE]


@pytest.mark.parametrize("case", CLIENT_CONFIG, ids=ids(CLIENT_CONFIG))
def test_config_through_the_clients(kind, case, caplog, monkeypatch):
    monkeypatch.delenv("VAULTODY_RESPONSE_SIGNATURE", raising=False)
    hooks = Hooks(clock=FakeClock(), embedded_roots=TEST_ROOTS if case["embeddedRoots"] else (), sdk_version=pep440(case["version"]))
    with caplog.at_level(logging.WARNING, logger="vaultody_sdk"):
        client = make_client(kind, None, hooks=hooks, roots=TEST_ROOTS if case["rootsOption"] else None, response_signature=case["option"])
    assert client.response_signature == case["expected"]["mode"]
    assert "response_signature={}".format(case["expected"]["mode"]) in repr(client)
    assert client.strict is (case["expected"]["mode"] == "required")
    assert len(warnings_of(caplog)) == (1 if case["expected"]["warning"] else 0)
    run(kind, client, lambda api: asyncio.sleep(0))


def test_when_present_from_the_environment_is_ignored_with_roots_too(kind, caplog, monkeypatch):
    monkeypatch.setenv("VAULTODY_RESPONSE_SIGNATURE", "when-present")
    with caplog.at_level(logging.WARNING, logger="vaultody_sdk"):
        client = make_client(kind, None)
    assert client.response_signature == "required" and len(warnings_of(caplog)) == 1
    run(kind, client, lambda api: asyncio.sleep(0))
    # Empty is not set: with no roots at all, the build default, and nothing to warn about.
    monkeypatch.setenv("VAULTODY_RESPONSE_SIGNATURE", "")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="vaultody_sdk"):
        client = make_client(kind, None, roots=None, hooks=Hooks(clock=FakeClock(), embedded_roots=()))
    assert client.response_signature == DEFAULT_RESPONSE_SIGNATURE and warnings_of(caplog) == []
    run(kind, client, lambda api: asyncio.sleep(0))


# -- answers ------------------------------------------------------------------------------------------


def answer_case(name):
    wanted = "missing_all" if name == "unsigned" else name
    return next(case for case in RESPONSES["cases"] if case["name"] == wanted)


def core_for(case, verify, store, events):
    """A client's core as the case describes it (mode, roots), with the case's clock."""
    roots = [ROOT_DER[name] for name in verify["pinnedRoots"]]
    options = {}
    if case["mode"] == "required" and case["roots"]:
        options["roots"] = roots
        embedded = ()
    elif case["roots"]:
        # A release candidate that embeds the roots: when-present, and they check a signature.
        embedded = roots
    else:
        embedded = ()
    if not (case["mode"] == "required" and case["roots"]):
        options["response_signature"] = case["mode"]
    hooks = Hooks(clock=lambda: verify["now"], embedded_roots=embedded, sdk_version=RELEASE_CANDIDATE)
    core = Core(API_KEY, API_SECRET, PASSPHRASE, base_url=ORIGIN, vault_key_store=store, on_security_event=events.append, hooks=hooks, **options)
    assert core.response_signature == case["mode"]
    return core


def verification(core, verify):
    """What the client does with one answer: the latch read from the store, then Core._outcome."""
    sent, received = verify["request"], verify["response"]
    url = sent["path"] + ("?" + sent["query"] if sent["query"] else "")
    signed = _Signed(headers=(), url_target=url, timestamp="0", nonce="n", api_sign=sent["apiSign"], keypair_sign=sent["keypairSign"], signed_at_ms=0)
    raw = RawResponse(received["status"], Headers(received["headers"].items()), base64.b64decode(received["bodyBase64"]))
    yield from core._load_latch()
    return (yield from core._outcome(sent["method"], signed, base64.b64decode(sent["bodyBase64"]), raw))


def drive(how, generator, store):
    def perform(effect):
        assert isinstance(effect, StoreOp), effect
        return getattr(store, effect.name)(*effect.args)

    async def perform_async(effect):
        return perform(effect)

    if how == "run_sync":
        return run_sync(generator, perform)
    return asyncio.run(run_async(generator, perform_async))


@pytest.mark.parametrize("how", ["run_sync", "run_async"])
@pytest.mark.parametrize("case", MODES["answers"], ids=ids(MODES["answers"]))
def test_answers(case, how):
    verify = answer_case(case["answer"])["verify"]
    store, events = MemoryVaultKeyStore(), []
    if case["latchedBefore"]:
        store.set_strict_latch(ORIGIN, dict(MODES["previousLatch"]))
    core = core_for(case, verify, store, events)
    expected = case["expected"]
    try:
        outcome, exchange, error = drive(how, verification(core, verify), store)
    except ConfigurationError as raised:
        assert expected["result"] == {"configurationError": True}
        assert raised.code == "no_roots"
    else:
        if isinstance(expected["result"], dict):
            assert exchange is None and isinstance(error, ResponseVerificationError)
            assert {"error": error.reason} == expected["result"]
        else:
            assert error is None and exchange.signature == expected["result"]
    assert store.get_strict_latch(ORIGIN) == expected["latch"]
    assert [event["type"] for event in events] == expected["events"]
    latched = [event for event in events if event["type"] == "response_signature_latched"]
    if latched:
        # The latch as stored, rootId None when the answer did not verify.
        assert {"latchedAt": latched[0]["latchedAt"], "rootId": latched[0]["rootId"]} == expected["latch"]


def test_a_signature_is_any_of_the_four_headers_with_a_value():
    assert not carries_signature(Headers([("content-type", "application/json")]))
    assert not carries_signature(Headers([("x-api-response-sign", ""), ("x-api-response-cert", "")]))
    assert carries_signature(Headers([("X-Api-Response-Timestamp", "1794201000")]))
    assert carries_signature(Headers([("x-api-response-sign", ""), ("x-api-response-sign", "c2ln")]))
    assert carries_signature({"X-API-RESPONSE-SIGN-VERSION": "1"})
    assert not carries_signature(None)


# -- against the mock gateway ---------------------------------------------------------------------------


def shared_hooks(clock):
    """One nonce sequence for every client of a test: the gateway would take a repeated nonce for a replay."""
    return Hooks(clock=clock, sleep=clock.sleep, random=lambda: 0.5, nonce=Nonces())


def expect(error_class):
    async def raises(call):
        with pytest.raises(error_class) as raised:
            await call
        return raised.value

    return raises


def transfer(api):
    return api.request("POST", TRANSFER, path_params={"vaultId": "v1"}, item={"amount": "0.1"})


def paths(gateway):
    return [request.url.path for request in gateway.received]


def test_a_release_candidate_turns_strict_on_the_first_signed_answer_it_can_not_check(kind, clock):
    gateway = MockGateway(clock)
    store, events, hooks = MemoryVaultKeyStore(), [], shared_hooks(clock)
    client = make_client(kind, gateway, store=store, hooks=hooks, on_security_event=events.append, roots=None)

    async def scenario(api):
        no_roots = await expect(ConfigurationError)(api.request("GET", "/ping"))
        latch = store.get_strict_latch(ORIGIN)
        gateway.intervene("strip")
        stripped = await expect(ResponseVerificationError)(api.request("GET", "/ping"))
        return no_roots, latch, stripped

    no_roots, latch, stripped = run(kind, client, scenario)
    assert no_roots.code == "no_roots"
    assert latch == {"latchedAt": int(clock()), "rootId": None}
    assert stripped.reason == "missing"
    assert [event["type"] for event in events] == ["response_signature_latched", "response_verification_failed"]
    assert events[0]["rootId"] is None

    # A new client on the same store, the origin unsigned: strict from its first call.
    gateway.sign_responses = False
    received = len(gateway.received)
    again = make_client(kind, gateway, store=store, hooks=hooks, roots=None)
    assert run(kind, again, lambda api: expect(ResponseVerificationError)(api.request("GET", "/ping"))).reason == "missing"
    assert len(gateway.received) == received + 1
    assert store.get_strict_latch(ORIGIN) == latch, "never latched again"


def test_with_roots_an_origin_that_does_not_sign_is_refused_and_no_write_is_sent(kind, clock):
    gateway = MockGateway(clock, sign_responses=False)
    events = []
    client = make_client(kind, gateway, on_security_event=events.append)

    async def scenario(api):
        read = await expect(ResponseVerificationError)(api.request("GET", "/ping"))
        sent_for_the_read = len(gateway.received)
        write = await expect(ResponseVerificationError)(transfer(api))
        return read, sent_for_the_read, write

    read, sent_for_the_read, write = run(kind, client, scenario)
    assert read.reason == "missing" and sent_for_the_read == 1, "refused, never retried"
    assert write.reason == "missing"
    assert paths(gateway) == ["/ping", SIGNED_READ_PATH], "the signed read is refused before the write is sent"
    assert gateway.transfers == []
    assert [event["type"] for event in events] == ["response_verification_failed"] * 2


def test_with_roots_and_a_signer_the_key_pair_check_is_the_signed_read(kind, clock):
    gateway = MockGateway(clock, sign_responses=False, registered_keys=["ed25519"])
    client = make_client(kind, gateway, signer=PemSigner(CLIENT_KEYS["ed25519"]["privateKeyPkcs8Pem"]))
    assert run(kind, client, lambda api: expect(ResponseVerificationError)(transfer(api))).reason == "missing"
    assert paths(gateway) == [SIGNED_READ_PATH] and gateway.transfers == []


@pytest.mark.parametrize("signer", [False, True])
def test_one_signed_read_before_the_first_write_and_none_after(kind, clock, signer):
    gateway = MockGateway(clock, registered_keys=["ed25519"] if signer else ())
    store = MemoryVaultKeyStore()
    options = {"signer": PemSigner(CLIENT_KEYS["ed25519"]["privateKeyPkcs8Pem"])} if signer else {}
    client = make_client(kind, gateway, store=store, **options)

    async def scenario(api):
        await transfer(api)
        await transfer(api)

    run(kind, client, scenario)
    assert paths(gateway) == [SIGNED_READ_PATH, "/vaults/v1/transaction-requests/single-transfer", "/vaults/v1/transaction-requests/single-transfer"]
    assert store.get_strict_latch(ORIGIN)["rootId"] == RESPONSES["keys"]["roots"]["current"]["rootId"]


def test_no_signed_read_when_the_store_holds_the_latch(kind, clock):
    gateway = MockGateway(clock)
    store, events = MemoryVaultKeyStore(), []
    store.set_strict_latch(ORIGIN, dict(MODES["previousLatch"]))
    run(kind, make_client(kind, gateway, store=store, on_security_event=events.append), transfer)
    assert paths(gateway) == ["/vaults/v1/transaction-requests/single-transfer"]
    assert events == [], "a strict client reads the latch too, and never latches again"
    assert store.get_strict_latch(ORIGIN) == MODES["previousLatch"]


def test_a_signed_read_lost_on_the_network_lets_the_write_go_ahead(kind, clock):
    gateway = MockGateway(clock)
    gateway.intervene(*["connect_error"] * 5)  # every attempt of the read
    result = run(kind, make_client(kind, gateway), transfer)
    assert result.meta.signature == "verified"
    assert paths(gateway) == [SIGNED_READ_PATH] * 5 + ["/vaults/v1/transaction-requests/single-transfer"]


def test_with_a_signer_the_key_pair_check_is_made_again_until_the_origin_is_latched(kind, clock):
    gateway = MockGateway(clock, registered_keys=["ed25519"])
    gateway.intervene(*["connect_error"] * 10)  # every attempt of the key-pair check, then of the write
    client = make_client(kind, gateway, signer=PemSigner(CLIENT_KEYS["ed25519"]["privateKeyPkcs8Pem"]))

    async def scenario(api):
        await expect(TransportError)(transfer(api))
        await transfer(api)

    run(kind, client, scenario)
    write = "/vaults/v1/transaction-requests/single-transfer"
    assert paths(gateway) == [SIGNED_READ_PATH] * 5 + [write] * 5 + [SIGNED_READ_PATH, write]


def test_no_signed_read_without_roots_or_for_a_read(kind, clock):
    gateway = MockGateway(clock)
    run(kind, make_client(kind, gateway), lambda api: api.request("GET", "/ping"))
    assert paths(gateway) == ["/ping"]
    gateway = MockGateway(clock, sign_responses=False)
    run(kind, make_client(kind, gateway, roots=None, hooks=shared_hooks(clock)), transfer)
    assert paths(gateway) == ["/vaults/v1/transaction-requests/single-transfer"]


def test_the_mock_gateway_signs_with_the_roots_the_clients_pin():
    assert PINNED_ROOTS == TEST_ROOTS
