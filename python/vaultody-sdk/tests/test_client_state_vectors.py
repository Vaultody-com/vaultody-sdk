"""Vector sets whose requests a client reproduces exactly (the vector credentials, clock and nonce), so the
signed answers are served unchanged to both clients:

- signing-keys-v1.json: check_signing_key(), the confirmation that the key pair is active;
- vault-key-pins-v1.json: GET /vaults/main answers and what they do to the pins; its address checks
  through the address routes.

These sets verify each answer on its own (signed ones must verify, unsigned ones pass): a signed answer goes
to a client with the vector roots, an unsigned one to a client without roots (a release candidate before the
API signs), which accepts it. A client with roots refuses an unsigned answer (response-mode-v1.json).
"""

import base64
import copy

import httpx
import pytest

from vaultody_sdk import AddressVerificationError, MemoryVaultKeyStore, PemSigner, ResponseVerificationError, VaultKeyChangedError
from vaultody_sdk._core import Hooks

from conftest import make_client, run
from mock_gateway import (
    ACCOUNT,
    API_KEY,
    API_SECRET,
    ECDSA_XPUB,
    EDDSA_XPUB,
    ORIGIN,
    PASSPHRASE,
    PINNED_ROOTS,
    VAULT_MAIN,
    VAULT_SMART,
    FakeClock,
    MockGateway,
    address_case,
    address_item,
    envelope_item,
    standard_vaults,
)
from sdk_vectors import ids, load

SIGNING_KEYS = load("signing-keys-v1.json")
PINS = load("vault-key-pins-v1.json")
FULL = load("request-full-v1.json")

TIMESTAMP = "1794201000"
NONCE = "0c9b8a7f6e5d4c3b2a1908f7e6d5c4b3"


def vector_hooks(now):
    clock = FakeClock(now)
    return Hooks(clock=clock, sleep=clock.sleep, random=lambda: 0.5, nonce=lambda: NONCE, timestamp=lambda: TIMESTAMP, api_version="2026-03-20")


def roots_for(response):
    """The vector roots for a signed answer (any of the four x-api-response-* headers), none for an unsigned one."""
    signed = any(name.lower().startswith("x-api-response-") and value for name, value in response["headers"].items())
    return PINNED_ROOTS if signed else None


def serve(step):
    """A transport that checks the request is the vector's, byte for byte, and answers with its response."""
    sent = step["request"]
    received = step["response"]

    def handler(request):
        path, _, query = request.url.raw_path.decode("ascii").partition("?")
        assert (request.method, path, query) == (sent["method"], sent["path"], sent["query"])
        assert request.content == base64.b64decode(sent["bodyBase64"])
        assert request.headers["x-api-sign"] == sent["apiSign"]
        assert request.headers.get("x-api-keypair-sign", "") == sent["keypairSign"]
        return httpx.Response(received["status"], headers=received["headers"], content=base64.b64decode(received["bodyBase64"]))

    return httpx.MockTransport(handler)


# -- signing-keys-v1.json ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", SIGNING_KEYS["cases"], ids=ids(SIGNING_KEYS["cases"]))
def test_check_signing_key(kind, vector):
    signer = PemSigner(FULL["keys"]["ed25519"]["privateKeyPkcs8Pem"])
    assert signer.fingerprint == vector["fingerprint"]
    client = make_client(kind, None, hooks=vector_hooks(vector["now"]), signer=signer, transport=serve(vector), roots=roots_for(vector["response"]))
    expected = vector["expected"]

    async def scenario(api):
        if isinstance(expected["signature"], dict):
            with pytest.raises(ResponseVerificationError) as raised:
                await api.check_signing_key()
            return raised.value
        return await api.check_signing_key()

    result = run(kind, client, scenario)
    if isinstance(expected["signature"], dict):
        assert result.reason == expected["signature"]["error"]
        return
    assert result["signature"] == expected["signature"]
    assert result["outcome"] == expected["outcome"]
    assert result["fingerprint"] == vector["fingerprint"]
    if "code" in expected:
        assert result["code"] == expected["code"]


# -- vault-key-pins-v1.json -------------------------------------------------------------------------


def sorted_pins(store):
    return sorted(store.list(ORIGIN), key=lambda pin: pin["vaultId"])


@pytest.mark.parametrize("vector", PINS["cases"], ids=ids(PINS["cases"]))
def test_pins(kind, vector):
    store = MemoryVaultKeyStore()
    for pin in vector["initialPins"]:
        store.pin_if_absent(ORIGIN, pin)
    for step in vector["steps"]:
        expected = step["expected"]
        # The vectors verify each answer on its own; the strict latch, which the clients keep across answers
        # (a signed answer sets it, verified or not), is tested on its own below.
        store.reset_strict_latch(ORIGIN)
        events = []
        client = make_client(
            kind, None, hooks=vector_hooks(step["now"]), transport=serve(step), store=store, on_security_event=events.append,
            pinned_vault_keys=vector["configuredPins"], roots=roots_for(step["response"]),
        )

        async def scenario(api):
            return await api.request("GET", "/vaults/{networkType}", path_params={"networkType": "main"}, query=[("limit", 50)])

        if isinstance(expected["signature"], dict):
            with pytest.raises(ResponseVerificationError) as raised:
                run(kind, client, scenario)
            assert raised.value.reason == expected["signature"]["error"]
        elif "alarms" in expected:
            with pytest.raises(VaultKeyChangedError) as raised:
                run(kind, client, scenario)
            assert raised.value.alarms == expected["alarms"]
            alarm_events = [event for event in events if event["type"] == "vault_key_changed"]
            assert [event["alarms"] for event in alarm_events] == [expected["alarms"]]
            for xpub in (ECDSA_XPUB, EDDSA_XPUB):
                assert xpub not in str(raised.value) and xpub not in str(events)
        else:
            result = run(kind, client, scenario)
            assert result.meta.signature == expected["signature"]
            pinned = [o["vaultId"] for o in expected["outcomes"] if o["outcome"] == "pinned"]
            upgraded = [o["vaultId"] for o in expected["outcomes"] if o["outcome"] == "upgraded"]
            assert [e["vaultId"] for e in events if e["type"] == "vault_key_pinned"] == pinned
            assert [e["vaultId"] for e in events if e["type"] == "vault_key_verified"] == upgraded
            # The per-vault results: the outcomes of the vector, with each vault's pin status after it (a
            # configured vault: verified).
            status_after = {pin["vaultId"]: pin["status"] for pin in expected["pinsAfter"]}
            status_after.update({pin["vaultId"]: "verified" for pin in vector["configuredPins"]})
            assert list(result.meta.vault_keys) == [
                {"vaultId": o["vaultId"], "status": status_after.get(o["vaultId"], "not_verifiable"), "outcome": o["outcome"]}
                for o in expected["outcomes"]
            ]
        assert sorted_pins(store) == expected["pinsAfter"]


def test_with_the_latch_an_unsigned_vault_list_after_a_signed_one_is_refused(kind):
    """What the latch adds to verified_then_unsigned_same: the clients refuse the second answer."""
    vector = next(case for case in PINS["cases"] if case["name"] == "verified_then_unsigned_same")
    store = MemoryVaultKeyStore()
    for pin in vector["initialPins"]:
        store.pin_if_absent(ORIGIN, pin)
    store.set_strict_latch(ORIGIN, {"latchedAt": 1, "rootId": "TEST"})
    step = vector["steps"][-1]
    assert step["expected"]["signature"] == "absent"
    # A client without roots, which accepts an unsigned answer from an origin that is not latched.
    client = make_client(kind, None, hooks=vector_hooks(step["now"]), transport=serve(step), store=store, roots=None)

    async def scenario(api):
        with pytest.raises(ResponseVerificationError) as raised:
            await api.request("GET", "/vaults/{networkType}", path_params={"networkType": "main"}, query=[("limit", 50)])
        return raised.value

    assert run(kind, client, scenario).reason == "missing"
    assert sorted_pins(store) == step["expected"]["pinsAfter"]


# addressChecks: (pin status, vault has keys, address carries its path, derivation) → status or error. A
# configured pin is given as pinned_vault_keys, with unsigned answers: it counts as verified all the same. A case
# with pathRequired runs through its operation, with require_address_paths as given (absent: off), on bitcoin or,
# for a chain the SDK can't derive, on one it does not know.

UNKNOWN_CHAIN = "TEST-unknown-chain"


def address_scenario(kind, check):
    clock = FakeClock()
    signed = check["pin"] == "verified"
    gateway = MockGateway(clock, sign_responses=signed)
    standard_vaults(gateway)
    store = MemoryVaultKeyStore()
    vault_id = VAULT_MAIN if check["vaultHasKeys"] else VAULT_SMART
    required = check.get("pathRequired") or {"requireAddressPaths": False, "operationId": "listAddressesByVaultAccountId", "chainKnown": True}
    options = {"require_address_paths": required["requireAddressPaths"], "roots": PINNED_ROOTS if signed else None}
    if check["pin"] == "configured":
        options["pinned_vault_keys"] = [{"vaultId": vault_id, "type": "main", "keys": {"ECDSA": ECDSA_XPUB, "EDDSA": EDDSA_XPUB}}]
    elif check["pin"] is not None:
        store.pin_if_absent(ORIGIN, {
            "vaultId": vault_id, "type": "main", "keys": {"ECDSA": ECDSA_XPUB, "EDDSA": EDDSA_XPUB},
            "status": check["pin"], "firstSeenAt": 1, "verifiedAt": 1 if signed else None,
            "verification": {"rootId": "TEST", "timestamp": 1} if signed else None,
        })
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    item = address_item(case, with_path=check["pathFields"])
    if check["derivation"] == "mismatch":
        item["address"] = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/5")["address"]
    blockchain = "bitcoin" if required["chainKnown"] else UNKNOWN_CHAIN
    item["blockchain"] = blockchain
    operation = required["operationId"]
    if operation == "generateDepositAddress":
        gateway.addresses[(vault_id, blockchain, "mainnet")] = [item]
        call = ("POST", "/vaults/{vaultId}/{blockchain}/{network}/addresses", {"vaultId": vault_id, "blockchain": blockchain, "network": "mainnet"}, {"label": "TEST"})
    elif operation == "addAssetToVaultAccount":
        gateway.route("PUT", r"/vaults/([^/]+)/vault-accounts/([^/]+)/add-asset", lambda request, match, body: (200, envelope_item(item)))
        call = ("PUT", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset", {"vaultId": vault_id, "vaultAccountId": ACCOUNT}, {"address": item["address"], "assetId": "TEST"})
    else:
        gateway.addresses[("list", vault_id, ACCOUNT)] = [item]
        call = ("GET", "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses", {"vaultId": vault_id, "vaultAccountId": ACCOUNT}, None)
    client = make_client(kind, gateway, store=store, **options)
    method, path, path_params, body = call

    async def scenario(api):
        if body is None:
            return await api.request(method, path, path_params=path_params)
        return await api.request(method, path, path_params=path_params, item=body)

    return run(kind, client, scenario)


@pytest.mark.parametrize("check", PINS["addressChecks"], ids=ids(PINS["addressChecks"]))
def test_address_checks(kind, check):
    if "error" in check["expected"]:
        with pytest.raises(AddressVerificationError) as raised:
            address_scenario(kind, check)
        assert raised.value.code == check["expected"]["error"]
        return
    result = address_scenario(kind, check)
    assert [entry["status"] for entry in result.meta.address_checks] == [check["expected"]["status"]]
    if check["pin"] == "configured":
        assert result.meta.signature == "absent"
    assert copy.deepcopy(result.item if hasattr(result, "item") else result.items)  # the answer is returned whole
