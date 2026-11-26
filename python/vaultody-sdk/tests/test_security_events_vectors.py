"""test-vectors/security-events-v1.json: the security events' names and fields, and the entries of the
per-answer results, the same in every language. The client builds every event from its catalogue, which is
the vector's; one run through both clients raises the common events and returns both kinds of results, all
with exactly the vector's fields."""

import json

import pytest

from vaultody_sdk import SECURITY_EVENTS, AddressVerificationError, MemoryVaultKeyStore
from vaultody_sdk._core import Hooks
from vaultody_sdk.security_events import security_event

from conftest import make_client, run
from mock_gateway import ORIGIN, VAULT_MAIN, MockGateway, Nonces, address_case, address_item, standard_vaults
from sdk_vectors import load

VECTORS = load("security-events-v1.json")
DEPOSIT = "/vaults/{vaultId}/{blockchain}/{network}/addresses"


def test_the_catalogue_is_the_vectors():
    assert sorted(SECURITY_EVENTS) == sorted(event["type"] for event in VECTORS["events"])
    for event in VECTORS["events"]:
        assert list(SECURITY_EVENTS[event["type"]]) == event["fields"], event["type"]


@pytest.mark.parametrize("event", VECTORS["events"], ids=[event["type"] for event in VECTORS["events"]])
def test_an_event_has_exactly_its_fields(event):
    built = security_event({"type": event["type"], "origin": ORIGIN})
    assert list(built) == event["fields"]
    assert built["type"] == event["type"] and built["origin"] == ORIGIN
    assert all(built[name] is None for name in event["fields"] if name not in ("type", "origin"))
    with pytest.raises(TypeError):
        security_event({"type": event["type"], "origin": ORIGIN, "extra": "x"})


def test_a_type_not_catalogued_is_refused():
    for name in ("vault_key_upgraded", "address_mismatch", "signing_key_confirmation"):
        with pytest.raises(TypeError):
            security_event({"type": name})


def test_through_the_pipeline_events_and_results_have_exactly_the_vectors_fields(kind, clock):
    genuine = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    other = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/5")
    gateway = MockGateway(clock, sign_responses=False)
    standard_vaults(gateway)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(genuine), address_item(genuine)]  # one per deposit
    events, store = [], MemoryVaultKeyStore()
    # One nonce sequence for both clients: the gateway would take a repeated nonce for a replay.
    hooks = Hooks(clock=clock, sleep=clock.sleep, random=lambda: 0.5, nonce=Nonces())
    deposit = {"path_params": {"vaultId": VAULT_MAIN, "blockchain": "bitcoin", "network": "mainnet"}, "item": {"label": "TEST"}}

    # Unsigned, to a release candidate (no roots): accepted (unsigned_response_accepted), the vault pinned unverified
    # (vault_key_pinned).
    release_candidate = make_client(kind, gateway, store=store, hooks=hooks, on_security_event=events.append, roots=None)
    first = run(kind, release_candidate, lambda api: api.request("POST", DEPOSIT, **deposit))

    async def scenario(api):
        # Signed, to a client with roots on the same store: the latch (response_signature_latched), the pin confirmed
        # (vault_key_verified).
        await api.request("POST", DEPOSIT, **deposit)
        page = await api.request("GET", "/vaults/{networkType}", path_params={"networkType": "main"})
        # A swapped address: address_verification_failed.
        gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [dict(address_item(genuine), address=other["address"])]
        with pytest.raises(AddressVerificationError):
            await api.request("POST", DEPOSIT, **deposit)
        return page

    gateway.sign_responses = True
    page = run(kind, make_client(kind, gateway, store=store, hooks=hooks, on_security_event=events.append), scenario)
    fields = {event["type"]: event["fields"] for event in VECTORS["events"]}
    seen = {event["type"] for event in events}
    for name in ("unsigned_response_accepted", "vault_key_pinned", "response_signature_latched", "vault_key_verified", "address_verification_failed"):
        assert name in seen, "no {}".format(name)
    for event in events:
        assert sorted(event) == sorted(fields[event["type"]]), event["type"]
    failed = next(event for event in events if event["type"] == "address_verification_failed")
    assert failed == {"type": "address_verification_failed", "origin": ORIGIN, "operationId": "generateDepositAddress", "vaultId": VAULT_MAIN, "code": "mismatch"}
    for check in first.meta.address_checks:
        assert list(check) == VECTORS["addressCheck"]["fields"] and check["status"] in VECTORS["addressCheck"]["status"]
    assert page.meta.vault_keys
    for result in page.meta.vault_keys:
        assert list(result) == VECTORS["vaultKeyResult"]["fields"]
        assert result["status"] in VECTORS["vaultKeyResult"]["status"] and result["outcome"] in VECTORS["vaultKeyResult"]["outcome"]


def _deposit_with(kind, clock, extra, **client_options):
    """One deposit address of the main vault, its answer item changed by ``extra``; returns (result or error, events)."""
    genuine = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = MockGateway(clock)
    standard_vaults(gateway)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [dict(address_item(genuine, with_network=True), **extra)]
    events = []
    client_options.setdefault("on_security_event", events.append)
    client = make_client(kind, gateway, store=MemoryVaultKeyStore(), **client_options)

    async def scenario(api):
        try:
            return await api.request(
                "POST", DEPOSIT, path_params={"vaultId": VAULT_MAIN, "blockchain": "bitcoin", "network": "mainnet"}, item={"label": "TEST"}
            )
        except AddressVerificationError as error:
            return error

    return run(kind, client, scenario), events


@pytest.mark.parametrize("extra, code", [({"network": "testnet"}, "network_mismatch"), ({"blockchain": "litecoin"}, "mismatch"), ({}, None)])
def test_address_codes_another_network_is_network_mismatch_another_chain_mismatch(kind, clock, extra, code):
    codes = [entry["code"] for entry in VECTORS["addressCodes"]]
    outcome, events = _deposit_with(kind, clock, extra)
    if code is None:
        assert [check["status"] for check in outcome.meta.address_checks] == ["verified"]
        return
    assert isinstance(outcome, AddressVerificationError) and outcome.code == code and code in codes
    assert next(event for event in events if event["type"] == "address_verification_failed")["code"] == code


def test_logging_with_no_hook_every_event_once_as_a_warning(kind, clock, caplog):
    with caplog.at_level("INFO", logger="vaultody_sdk"):
        _deposit_with(kind, clock, {}, on_security_event=None)
    lines = [record for record in caplog.records if record.getMessage().startswith("Vaultody security event: ")]
    logged = [json.loads(record.getMessage()[len("Vaultody security event: "):]) for record in lines]
    assert {record.levelname for record in lines} == {"WARNING"}
    assert [event["type"] for event in logged] == ["response_signature_latched", "vault_key_pinned"]
    assert list(logged[1]) == list(SECURITY_EVENTS["vault_key_pinned"])
    assert not [record for record in caplog.records if record.levelname == "INFO"], "nothing else is logged per event"


def test_logging_with_a_hook_nothing_and_a_raising_hook_once_per_event(kind, clock, caplog):
    with caplog.at_level("INFO", logger="vaultody_sdk"):
        _deposit_with(kind, clock, {})
    assert not [record for record in caplog.records if record.getMessage().startswith("Vaultody security event: ")]
    caplog.clear()

    def broken(event):
        raise RuntimeError("hook down")

    with caplog.at_level("INFO", logger="vaultody_sdk"):
        _deposit_with(kind, clock, {}, on_security_event=broken)
    raised = [record for record in caplog.records if record.getMessage().startswith("the security event hook raised on ")]
    assert len(raised) == 2 and {record.levelname for record in raised} == {"WARNING"}


def test_store_conflict_a_pin_removed_between_the_read_and_the_write(kind, clock):
    from vaultody_sdk import VaultKeyStoreError

    inner = MemoryVaultKeyStore()

    class Vanishing:
        def get(self, origin, vault_id):
            return inner.get(origin, vault_id)

        def list(self, origin):
            return inner.list(origin)

        def pin_if_absent(self, origin, pin):
            return None

        def upgrade_trust(self, origin, vault_id, expected, upgraded):
            return None

        def get_strict_latch(self, origin):
            return inner.get_strict_latch(origin)

        def set_strict_latch(self, origin, latch):
            return inner.set_strict_latch(origin, latch)

    gateway = MockGateway(clock)
    standard_vaults(gateway)
    client = make_client(kind, gateway, store=Vanishing())

    async def scenario(api):
        with pytest.raises(VaultKeyStoreError) as raised:
            await api.request("GET", "/vaults/{networkType}", path_params={"networkType": "main"})
        return raised.value

    assert run(kind, client, scenario).code == "store_conflict"
