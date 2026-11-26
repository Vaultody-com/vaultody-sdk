"""Vault xpub pins and address checks in both clients, against the mock gateway with the xpubs and
addresses of test-vectors/address-v1.json."""

import pytest

from vaultody_sdk import AddressVerificationError, ConfigurationError, FileVaultKeyStore, MemoryVaultKeyStore, VaultKeyChangedError
from vaultody_sdk._defaults import ADDRESS_PATHS_PUBLIC

from conftest import make_client, run
from mock_gateway import (
    ACCOUNT,
    ECDSA_XPUB,
    EDDSA_XPUB,
    ORIGIN,
    OTHER_ECDSA_XPUB,
    PINNED_ROOTS,
    VAULT_MAIN,
    VAULT_SMART,
    VAULT_TEST,
    MockGateway,
    address_case,
    address_item,
    standard_vaults,
    vault_item,
)

DEPOSIT = "/vaults/{vaultId}/{blockchain}/{network}/addresses"
LIST = "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses"
ADD_ASSET = "/vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset"


def deposit(vault_id, blockchain, network):
    def call(api):
        return api.request("POST", DEPOSIT, path_params={"vaultId": vault_id, "blockchain": blockchain, "network": network}, item={"label": "TEST"})

    return call


def list_addresses(vault_id):
    def call(api):
        return api.request("GET", LIST, path_params={"vaultId": vault_id, "vaultAccountId": ACCOUNT})

    return call


def pin(vault_id, status, keys=None, vault_type="main"):
    return {
        "vaultId": vault_id, "type": vault_type, "keys": keys or {"ECDSA": ECDSA_XPUB, "EDDSA": EDDSA_XPUB},
        "status": status, "firstSeenAt": 1, "verifiedAt": 1 if status == "verified" else None,
        "verification": {"rootId": "TEST", "timestamp": 1} if status == "verified" else None,
    }


def setup(clock, signed=True, **addresses):
    """The mock gateway; ``signed=False`` answers unsigned, as production does today, so its clients have no
    response-signing roots (UNSIGNED): a client with roots refuses an unsigned answer."""
    gateway = MockGateway(clock, sign_responses=signed)
    standard_vaults(gateway)
    for key, items in addresses.items():
        gateway.addresses[key] = items
    return gateway


UNSIGNED = {"roots": None}


def vault_list_calls(gateway):
    return [request.url.raw_path.decode() for request in gateway.received if request.url.path in ("/vaults/main", "/vaults/test")]


def statuses(result):
    return [check["status"] for check in result.meta.address_checks]


def expect_error(kind, client, call, error_class=AddressVerificationError):
    async def scenario(api):
        with pytest.raises(error_class) as raised:
            await call(api)
        return raised.value

    return run(kind, client, scenario)


# -- first sight and trust ----------------------------------------------------------------------------


def test_first_sight_pins_from_a_signed_list_and_verifies(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    store, events = MemoryVaultKeyStore(), []
    result = run(kind, make_client(kind, gateway, store=store, on_security_event=events.append), deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    assert statuses(result) == ["verified"]
    assert result.item["address"] == case["address"]
    assert vault_list_calls(gateway) == ["/vaults/main?limit=50"]
    assert store.get(ORIGIN, VAULT_MAIN)["status"] == "verified"
    assert "vault_key_pinned" in [event["type"] for event in events]
    assert all(ECDSA_XPUB not in str(event) for event in events)


def test_first_sight_from_an_unsigned_list_is_trust_on_first_use(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2pkh", path="m/0/0/0")
    gateway = setup(clock, signed=False)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    store = MemoryVaultKeyStore()
    result = run(kind, make_client(kind, gateway, store=store, **UNSIGNED), deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    assert statuses(result) == ["unverified"], "never reported as verified"
    assert store.get(ORIGIN, VAULT_MAIN)["status"] == "unverified"


def test_a_tofu_pin_is_confirmed_by_the_first_signed_list(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = setup(clock, **{"x": []})
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case), address_item(case)]
    store, events = MemoryVaultKeyStore(), []
    store.pin_if_absent(ORIGIN, pin(VAULT_MAIN, "unverified"))
    client = make_client(kind, gateway, store=store, on_security_event=events.append)

    async def scenario(api):
        first = await deposit(VAULT_MAIN, "bitcoin", "mainnet")(api)
        second = await deposit(VAULT_MAIN, "bitcoin", "mainnet")(api)
        return first, second

    first, second = run(kind, client, scenario)
    assert statuses(first) == statuses(second) == ["verified"]
    stored = store.get(ORIGIN, VAULT_MAIN)
    assert stored["status"] == "verified" and stored["firstSeenAt"] == 1
    assert [event["type"] for event in events if event["type"].startswith("vault_key")] == ["vault_key_verified"]
    assert len(vault_list_calls(gateway)) == 1, "confirmed once, then the pin is used"


def test_a_tofu_pin_contradicted_by_a_signed_list_raises_the_alarm(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    store, events = MemoryVaultKeyStore(), []
    tofu = pin(VAULT_MAIN, "unverified", keys={"ECDSA": OTHER_ECDSA_XPUB, "EDDSA": EDDSA_XPUB})
    store.pin_if_absent(ORIGIN, tofu)
    error = expect_error(kind, make_client(kind, gateway, store=store, on_security_event=events.append), deposit(VAULT_MAIN, "bitcoin", "mainnet"), VaultKeyChangedError)
    assert error.alarms[0]["reason"] == "xpub_changed" and error.alarms[0]["algorithm"] == "ECDSA"
    assert store.get(ORIGIN, VAULT_MAIN) == tofu, "never re-pinned automatically"
    assert [event["type"] for event in events if event["type"] == "vault_key_changed"] == ["vault_key_changed"]
    assert OTHER_ECDSA_XPUB not in str(error) and ECDSA_XPUB not in str(events)


def test_any_vault_list_is_compared_with_the_pins(kind, clock):
    gateway = setup(clock)
    gateway.vaults["main"][0] = vault_item(VAULT_MAIN, "main", {"ECDSA": OTHER_ECDSA_XPUB, "EDDSA": EDDSA_XPUB})
    store = MemoryVaultKeyStore()
    store.pin_if_absent(ORIGIN, pin(VAULT_MAIN, "verified"))
    expect_error(
        kind, make_client(kind, gateway, store=store),
        lambda api: api.request("GET", "/vaults/{networkType}", path_params={"networkType": "main"}),
        VaultKeyChangedError,
    )
    assert store.get(ORIGIN, VAULT_MAIN)["keys"]["ECDSA"] == ECDSA_XPUB


@pytest.mark.parametrize("change", ["xpub_added", "type_changed"])
def test_a_new_algorithm_or_a_vault_type_change_is_refused(kind, clock, change):
    # Refused on purpose: the client confirms the change and re-pins the vault (vault-keys accept, replace()).
    gateway = setup(clock)
    store = MemoryVaultKeyStore()
    if change == "xpub_added":
        store.pin_if_absent(ORIGIN, pin(VAULT_MAIN, "verified", keys={"ECDSA": ECDSA_XPUB, "EDDSA": None}))
        vault_id, listed = VAULT_MAIN, "main"
    else:
        store.pin_if_absent(ORIGIN, pin(VAULT_TEST, "verified", vault_type="main"))
        vault_id, listed = VAULT_TEST, "test"
    error = expect_error(
        kind, make_client(kind, gateway, store=store),
        lambda api: api.request("GET", "/vaults/{networkType}", path_params={"networkType": listed}),
        VaultKeyChangedError,
    )
    assert [alarm["reason"] for alarm in error.alarms] == [change]
    assert error.alarms[0]["vaultId"] == vault_id


# -- pins given in configuration (pinned_vault_keys) -----------------------------------------------------


def configured(vault_id=VAULT_MAIN, keys=None, vault_type="main"):
    return [{"vaultId": vault_id, "type": vault_type, "keys": keys or {"ECDSA": ECDSA_XPUB, "EDDSA": EDDSA_XPUB}}]


def list_vaults(api):
    return api.request("GET", "/vaults/{networkType}", path_params={"networkType": "main"})


def test_a_configured_pin_counts_as_verified_with_an_unsigned_list(kind, clock):
    gateway = setup(clock, signed=False)
    store, events = MemoryVaultKeyStore(), []
    client = make_client(kind, gateway, store=store, on_security_event=events.append, pinned_vault_keys=configured(), **UNSIGNED)
    result = run(kind, client, list_vaults)
    assert result.meta.signature == "absent"
    assert list(result.meta.vault_keys) == [
        {"vaultId": VAULT_MAIN, "status": "verified", "outcome": "unchanged"},
        {"vaultId": VAULT_SMART, "status": "not_verifiable", "outcome": "not_verifiable"},
    ]
    assert store.get(ORIGIN, VAULT_MAIN) is None, "never written to the store"
    assert not [event for event in events if event["type"].startswith("vault_key")]


def test_a_configured_pin_checks_addresses_as_verified_without_listing_vaults(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = setup(clock, signed=False)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    store = MemoryVaultKeyStore()
    result = run(kind, make_client(kind, gateway, store=store, pinned_vault_keys=configured(), **UNSIGNED), deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    assert statuses(result) == ["verified"]
    assert vault_list_calls(gateway) == []
    assert store.list(ORIGIN) == []


def test_an_address_that_does_not_derive_from_a_configured_pin_is_refused(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh", xpub=OTHER_ECDSA_XPUB, path="m/0/0/1")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    error = expect_error(kind, make_client(kind, gateway, pinned_vault_keys=configured()), deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    assert error.code == "mismatch"


@pytest.mark.parametrize("signed", [True, False])
def test_a_list_that_differs_from_a_configured_pin_is_the_alarm(kind, clock, signed):
    gateway = setup(clock, signed=signed)
    store, events = MemoryVaultKeyStore(), []
    stored = pin(VAULT_MAIN, "unverified", keys={"ECDSA": OTHER_ECDSA_XPUB, "EDDSA": EDDSA_XPUB})
    store.pin_if_absent(ORIGIN, stored)
    # The configured pin takes the place of the stored one, which the list agrees with: still the alarm.
    client = make_client(kind, gateway, store=store, on_security_event=events.append, roots=PINNED_ROOTS if signed else None,
                         pinned_vault_keys=configured(keys={"ECDSA": OTHER_ECDSA_XPUB, "EDDSA": None}))
    error = expect_error(kind, client, list_vaults, VaultKeyChangedError)
    assert [(alarm["algorithm"], alarm["reason"]) for alarm in error.alarms] == [("ECDSA", "xpub_changed"), ("EDDSA", "xpub_added")]
    assert store.get(ORIGIN, VAULT_MAIN) == stored, "the store untouched"
    assert store.get(ORIGIN, VAULT_SMART) is None
    assert [event["type"] for event in events if event["type"].startswith("vault_key")] == ["vault_key_changed"]
    assert ECDSA_XPUB not in str(error) and OTHER_ECDSA_XPUB not in str(events)


def test_a_configured_pin_never_shows_an_xpub(kind, clock):
    client = make_client(kind, setup(clock), pinned_vault_keys=configured())
    blob = "\n".join([repr(client), str(client), repr(client._core), repr(vars(client._core))])
    assert ECDSA_XPUB not in blob and EDDSA_XPUB not in blob


def test_pins_survive_a_restart_and_alarm_after_it(kind, clock, tmp_path):
    path = tmp_path / "vault-keys.json"
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    run(kind, make_client(kind, gateway, store=FileVaultKeyStore(path)), deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    changed = setup(clock)
    changed.vaults["main"][0] = vault_item(VAULT_MAIN, "main", {"ECDSA": OTHER_ECDSA_XPUB, "EDDSA": EDDSA_XPUB})
    expect_error(
        kind, make_client(kind, changed, store=FileVaultKeyStore(path)),
        lambda api: api.request("GET", "/vaults/{networkType}", path_params={"networkType": "main"}),
        VaultKeyChangedError,
    )


# -- address checks ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "blockchain,network,fmt,vault_id",
    [
        ("bitcoin", "mainnet", "p2pkh", VAULT_MAIN),
        ("bitcoin", "testnet", "p2wpkh", VAULT_TEST),
        ("bitcoin-cash", "mainnet", "p2pkh-cash", VAULT_MAIN),
        ("ethereum", "mainnet", "standard", VAULT_MAIN),
        ("ethereum", "sepolia", "standard", VAULT_TEST),
        ("tron", "nile", "base58", VAULT_TEST),
        ("xrp", "mainnet", "classic", VAULT_MAIN),
        ("solana", "mainnet", "base58", VAULT_MAIN),
    ],
)
def test_deposit_addresses_verify_on_each_kind_of_chain(kind, clock, blockchain, network, fmt, vault_id):
    xpub = EDDSA_XPUB if blockchain == "solana" else ECDSA_XPUB
    case = address_case(blockchain, network, fmt, xpub=xpub)
    gateway = setup(clock)
    gateway.addresses[(vault_id, blockchain, network)] = [address_item(case)]
    result = run(kind, make_client(kind, gateway), deposit(vault_id, blockchain, network))
    assert statuses(result) == ["verified"]


def test_an_evm_address_in_another_letter_case_is_the_same_address(kind, clock):
    case = address_case("ethereum", "mainnet")
    item = dict(address_item(case), address="0x" + case["address"][2:].upper())
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "ethereum", "mainnet")] = [item]
    assert statuses(run(kind, make_client(kind, gateway), deposit(VAULT_MAIN, "ethereum", "mainnet"))) == ["verified"]


def test_a_swapped_address_is_refused_whole(kind, clock):
    genuine = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    other = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/5")
    gateway = setup(clock, signed=False)  # as production today: no response signature to catch it first
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [dict(address_item(genuine), address=other["address"])]
    events = []
    error = expect_error(kind, make_client(kind, gateway, on_security_event=events.append, **UNSIGNED), deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    assert (error.code, error.vault_id, error.address) == ("mismatch", VAULT_MAIN, other["address"])
    assert [event["type"] for event in events if event["type"] == "address_verification_failed"] == ["address_verification_failed"]


def test_one_bad_address_refuses_the_whole_page(kind, clock):
    items = [address_item(address_case("bitcoin", "mainnet", "p2wpkh", path=path)) for path in ("m/0/0/0", "m/0/0/1", "m/0/0/5")]
    items[1]["address"] = items[2]["address"]
    gateway = setup(clock, **{"x": []})
    gateway.addresses[("list", VAULT_MAIN, ACCOUNT)] = items
    assert expect_error(kind, make_client(kind, gateway), list_addresses(VAULT_MAIN)).code == "mismatch"


def test_a_list_infers_the_network_from_the_vault_type(kind, clock):
    main_items = [address_item(address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/0")), address_item(address_case("ethereum", "mainnet"))]
    test_items = [address_item(address_case("ethereum", "sepolia")), address_item(address_case("tron", "nile"), with_network=True)]
    gateway = setup(clock)
    gateway.addresses[("list", VAULT_MAIN, ACCOUNT)] = main_items
    gateway.addresses[("list", VAULT_TEST, ACCOUNT)] = test_items

    async def scenario(api):
        return await list_addresses(VAULT_MAIN)(api), await list_addresses(VAULT_TEST)(api)

    main, test = run(kind, make_client(kind, gateway), scenario)
    assert statuses(main) == ["verified", "verified"]
    assert statuses(test) == ["verified", "verified"]
    assert vault_list_calls(gateway) == ["/vaults/main?limit=50", "/vaults/main?limit=50", "/vaults/test?limit=50"]


def test_an_address_on_the_wrong_network_for_the_vault_is_refused(kind, clock):
    case = address_case("bitcoin", "testnet", "p2wpkh")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "testnet")] = [address_item(case)]
    assert expect_error(kind, make_client(kind, gateway), deposit(VAULT_MAIN, "bitcoin", "testnet")).code == "network_mismatch"


def test_a_chain_the_sdk_does_not_know_is_refused(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "cardano", "mainnet")] = [dict(address_item(case), blockchain="cardano")]
    assert expect_error(kind, make_client(kind, gateway), deposit(VAULT_MAIN, "cardano", "mainnet")).code == "unsupported"


def test_malformed_path_fields_are_refused(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [dict(address_item(case), addressIndex="01")]
    assert expect_error(kind, make_client(kind, gateway), deposit(VAULT_MAIN, "bitcoin", "mainnet")).code == "invalid"


def test_an_address_without_its_path_is_not_verifiable_and_needs_no_vault_list(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case, with_path=False)]
    result = run(kind, make_client(kind, gateway), deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    assert statuses(result) == ["not_verifiable"]
    assert vault_list_calls(gateway) == []


def test_with_require_address_paths_a_new_address_without_its_path_is_refused(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case, with_path=False)]
    events = []
    client = make_client(kind, gateway, on_security_event=events.append, require_address_paths=True)
    error = expect_error(kind, client, deposit(VAULT_MAIN, "bitcoin", "mainnet"))
    assert (error.code, error.vault_id, error.address) == ("path_missing", VAULT_MAIN, case["address"])
    failed = [event for event in events if event["type"] == "address_verification_failed"]
    assert failed == [{
        "type": "address_verification_failed", "origin": ORIGIN, "operationId": "generateDepositAddress", "vaultId": VAULT_MAIN,
        "code": "path_missing",
    }]
    # Whether the vault has MPC keys is read from the vault lists, as for an address that carries its path.
    assert vault_list_calls(gateway) == ["/vaults/main?limit=50"]


def test_with_require_address_paths_a_smart_vault_address_is_not_verifiable(kind, clock):
    case = address_case("ethereum", "mainnet")
    gateway = setup(clock)
    gateway.addresses[(VAULT_SMART, "ethereum", "mainnet")] = [address_item(case, with_path=False)]
    result = run(kind, make_client(kind, gateway, require_address_paths=True), deposit(VAULT_SMART, "ethereum", "mainnet"))
    assert statuses(result) == ["not_verifiable"]


def test_require_address_paths_is_off_by_default_while_the_paths_are_hidden(kind, clock):
    assert ADDRESS_PATHS_PUBLIC is False
    case = address_case("bitcoin", "mainnet", "p2wpkh")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case, with_path=False)]
    assert statuses(run(kind, make_client(kind, gateway), deposit(VAULT_MAIN, "bitcoin", "mainnet"))) == ["not_verifiable"]


@pytest.mark.parametrize("value", [None, 1, "yes"])
def test_require_address_paths_takes_only_a_bool(kind, value):
    with pytest.raises(ConfigurationError) as raised:
        make_client(kind, None, require_address_paths=value)
    assert raised.value.code == "invalid_require_address_paths"


def test_a_smart_vault_is_not_verifiable_and_remembered(kind, clock):
    case = address_case("ethereum", "mainnet")
    gateway = setup(clock)
    gateway.addresses[(VAULT_SMART, "ethereum", "mainnet")] = [address_item(case), address_item(case)]
    client = make_client(kind, gateway)

    async def scenario(api):
        return await deposit(VAULT_SMART, "ethereum", "mainnet")(api), await deposit(VAULT_SMART, "ethereum", "mainnet")(api)

    first, second = run(kind, client, scenario)
    assert statuses(first) == statuses(second) == ["not_verifiable"]
    assert len(vault_list_calls(gateway)) == 1


def test_a_vault_in_neither_list_is_refused(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh")
    gateway = setup(clock)
    gateway.addresses[("6630f1c2a9e4b5d7c8e9ffff", "bitcoin", "mainnet")] = [address_item(case)]
    error = expect_error(kind, make_client(kind, gateway), deposit("6630f1c2a9e4b5d7c8e9ffff", "bitcoin", "mainnet"))
    assert error.code == "unknown_vault"
    assert vault_list_calls(gateway) == ["/vaults/main?limit=50", "/vaults/test?limit=50"]


def test_the_vault_lists_are_paged_through(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh")
    gateway = setup(clock)
    filler = [vault_item("6630f1c2a9e4b5d7c8e9{:04d}".format(i), "main", {"ECDSA": ECDSA_XPUB, "EDDSA": None}) for i in range(55)]
    gateway.vaults["main"] = filler + gateway.vaults["main"]
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    store = MemoryVaultKeyStore()
    assert statuses(run(kind, make_client(kind, gateway, store=store), deposit(VAULT_MAIN, "bitcoin", "mainnet"))) == ["verified"]
    assert vault_list_calls(gateway) == ["/vaults/main?limit=50", "/vaults/main?limit=50&startingAfter=6630f1c2a9e4b5d7c8e90049"]
    assert len(store.list(ORIGIN)) == 56


def test_add_asset_must_return_the_address_sent(kind, clock):
    case = address_case("ethereum", "mainnet")
    gateway = setup(clock)
    client = make_client(kind, gateway)

    async def scenario(api):
        return await api.request("PUT", ADD_ASSET, path_params={"vaultId": VAULT_MAIN, "vaultAccountId": ACCOUNT}, item={"address": case["address"], "assetId": "a1"})

    result = run(kind, client, scenario)
    assert statuses(result) == ["not_verifiable"], "no chain in the answer: only the byte-equal check"

    gateway = setup(clock)
    gateway.route("PUT", r"/vaults/([^/]+)/vault-accounts/([^/]+)/add-asset", lambda request, match, body: (200, {"data": {"item": {"address": "0xSWAPPED"}}}))
    error = expect_error(kind, make_client(kind, gateway), lambda api: api.request("PUT", ADD_ASSET, path_params={"vaultId": VAULT_MAIN, "vaultAccountId": ACCOUNT}, item={"address": case["address"]}))
    assert error.code == "mismatch"


def test_add_asset_with_chain_and_path_is_derived(kind, clock):
    case = address_case("ethereum", "mainnet")
    gateway = setup(clock)
    answer = dict(address_item(case, with_network=True), assetUnit="USDT")
    gateway.route("PUT", r"/vaults/([^/]+)/vault-accounts/([^/]+)/add-asset", lambda request, match, body: (200, {"data": {"item": answer}}))
    client = make_client(kind, gateway)

    async def scenario(api):
        return await api.request("PUT", ADD_ASSET, path_params={"vaultId": VAULT_MAIN, "vaultAccountId": ACCOUNT}, item={"address": case["address"]})

    assert statuses(run(kind, client, scenario)) == ["verified"]
