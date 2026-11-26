"""The API methods that return addresses or vault keys, on both clients: every address checked against
its vault's pinned xpub, every vault list compared with the pins, and nothing returned when a check fails.

generate_deposit_address, list_addresses_by_vault_account_id and add_asset_to_vault_account return
addresses; list_vaults is where the xpubs come from. tests/test_client_addresses.py covers the pinning
rules themselves; these show the methods go through them.
"""

import pytest

from vaultody_sdk import AddressVerificationError, MemoryVaultKeyStore, VaultKeyChangedError

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
    envelope_item,
    envelope_page,
    standard_vaults,
    vault_item,
)

ADD_ASSET = r"/vaults/([^/]+)/vault-accounts/([^/]+)/add-asset"
LIST_ADDRESSES = r"/vaults/([^/]+)/vault-accounts/([^/]+)/list-addresses"


def setup(clock, signed=True):
    """The mock gateway; ``signed=False`` answers unsigned, as production does today, to a client without
    response-signing roots (a client with roots refuses it)."""
    gateway = MockGateway(clock, sign_responses=signed)
    standard_vaults(gateway)
    return gateway


def statuses(meta):
    return [check["status"] for check in meta.address_checks]


def swapped(case, path):
    """The item of ``case`` naming another address of the same vault, chain and format."""
    other = address_case(case["blockchain"], case["network"], case["addressFormatWire"], path=path)
    assert other["address"] != case["address"]
    return dict(address_item(case), address=other["address"])


async def collect(api, pages):
    if api.is_async:
        return [item async for item in pages]
    return list(pages)


async def collect_pages(api, pages):
    """The pages read until one fails, and the failure."""
    found = []
    try:
        if api.is_async:
            async for page in pages.pages():
                found.append(page)
        else:
            for page in pages.pages():
                found.append(page)
    except Exception as error:  # noqa: BLE001 - returned for the test
        return found, error
    return found, None


async def awaited(api, value):
    return (await value) if api.is_async else value


# -- generate_deposit_address -------------------------------------------------------------------------


def deposit(api, vault_id=VAULT_MAIN, blockchain="bitcoin", network="mainnet"):
    return awaited(api, api.client.assets_addresses.generate_deposit_address(
        vaultId=vault_id, blockchain=blockchain, network=network, label="TEST", vaultAccountId=ACCOUNT,
    ))


def test_a_deposit_address_is_verified_against_the_vault_xpub(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [address_item(case)]
    store = MemoryVaultKeyStore()
    result = run(kind, make_client(kind, gateway, store=store), deposit)
    assert result.item["address"] == case["address"]
    assert statuses(result.meta) == ["verified"]
    assert store.get(ORIGIN, VAULT_MAIN)["status"] == "verified", "pinned from the signed vault list on first sight"


def test_a_swapped_deposit_address_is_refused(kind, clock):
    case = address_case("bitcoin", "mainnet", "p2wpkh", path="m/0/0/1")
    gateway = setup(clock)
    gateway.addresses[(VAULT_MAIN, "bitcoin", "mainnet")] = [swapped(case, "m/0/0/5")]
    events = []

    async def scenario(api):
        with pytest.raises(AddressVerificationError) as raised:
            await deposit(api)
        return raised.value

    error = run(kind, make_client(kind, gateway, on_security_event=events.append), scenario)
    assert error.code == "mismatch" and error.vault_id == VAULT_MAIN
    assert "address_verification_failed" in [event["type"] for event in events]


def test_a_deposit_address_without_a_derivation_path_is_not_verifiable_never_verified(kind, clock):
    case = address_case("ethereum", "sepolia")
    gateway = setup(clock)
    gateway.addresses[(VAULT_TEST, "ethereum", "sepolia")] = [address_item(case, with_path=False)]
    result = run(kind, make_client(kind, gateway), lambda api: deposit(api, VAULT_TEST, "ethereum", "sepolia"))
    assert statuses(result.meta) == ["not_verifiable"]


# -- list_addresses_by_vault_account_id ------------------------------------------------------------------


def test_every_listed_address_of_every_page_is_checked(kind, clock):
    good = [address_case("bitcoin", "mainnet", "p2pkh", path=path) for path in ("m/0/0/0", "m/0/0/1", "m/0/1/0")]
    gateway = setup(clock)
    pages = [
        envelope_page([address_item(good[0]), address_item(good[1])], has_more=True, limit=2),
        envelope_page([address_item(good[2])], has_more=False, limit=2),
    ]
    gateway.route("GET", LIST_ADDRESSES, lambda request, match, body: (200, pages.pop(0)))

    async def scenario(api):
        listing = api.client.assets_addresses.list_addresses_by_vault_account_id(vaultId=VAULT_MAIN, vaultAccountId=ACCOUNT, limit=2)
        return await collect_pages(api, listing)

    found, failure = run(kind, make_client(kind, gateway), scenario)
    assert failure is None
    assert [statuses(page.meta) for page in found] == [["verified", "verified"], ["verified"]]
    assert [check["address"] for page in found for check in page.meta.address_checks] == [case["address"] for case in good]


def test_a_swapped_address_on_a_later_page_refuses_that_page(kind, clock):
    good = address_case("bitcoin", "mainnet", "p2pkh", path="m/0/0/0")
    gateway = setup(clock)
    pages = [
        envelope_page([address_item(good)], has_more=True, limit=1),
        envelope_page([swapped(good, "m/0/0/1")], has_more=False, limit=1),
    ]
    gateway.route("GET", LIST_ADDRESSES, lambda request, match, body: (200, pages.pop(0)))

    async def scenario(api):
        listing = api.client.assets_addresses.list_addresses_by_vault_account_id(vaultId=VAULT_MAIN, vaultAccountId=ACCOUNT, limit=1)
        return await collect_pages(api, listing)

    found, failure = run(kind, make_client(kind, gateway), scenario)
    assert [statuses(page.meta) for page in found] == [["verified"]]
    assert isinstance(failure, AddressVerificationError) and failure.code == "mismatch", "nothing of the bad page is returned"


# -- add_asset_to_vault_account ----------------------------------------------------------------------------


def add_asset(api, **fields):
    return awaited(api, api.client.vault_accounts.add_asset_to_vault_account(vaultId=VAULT_MAIN, vaultAccountId=ACCOUNT, assetId="a1", **fields))


def answering(gateway, item):
    gateway.route("PUT", ADD_ASSET, lambda request, match, body: (200, envelope_item(item)))


def test_adding_an_asset_to_an_address_must_return_that_address(kind, clock):
    case = address_case("ethereum", "mainnet")
    gateway = setup(clock)
    result = run(kind, make_client(kind, gateway), lambda api: add_asset(api, address=case["address"]))
    assert result.item["address"] == case["address"]
    assert statuses(result.meta) == ["not_verifiable"], "no chain in the answer: the byte-equal check only"

    gateway = setup(clock)
    other = address_case("ethereum", "mainnet", path="m/0/0/1")
    assert other["address"] != case["address"]
    answering(gateway, {"address": other["address"], "assetUnit": "USDT"})

    async def scenario(api):
        with pytest.raises(AddressVerificationError) as raised:
            await add_asset(api, address=case["address"])
        return raised.value

    assert run(kind, make_client(kind, gateway), scenario).code == "mismatch"


def test_adding_an_asset_with_a_label_checks_the_new_address(kind, clock):
    case = address_case("ethereum", "mainnet")
    gateway = setup(clock)
    answering(gateway, dict(address_item(case, with_network=True), assetUnit="USDT"))
    result = run(kind, make_client(kind, gateway), lambda api: add_asset(api, label="Alice deposit"))
    assert statuses(result.meta) == ["verified"]

    gateway = setup(clock)
    answering(gateway, dict(address_item(case, with_network=True), assetUnit="USDT", accountIndex=case["accountIndex"] + 1))

    async def scenario(api):
        with pytest.raises(AddressVerificationError) as raised:
            await add_asset(api, label="Alice deposit")
        return raised.value

    assert run(kind, make_client(kind, gateway), scenario).code == "mismatch"


def test_a_new_address_with_a_path_but_no_chain_is_refused(kind, clock):
    case = address_case("ethereum", "mainnet")
    gateway = setup(clock)
    item = address_item(case)
    del item["blockchain"]
    answering(gateway, item)

    async def scenario(api):
        with pytest.raises(AddressVerificationError) as raised:
            await add_asset(api, label="Alice deposit")
        return raised.value

    # No chain to derive on: unsupported, as in Node and PHP.
    assert run(kind, make_client(kind, gateway), scenario).code == "unsupported"


def test_a_new_address_without_a_path_is_not_verifiable(kind, clock):
    gateway = setup(clock)
    answering(gateway, {"address": "0xa5bd60af2ed1499ce8292bb2e6c0179dcea34f33", "assetUnit": "USDT"})
    result = run(kind, make_client(kind, gateway), lambda api: add_asset(api, label="Alice deposit"))
    assert statuses(result.meta) == ["not_verifiable"], "the documented answer today: no path fields yet"


# -- list_vaults -------------------------------------------------------------------------------------------


def list_vaults(api, network_type="main"):
    return collect(api, api.client.vaults.list_vaults(networkType=network_type))


def test_listing_vaults_pins_their_xpubs(kind, clock):
    gateway = setup(clock)
    store = MemoryVaultKeyStore()
    vaults = run(kind, make_client(kind, gateway, store=store), list_vaults)
    assert [vault["id"] for vault in vaults] == [VAULT_MAIN, VAULT_SMART]
    pinned = store.get(ORIGIN, VAULT_MAIN)
    assert pinned["status"] == "verified" and pinned["keys"] == {"ECDSA": ECDSA_XPUB, "EDDSA": EDDSA_XPUB}
    assert store.get(ORIGIN, VAULT_SMART) is None, "no MPC keys: nothing to pin"


def test_an_unsigned_vault_list_pins_unverified(kind, clock):
    gateway = setup(clock, signed=False)
    store = MemoryVaultKeyStore()
    run(kind, make_client(kind, gateway, store=store, roots=None), lambda api: list_vaults(api, "test"))
    assert store.get(ORIGIN, VAULT_TEST)["status"] == "unverified", "trust on first use, never reported as verified"


def test_every_vault_list_page_reports_each_vault(kind, clock):
    """meta.vault_keys: per vault, its pin status after the answer and what the answer did to it."""
    store = MemoryVaultKeyStore()

    async def first_page(api):
        found, error = await collect_pages(api, api.client.vaults.list_vaults(networkType="main"))
        assert error is None
        return [list(page.meta.vault_keys) for page in found]

    def listed(signed):
        # A release candidate (no roots) while the API does not sign, then a client with roots on the same store.
        return run(kind, make_client(kind, setup(clock, signed=signed), store=store, roots=PINNED_ROOTS if signed else None), first_page)

    smart = {"vaultId": VAULT_SMART, "status": "not_verifiable", "outcome": "not_verifiable"}
    assert listed(False) == [[{"vaultId": VAULT_MAIN, "status": "unverified", "outcome": "pinned"}, smart]]
    assert listed(False) == [[{"vaultId": VAULT_MAIN, "status": "unverified", "outcome": "unchanged"}, smart]]
    assert listed(True) == [[{"vaultId": VAULT_MAIN, "status": "verified", "outcome": "upgraded"}, smart]]
    assert listed(True) == [[{"vaultId": VAULT_MAIN, "status": "verified", "outcome": "unchanged"}, smart]]


def test_other_answers_carry_no_vault_results(kind, clock):
    result = run(kind, make_client(kind, setup(clock)), lambda api: api.request("GET", "/ping"))
    assert result.meta.vault_keys == ()


def test_a_changed_xpub_in_a_vault_list_raises_the_alarm(kind, clock):
    gateway = setup(clock)
    store = MemoryVaultKeyStore()
    run(kind, make_client(kind, gateway, store=store), list_vaults)
    gateway = setup(clock)
    gateway.vaults["main"][0] = vault_item(VAULT_MAIN, "main", {"ECDSA": OTHER_ECDSA_XPUB, "EDDSA": EDDSA_XPUB})
    events = []

    async def scenario(api):
        listed = []
        with pytest.raises(VaultKeyChangedError) as raised:
            async_or_sync = api.client.vaults.list_vaults(networkType="main")
            if api.is_async:
                async for vault in async_or_sync:
                    listed.append(vault)
            else:
                for vault in async_or_sync:
                    listed.append(vault)
        return raised.value, listed

    error, listed = run(kind, make_client(kind, gateway, store=store, on_security_event=events.append), scenario)
    assert listed == [], "nothing of the list is returned"
    assert error.alarms[0]["vaultId"] == VAULT_MAIN and error.alarms[0]["reason"] == "xpub_changed"
    assert store.get(ORIGIN, VAULT_MAIN)["keys"]["ECDSA"] == ECDSA_XPUB, "the pin is not touched"
    assert OTHER_ECDSA_XPUB not in str(events) and OTHER_ECDSA_XPUB not in str(error)
