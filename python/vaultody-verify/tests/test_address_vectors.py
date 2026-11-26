"""Every case of test-vectors/address-v1.json (addresses as the vault service's own derivation code returns them,
on 17 chains, and 13 inputs the server refuses) must verify exactly against its xpub, with the format as stored
and with no format at all; a changed address must fail; no refused input may verify. The file holds ``change``
as the generator wrote it; the API field is ``isChange``, passed here as ``is_change``.
"""

import pytest

from vaultody_verify import AddressVerificationError, check_address, network_of_vault
from vaultody_verify.address.chains import CHAINS, is_refused_format
from vaultody_verify.address.derivation import derive_path, parse_xpub

from vaultody_vectors import load

VECTORS = load("address-v1.json")  # test-vectors/address-v1.json, next to the other shared vector sets
CASES = VECTORS["cases"]
REJECTED = VECTORS["rejected"]


def type_of(blockchain, network):
    return VECTORS["chains"][blockchain]["networks"][network]["vaultType"].lower()


def vault_of(algorithm, xpub, vault_type):
    return {
        "type": vault_type,
        "keys": {"ECDSA": xpub if algorithm == "ECDSA" else None, "EDDSA": xpub if algorithm == "EDDSA" else None},
    }


def params_of(case, **overrides):
    result = dict(
        blockchain=case["blockchain"],
        network=case["network"],
        account_index=case["accountIndex"],
        is_change=case["change"],
        address_index=case["addressIndex"],
        address_format=case["addressFormat"],
        address=case.get("address", ""),
    )
    result.update(overrides)
    return result


def test_vectors_are_the_v1_format_with_cases_and_refused_inputs():
    assert VECTORS["format"] == "vaultody address derivation vectors v1"
    assert len(CASES) == 511
    assert len(REJECTED) == 13


def test_vectors_list_exactly_the_chains_networks_algorithms_and_wire_formats_this_helper_knows():
    assert sorted(VECTORS["chains"]) == sorted(CHAINS)
    for blockchain, chain in VECTORS["chains"].items():
        ours = CHAINS[blockchain]
        assert ours.algorithm == chain["algorithm"], blockchain
        assert sorted(ours.formats) == sorted(chain["addressFormatsWire"]), blockchain
        assert sorted(ours.networks) == sorted(chain["networks"]), blockchain
        for network, settings in chain["networks"].items():
            mine = ours.networks[network]
            for field, key in (("p2pkh", "pubKeyHash"), ("p2sh", "scriptHash")):
                if field in mine:
                    assert mine[field].hex() == settings[key], (blockchain, network, key)
            if "bech32" in mine:
                assert mine["bech32"] == settings["bech32"], (blockchain, network)
            # The SDK infers the network of an address from its vault's type when a response omits it.
            assert network_of_vault(blockchain, settings["vaultType"].lower()) == network, (blockchain, network)


_ROOTS = {}


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_case_verifies_with_the_format_as_stored_and_with_no_format(case):
    vault = vault_of(case["algorithm"], case["xpub"], type_of(case["blockchain"], case["network"]))
    result = check_address(vault, **params_of(case))
    assert result.verified is True
    assert (result.algorithm, result.path, result.address, result.address_format) == (
        case["algorithm"],
        case["path"],
        case["address"],
        case["addressFormatWire"],
    )
    assert check_address(vault, **params_of(case, address_format=None)) == result
    if case["xpub"] not in _ROOTS:
        _ROOTS[case["xpub"]] = parse_xpub(case["xpub"], case["algorithm"])
    node = derive_path(_ROOTS[case["xpub"]], [case["accountIndex"], 1 if case["change"] else 0, case["addressIndex"]])
    assert node.key.hex() == case["publicKey"]


def test_a_changed_address_fails_with_mismatch_for_one_case_of_every_chain_network_and_format():
    seen = set()
    for case in CASES:
        group = (case["blockchain"], case["network"], case["addressFormatWire"])
        if group in seen:
            continue
        seen.add(group)
        address = case["address"][:-1] + ("b" if case["address"][-1] == "a" else "a")
        vault = vault_of(case["algorithm"], case["xpub"], type_of(case["blockchain"], case["network"]))
        with pytest.raises(AddressVerificationError) as failure:
            check_address(vault, **params_of(case, address=address))
        assert failure.value.reason == "mismatch", group


def test_the_key_of_the_other_algorithm_or_the_other_vault_type_never_verifies():
    case = next(item for item in CASES if item["algorithm"] == "ECDSA" and item["network"] == "mainnet")
    with pytest.raises(AddressVerificationError) as failure:
        check_address({"type": "main", "keys": {"ECDSA": None, "EDDSA": case["xpub"]}}, **params_of(case))
    assert failure.value.reason == "missing_key"
    with pytest.raises(AddressVerificationError) as failure:
        check_address(vault_of(case["algorithm"], case["xpub"], "test"), **params_of(case))
    assert failure.value.reason == "network_mismatch"


def test_an_address_without_its_derivation_path_is_not_verifiable_never_verified():
    case = CASES[0]
    vault = vault_of(case["algorithm"], case["xpub"], type_of(case["blockchain"], case["network"]))
    params = params_of(case, account_index=None)
    with pytest.raises(AddressVerificationError) as failure:
        check_address(vault, **params)
    assert failure.value.reason == "not_verifiable"
    result = check_address(vault, **params, allow_unverifiable=True)
    assert result.verified is False
    assert result.reason == "not_verifiable"


@pytest.mark.parametrize("rejected", REJECTED, ids=["{} ({})".format(r["name"], r["reason"]) for r in REJECTED])
def test_no_input_the_server_refuses_is_reported_as_verified(rejected):
    sample = next(
        (c for c in CASES if c["xpubName"] == rejected["xpubName"] and c["blockchain"] == rejected["blockchain"]),
        CASES[0],
    )
    chain = VECTORS["chains"].get(rejected["blockchain"])
    network = chain["networks"].get(rejected["network"]) if chain else None
    vault = vault_of(rejected["algorithm"], rejected["xpub"], network["vaultType"].lower() if network else "test")
    params = params_of(rejected, address=sample["address"])
    with pytest.raises((TypeError, ValueError, AddressVerificationError)) as failure:
        check_address(vault, **params)
    if isinstance(failure.value, AddressVerificationError):
        assert failure.value.reason in ("unsupported", "mismatch")
    if is_refused_format(rejected["blockchain"], rejected["addressFormatWire"]):
        with pytest.raises(AddressVerificationError) as refused:
            check_address(vault, **params)
        assert refused.value.reason == "unsupported"
