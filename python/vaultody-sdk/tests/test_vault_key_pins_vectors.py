"""test-vectors/vault-key-pins-v1.json: signed and unsigned vault lists, verified with vaultody_verify, and
what they do to the vault xpub pins. A case's configured pins (pinned_vault_keys) are compared like stored
ones and take their place; pinsAfter is the store alone, which never holds them."""

import base64
import json

import pytest

from vaultody_verify import ResponseSignatureError, verify_response
from vaultody_sdk import AddressVerificationError, VaultKeyChangedError, address_check_status, observe_vaults, read_vault_list
from vaultody_sdk.vault_keys import address_path_required, configured_pins

from sdk_vectors import ids, load

VECTORS = load("vault-key-pins-v1.json")
RESPONSE_VECTORS = load("v1.json")
ROOTS = [base64.b64decode(RESPONSE_VECTORS["keys"]["roots"][name]["publicKeySpkiDerBase64"]) for name in VECTORS["pinnedRoots"]]


def sorted_pins(pins):
    return sorted(pins.values(), key=lambda pin: pin["vaultId"])


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=ids(VECTORS["cases"]))
def test_pins(vector):
    pins = {pin["vaultId"]: pin for pin in vector["initialPins"]}
    configured = configured_pins(vector["configuredPins"])
    for step in vector["steps"]:
        request, response, now, expected = step["request"], step["response"], step["now"], step["expected"]
        body = base64.b64decode(response["bodyBase64"])
        try:
            result = verify_response(
                {
                    "method": request["method"],
                    "url": request["path"] + ("?" + request["query"] if request["query"] else ""),
                    "body": base64.b64decode(request["bodyBase64"]),
                    "api_sign": request["apiSign"],
                    "keypair_sign": request["keypairSign"],
                },
                {"status": response["status"], "headers": response["headers"], "body": body},
                roots=ROOTS,
                now=now,
                require_response_signature=False,
            )
        except ResponseSignatureError as error:
            assert {"error": error.reason} == expected["signature"]
            assert sorted_pins(pins) == expected["pinsAfter"]
            continue
        assert ("verified" if result.verified else "absent") == expected["signature"]

        vaults = read_vault_list(json.loads(body)["data"]["items"])
        if result.verified:
            evidence = {"signed": True, "rootId": result.root_id, "timestamp": result.timestamp, "now": now}
        else:
            evidence = {"signed": False, "now": now}
        if "alarms" in expected:
            with pytest.raises(VaultKeyChangedError) as raised:
                observe_vaults({**pins, **configured}, vaults, evidence)
            assert raised.value.alarms == expected["alarms"]
            for vault in vaults:
                for xpub in vault["keys"].values():
                    if xpub:
                        assert xpub not in str(raised.value)
        else:
            outcomes, changes = observe_vaults({**pins, **configured}, vaults, evidence)
            assert outcomes == expected["outcomes"]
            assert not any(pin["vaultId"] in configured for pin in changes), "a configured pin is never written"
            pins = dict(pins)
            for pin in changes:
                pins[pin["vaultId"]] = pin
        assert sorted_pins(pins) == expected["pinsAfter"]


@pytest.mark.parametrize("check", VECTORS["addressChecks"], ids=ids(VECTORS["addressChecks"]))
def test_address_check(check):
    if check["pin"] == "configured":
        pin = configured_pins([{"vaultId": "v", "type": "main", "keys": {"ECDSA": "xpub-TEST", "EDDSA": None}}])["v"]
    else:
        pin = None if check["pin"] is None else {"status": check["pin"]}
    # pathRequired absent: require_address_paths off.
    required = check.get("pathRequired")
    path_required = required is not None and address_path_required(required["requireAddressPaths"], required["operationId"], required["chainKnown"])
    args = (pin, check["vaultHasKeys"], check["pathFields"], check["derivation"])
    if "error" in check["expected"]:
        with pytest.raises(AddressVerificationError) as raised:
            address_check_status(*args, path_required=path_required)
        assert raised.value.code == check["expected"]["error"]
    else:
        assert address_check_status(*args, path_required=path_required) == check["expected"]["status"]


@pytest.mark.parametrize("operation_id", ["generateDepositAddress", "listAddressesByVaultAccountId", "addAssetToVaultAccount"])
def test_a_path_is_required_only_for_a_new_address_on_a_known_chain_with_the_option_on(operation_id):
    assert address_path_required(True, operation_id, True) is (operation_id == "generateDepositAddress")
    assert address_path_required(False, operation_id, True) is False
    assert address_path_required(True, operation_id, False) is False
