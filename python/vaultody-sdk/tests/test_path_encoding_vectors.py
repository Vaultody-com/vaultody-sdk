"""test-vectors/path-encoding-v1.json: path and query parameters → the exact request target."""

import pytest

from vaultody_sdk import ParameterError, build_request_target

from sdk_vectors import ids, load

VECTORS = load("path-encoding-v1.json")


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=ids(VECTORS["cases"]))
def test_request_target(vector):
    query = [tuple(pair) for pair in vector["query"]]
    if "error" in vector["expected"]:
        with pytest.raises(ParameterError) as raised:
            build_request_target(vector["template"], vector["pathParams"], query)
        assert raised.value.code == vector["expected"]["error"]
        return
    assert build_request_target(vector["template"], vector["pathParams"], query) == vector["expected"]["target"]


def test_a_lone_surrogate_has_no_utf8_form():
    # Not in the shared vectors: not every language's JSON reader takes a lone surrogate.
    with pytest.raises(ParameterError) as raised:
        build_request_target("/vaults/{vaultId}/utxos", {"vaultId": "\ud800"})
    assert raised.value.code == "invalid_path_param"
    with pytest.raises(ParameterError) as raised:
        build_request_target("/supported-assets", {}, [("assetUnit", "\ud800")])
    assert raised.value.code == "invalid_query_param"


def test_a_bool_is_no_integer_path_parameter_and_a_float_no_query_value():
    with pytest.raises(ParameterError) as raised:
        build_request_target("/vaults/{vaultId}/utxos", {"vaultId": False})
    assert raised.value.code == "invalid_path_param"
    with pytest.raises(ParameterError) as raised:
        build_request_target("/supported-assets", {}, [("limit", 2.0)])
    assert raised.value.code == "invalid_query_param"
