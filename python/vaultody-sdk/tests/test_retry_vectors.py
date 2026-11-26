"""test-vectors/retry-v1.json: one finished attempt → retry (re-signed or resent), return, fail or outcome unknown."""

import pytest

from vaultody_sdk import RETRY, decide_retry

from sdk_vectors import ids, load

VECTORS = load("retry-v1.json")


def test_uses_the_constants_of_the_vectors():
    assert dict(RETRY) == VECTORS["constants"]


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=ids(VECTORS["cases"]))
def test_retry(vector):
    assert decide_retry(vector["input"]) == vector["expected"]
