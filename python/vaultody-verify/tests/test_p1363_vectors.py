"""test-vectors/p1363-der-v1.json: a P-256 signature as IEEE P1363 r||s turned into the DER form the
gateway requires."""

import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vaultody_verify import SignatureFormatError, p1363_to_der

from vaultody_vectors import load

VECTORS = load("p1363-der-v1.json")
PUBLIC_KEY = serialization.load_der_public_key(base64.b64decode(VECTORS["publicKeySpkiDerBase64"]))


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=[vector["name"] for vector in VECTORS["cases"]])
def test_p1363_to_der(vector):
    data = bytes.fromhex(vector["p1363Hex"])
    if "error" in vector["expected"]:
        with pytest.raises(SignatureFormatError) as raised:
            p1363_to_der(data)
        assert raised.value.code == vector["expected"]["error"]
        return
    der = p1363_to_der(data)
    assert der.hex() == vector["expected"]["derHex"]
    if vector["messageBase64"] is not None:
        PUBLIC_KEY.verify(der, base64.b64decode(vector["messageBase64"]), ec.ECDSA(hashes.SHA256()))


def test_takes_a_memoryview_and_a_bytearray():
    vector = next(case for case in VECTORS["cases"] if case["name"] == "both_high_bits")
    data = bytes.fromhex(vector["p1363Hex"])
    assert p1363_to_der(memoryview(b"xyz" + data)[3:]).hex() == vector["expected"]["derHex"]
    assert p1363_to_der(bytearray(data)).hex() == vector["expected"]["derHex"]


def test_refuses_text():
    with pytest.raises(SignatureFormatError) as raised:
        p1363_to_der("00" * 64)
    assert raised.value.code == "invalid_length"
