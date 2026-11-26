"""The embedded roots and the fingerprint check that runs at import."""

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization

from vaultody_verify import ConfigurationError
from vaultody_verify import roots as roots_module

from vaultody_vectors import root_der, root_id, root_pem


def test_every_embedded_root_matches_its_recorded_fingerprint_and_is_p256():
    pairs = [
        (roots_module.CURRENT_ROOT_PEM, roots_module.CURRENT_ROOT_FINGERPRINT),
        (roots_module.NEXT_ROOT_PEM, roots_module.NEXT_ROOT_FINGERPRINT),
    ]
    expected = [fingerprint for pem, fingerprint in pairs if pem]
    assert roots_module.embedded_fingerprints() == tuple(expected)
    for root in roots_module.EMBEDDED_ROOTS:
        assert root.public_key.curve.name == "secp256r1"


def test_fingerprint_is_the_root_id_certificates_name():
    """The id must equal the gateway's rootId: SHA-256 of the SPKI DER, from PEM or DER alike."""
    assert roots_module.load_root(root_pem("current")).root_id == root_id("current")
    assert roots_module.load_root(root_der("next")).root_id == root_id("next")


def test_embedded_root_with_matching_fingerprint_loads():
    root = roots_module._embedded_root("current", root_pem("current"), root_id("current"))
    assert root.root_id == root_id("current")


def test_empty_slot_is_skipped():
    assert roots_module._embedded_root("next", "", "") is None


@pytest.mark.parametrize(
    "pem, fingerprint",
    [
        pytest.param(lambda: root_pem("current"), lambda: root_id("next"), id="fingerprint-of-another-key"),
        pytest.param(lambda: root_pem("current"), lambda: root_id("current").upper(), id="uppercase-fingerprint"),
        pytest.param(lambda: root_pem("current"), lambda: "", id="pem-without-fingerprint"),
        pytest.param(lambda: "", lambda: root_id("current"), id="fingerprint-without-pem"),
        pytest.param(lambda: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", lambda: root_id("current"),
                     id="unreadable-pem"),
    ],
)
def test_embedded_root_mismatch_stops_the_import(pem, fingerprint):
    with pytest.raises(ConfigurationError):
        roots_module._embedded_root("current", pem(), fingerprint())


def compressed_point_spki_der():
    """The first test root as a compressed-point SPKI: the same key, different bytes, a different id."""
    key = serialization.load_der_public_key(root_der("current"))
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    assert len(point) == 33
    return bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + point


def compressed_point_spki_pem():
    body = base64.b64encode(compressed_point_spki_der()).decode("ascii")
    return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n"


def test_the_compressed_test_key_is_the_same_key_as_the_uncompressed_root():
    key = serialization.load_der_public_key(compressed_point_spki_der())
    assert key.public_numbers() == serialization.load_der_public_key(root_der("current")).public_numbers()


@pytest.mark.parametrize("form", [compressed_point_spki_der, compressed_point_spki_pem], ids=["der", "pem"])
def test_compressed_point_root_is_refused_in_the_roots_override(form):
    with pytest.raises(ConfigurationError):
        roots_module.load_roots([form()])
    with pytest.raises(ConfigurationError):
        roots_module.load_roots({"current": form()})


def test_compressed_point_root_is_refused_as_an_embedded_root():
    der = compressed_point_spki_der()
    fingerprint = hashlib.sha256(der).hexdigest()
    with pytest.raises(ConfigurationError):
        roots_module._embedded_root("current", compressed_point_spki_pem(), fingerprint)


def test_root_id_is_taken_from_the_der_as_given():
    assert roots_module.load_root(root_der("current")).root_id == root_id("current")
    assert roots_module.load_root(root_pem("current")).root_id == root_id("current")
