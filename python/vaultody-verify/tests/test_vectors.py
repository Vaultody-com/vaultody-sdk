"""Every shared test vector must produce exactly its expected verdict and reason."""

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vaultody_verify import ResponseSignatureError, VerificationResult, verify_response
from vaultody_verify.response import MAX_CERT_LIFETIME_SECONDS

from vaultody_vectors import CASES, VECTORS, inputs, root_pem


def test_vectors_are_loaded_and_cover_every_reason():
    assert len(CASES) > 0
    reasons = {vector["expected"].get("reason") for vector in CASES if not vector["expected"]["valid"]}
    assert reasons == set(ResponseSignatureError.REASONS)
    assert any(vector["expected"]["valid"] for vector in CASES)


@pytest.mark.parametrize("vector", CASES, ids=[vector["name"] for vector in CASES])
def test_vector_verdict(vector):
    request, response, options = inputs(vector)
    expected = vector["expected"]

    if expected["valid"]:
        result = verify_response(request, response, **options)
        certificate = vector["signed"]["certificate"]
        assert result == VerificationResult(
            verified=True,
            key_id=certificate["keyId"],
            root_id=certificate["rootId"],
            timestamp=vector["signed"]["ts"],
        )
    else:
        with pytest.raises(ResponseSignatureError) as failure:
            verify_response(request, response, **options)
        assert failure.value.reason == expected["reason"]


@pytest.mark.parametrize("vector", CASES, ids=[vector["name"] for vector in CASES])
def test_vector_verdict_in_non_strict_mode(vector):
    """Non-strict mode changes the outcome of a response with no signature at all, and nothing else."""
    request, response, options = inputs(vector)
    expected = vector["expected"]

    if vector["name"] == "missing_all":
        result = verify_response(request, response, require_response_signature=False, **options)
        assert result == VerificationResult(verified=False, reason="missing")
    elif expected["valid"]:
        assert verify_response(request, response, require_response_signature=False, **options).verified is True
    else:
        with pytest.raises(ResponseSignatureError) as failure:
            verify_response(request, response, require_response_signature=False, **options)
        assert failure.value.reason == expected["reason"]


_NOT_BEFORE = 1794200000


def _signed_under(not_after):
    """A response signed by pod 1 under a certificate the current root signed for [notBefore, not_after]."""
    root = VECTORS["keys"]["roots"]["current"]
    pod = VECTORS["keys"]["podKeys"]["pod1"]
    cert = "\n".join(
        ("vaultody-response-key-v1", root["rootId"], pod["publicKeyBase64"], pod["keyId"], str(_NOT_BEFORE), str(not_after))
    ).encode("ascii")
    root_key = serialization.load_pem_private_key(root["privateKeyPkcs8Pem"].encode("ascii"), password=None)
    root_signature = root_key.sign(cert, ec.ECDSA(hashes.SHA256()))
    pod_key = serialization.load_pem_private_key(pod["privateKeyPkcs8Pem"].encode("ascii"), password=None)
    ts = _NOT_BEFORE + 1000
    body = b'{"ok":true}'
    head = "\n".join(("vaultody-response-v1", str(ts), "200", "GET", "/vaults", "", hashlib.sha256(b"").hexdigest(), "", ""))
    signature = pod_key.sign(head.encode("ascii") + b"\n" + body)
    headers = {
        "x-api-response-sign": base64.b64encode(signature).decode("ascii"),
        "x-api-response-timestamp": str(ts),
        "x-api-response-sign-version": "1",
        "x-api-response-cert": base64.b64encode(cert).decode("ascii") + "." + base64.b64encode(root_signature).decode("ascii"),
    }
    return verify_response(
        {"method": "GET", "url": "/vaults"},
        {"status": 200, "headers": headers, "body": body},
        roots=[root_pem("current")],
        now=ts + 2,
    )


def test_the_certificate_lifetime_is_at_most_3600_seconds_as_the_vectors_say():
    assert MAX_CERT_LIFETIME_SECONDS == 3600
    assert VECTORS["verifier"]["maxCertificateLifetimeSeconds"] == MAX_CERT_LIFETIME_SECONDS


def test_a_certificate_valid_for_exactly_3600_seconds_is_accepted():
    assert _signed_under(_NOT_BEFORE + 3600).verified is True


def test_a_certificate_valid_for_3601_seconds_is_invalid_though_the_response_is_inside_its_window():
    with pytest.raises(ResponseSignatureError) as failure:
        _signed_under(_NOT_BEFORE + 3601)
    assert failure.value.reason == "invalid"
