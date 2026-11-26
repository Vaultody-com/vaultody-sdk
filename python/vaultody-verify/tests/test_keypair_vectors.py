"""The shared vectors for the customer key-pair signature and the registration proof of possession.

test-vectors/request-keypair-v1.json and test-vectors/keypair-challenge-v1.json. For every case this
builds the signed string from the request fields the way a client must, checks it against the bytes in
the vector, then verifies the signature the way the API does and expects the
vector's verdict. They are the contract for the SDKs' request signing.
"""

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vaultody_verify import keys

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test-vectors"
REQUEST_VECTORS = json.loads((VECTORS_DIR / "request-keypair-v1.json").read_text(encoding="utf-8"))
CHALLENGE_VECTORS = json.loads((VECTORS_DIR / "keypair-challenge-v1.json").read_text(encoding="utf-8"))

REQUEST_TAG = "vaultody-request-keypair-v1"
CHALLENGE_TAG = "vaultody-keypair-challenge-v1"
# fullmatch only: Python's "$" would also accept a trailing newline
CHALLENGE_FORMAT = re.compile(r"vk-chal-[0-9a-f]{64}")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())


def strict_base64(text):
    """Standard padded base64 in the one spelling an encoder writes, else None."""
    if not text or not _BASE64.fullmatch(text):
        return None
    data = base64.b64decode(text)
    return data if base64.b64encode(data).decode("ascii") == text else None


def request_signed_string(request):
    """The string a client signs for x-api-keypair-sign, as UTF-8: the tag, the x-api-key, then the HMAC v2 fields."""
    fields = (
        REQUEST_TAG,
        request["apiKey"],
        request["timestamp"],
        request["method"],
        request["path"],
        request["apiVersion"],
        request["passphrase"],
        request["nonce"],
        request["query"],
        request["body"],
    )
    return "\n".join(fields).encode("utf-8")


def challenge_proof_string(api_key_id, fingerprint, challenge):
    return "\n".join((CHALLENGE_TAG, api_key_id, fingerprint, challenge)).encode("utf-8")


def public_key_of(pem):
    """What a registration makes of a pasted public key: (algorithm, canonical SPKI DER, fingerprint, key) or an error code."""
    if "PRIVATE KEY" in pem:
        return {"error": "api_key_public_key_is_private"}
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except Exception:
        return {"error": "api_key_public_key_invalid"}
    if isinstance(key, Ed25519PublicKey):
        algorithm = "ed25519"
    elif isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1":
        algorithm = "p-256"
    else:
        return {"error": "api_key_public_key_unsupported_algorithm"}
    # SubjectPublicKeyInfo DER always carries an EC point uncompressed here, however it was pasted
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode("ascii").rstrip("=")
    return {
        "algorithm": algorithm,
        "canonicalSpkiDerBase64": base64.b64encode(der).decode("ascii"),
        "fingerprint": fingerprint,
        "key": key,
    }


def signature_verifies(public_key, message, signature_text):
    """Ed25519: the raw 64 bytes; P-256: ECDSA SHA-256 in DER, accepted only in its one encoding."""
    signature = strict_base64(signature_text)
    if signature is None:
        return False
    try:
        if public_key["algorithm"] == "ed25519":
            if len(signature) != 64:
                return False
            public_key["key"].verify(signature, message)
        else:
            public_key["key"].verify(signature, message, _ECDSA_SHA256)
    except Exception:
        return False
    return True


def key_named(vectors, name):
    return public_key_of(vectors["keys"][name]["publicKeySpkiPem"])


def without_key(result):
    return {name: value for name, value in result.items() if name != "key"}


def ids(cases):
    return [vector["name"] for vector in cases]


def test_request_vectors_are_v1_with_every_category_and_both_algorithms():
    assert REQUEST_VECTORS["format"] == "vaultody request key-pair signatures, v1"
    assert "TEST-ONLY" in REQUEST_VECTORS["warning"]
    categories = {vector["category"] for vector in REQUEST_VECTORS["cases"]}
    assert {"valid", "tampered", "key", "encoding", "signed_string"} <= categories
    valid = {vector["signed"]["algorithm"] for vector in REQUEST_VECTORS["cases"] if vector["expected"]["valid"]}
    assert valid == {"ed25519", "p-256"}


def test_a_request_signed_for_one_api_key_is_refused_under_another():
    swapped = next(vector for vector in REQUEST_VECTORS["cases"] if vector["name"] == "signed_for_other_api_key")
    assert swapped["verify"]["request"]["apiKey"] != swapped["signed"]["request"]["apiKey"]
    assert {**swapped["verify"]["request"], "apiKey": swapped["signed"]["request"]["apiKey"]} == swapped["signed"]["request"]
    assert swapped["expected"] == {"valid": False, "reason": "invalid_api_keypair_sign"}
    assert all(isinstance(vector["verify"]["request"]["apiKey"], str) for vector in REQUEST_VECTORS["cases"])


@pytest.mark.parametrize("name", sorted(REQUEST_VECTORS["keys"]))
def test_key_fingerprint_and_public_half(name):
    key = REQUEST_VECTORS["keys"][name]
    parsed = public_key_of(key["publicKeySpkiPem"])
    assert parsed["fingerprint"] == key["fingerprint"]
    assert parsed["algorithm"] == key["algorithm"]
    private = serialization.load_pem_private_key(key["privateKeyPkcs8Pem"].encode("ascii"), password=None)
    der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert base64.b64encode(der).decode("ascii") == key["publicKeySpkiDerBase64"]


@pytest.mark.parametrize("key_case", REQUEST_VECTORS["publicKeys"], ids=ids(REQUEST_VECTORS["publicKeys"]))
def test_public_key_as_pasted(key_case):
    assert without_key(public_key_of(key_case["publicKeyPem"])) == key_case["expected"]


@pytest.mark.parametrize("vector", REQUEST_VECTORS["cases"], ids=ids(REQUEST_VECTORS["cases"]))
def test_request_case_build_then_verify(vector):
    signed, verify = vector["signed"], vector["verify"]

    # 1. The client's signed string, from the request fields
    built = request_signed_string(signed["request"])
    if vector["category"] == "signed_string":
        # what was signed here is not that string: that is the point of the case
        assert base64.b64encode(built).decode("ascii") != signed["signedStringBase64"]
    else:
        assert base64.b64encode(built).decode("ascii") == signed["signedStringBase64"]
        assert built.decode("utf-8") == signed["signedString"]
        assert signature_verifies(key_named(REQUEST_VECTORS, signed["key"]), built, signed["signature"])

    # 2. The gateway's check, on the request and headers as received
    registered = [key_named(REQUEST_VECTORS, name) for name in verify["registeredKeys"]]
    public_key = next((key for key in registered if key["fingerprint"] == verify["headers"]["x-api-keypair-id"]), None)
    if public_key is None:
        verdict = {"valid": False, "reason": "unknown_api_keypair_id"}
    elif signature_verifies(public_key, request_signed_string(verify["request"]), verify["headers"]["x-api-keypair-sign"]):
        verdict = {"valid": True}
    else:
        verdict = {"valid": False, "reason": "invalid_api_keypair_sign"}
    assert verdict == vector["expected"]

    # 3. The package's own builder and check reach the same bytes and verdict.
    assert keys.keypair_request_message(signed["request"]) == built
    package_keys = [keys.read_signing_key(REQUEST_VECTORS["keys"][name]["publicKeySpkiPem"]) for name in verify["registeredKeys"]]
    headers = verify["headers"]
    assert keys.verify_keypair_request(package_keys, verify["request"], headers["x-api-keypair-id"], headers["x-api-keypair-sign"]) == vector["expected"]


def test_challenge_vectors_are_v1_and_share_the_keys():
    assert CHALLENGE_VECTORS["format"] == "vaultody key-pair proof of possession, challenge v1"
    assert CHALLENGE_VECTORS["keys"] == REQUEST_VECTORS["keys"]


@pytest.mark.parametrize("vector", CHALLENGE_VECTORS["cases"], ids=ids(CHALLENGE_VECTORS["cases"]))
def test_challenge_case_build_then_verify(vector):
    signed, verify = vector["signed"], vector["verify"]

    built = challenge_proof_string(signed["apiKeyId"], signed["fingerprint"], signed["challenge"])
    if vector["category"] == "signed_string":
        assert base64.b64encode(built).decode("ascii") != signed["proofStringBase64"]
    else:
        assert base64.b64encode(built).decode("ascii") == signed["proofStringBase64"]
        assert signature_verifies(key_named(CHALLENGE_VECTORS, signed["key"]), built, signed["signature"])

    # The registration rebuilds the proof from the pasted key's own fingerprint
    public_key = key_named(CHALLENGE_VECTORS, verify["publicKey"])
    proof = challenge_proof_string(verify["apiKeyId"], public_key["fingerprint"], verify["challenge"])
    if CHALLENGE_FORMAT.fullmatch(verify["challenge"]) and signature_verifies(public_key, proof, verify["signature"]):
        verdict = {"valid": True}
    else:
        verdict = {"valid": False, "reason": "api_key_public_key_proof_invalid"}
    assert verdict == vector["expected"]


@pytest.mark.parametrize(
    "format_case", CHALLENGE_VECTORS["challengeFormat"], ids=[repr(item["challenge"]) for item in CHALLENGE_VECTORS["challengeFormat"]]
)
def test_challenge_format(format_case):
    assert bool(CHALLENGE_FORMAT.fullmatch(format_case["challenge"])) is format_case["valid"]
