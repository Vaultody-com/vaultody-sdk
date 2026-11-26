"""test-vectors/request-hmac-v2.json and request-full-v1.json, generated with the gateway's own apiSign and
RequestKeypair: the HMAC v2 string and signature, the secrets the SDK refuses, and every authentication
header of a request, with and without a key pair."""

import base64

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from vaultody_verify import keys

from vaultody_vectors import load

HMAC_VECTORS = load("request-hmac-v2.json")
FULL_VECTORS = load("request-full-v1.json")


def ids(cases):
    return [vector["name"] for vector in cases]


@pytest.mark.parametrize("vector", HMAC_VECTORS["cases"], ids=ids(HMAC_VECTORS["cases"]))
def test_hmac_v2(vector):
    secret, request, expected = vector["secret"], vector["request"], vector["expected"]
    if "error" in expected:
        with pytest.raises(keys.UsageError) as raised:
            keys.hmac_v2_signature(secret, request)
        assert raised.value.code == expected["error"]
        with pytest.raises(keys.UsageError) as raised:
            keys.sign_hmac_v2_request({"apiKey": "k", "apiSecret": secret, "passphrase": request["passphrase"]}, request)
        assert raised.value.code == expected["error"]
        return
    message = keys.hmac_v2_request_message(request)
    assert message.decode("utf-8") == expected["signedString"]
    assert base64.b64encode(message).decode("ascii") == expected["signedStringBase64"]
    assert keys.hmac_v2_signature(secret, request) == expected["signature"]


def test_the_secret_never_appears_in_an_error():
    vector = HMAC_VECTORS["cases"][0]
    secret = vector["secret"] + "\n"
    with pytest.raises(keys.UsageError) as raised:
        keys.hmac_v2_signature(secret, vector["request"])
    assert vector["secret"] not in str(raised.value)
    assert vector["secret"] not in repr(raised.value)


def key_of(name, part):
    record = FULL_VECTORS["keys"][name]
    return keys.read_signing_key(record["privateKeyPkcs8Pem"] if part == "private" else record["publicKeySpkiPem"])


@pytest.mark.parametrize("name", sorted(FULL_VECTORS["keys"]))
def test_keys_read_with_their_fingerprint(name):
    record = FULL_VECTORS["keys"][name]
    for part in ("private", "public"):
        key = key_of(name, part)
        assert key.algorithm == record["algorithm"]
        assert key.fingerprint == record["fingerprint"]
        assert base64.b64encode(key.spki_der).decode("ascii") == record["publicKeySpkiDerBase64"]
    assert "PRIVATE" not in repr(key_of(name, "private")) and "BEGIN" not in repr(key_of(name, "private"))


@pytest.mark.parametrize("vector", FULL_VECTORS["cases"], ids=ids(FULL_VECTORS["cases"]))
def test_full_header_set(vector):
    credentials = FULL_VECTORS["credentials"]
    request, expected = vector["request"], vector["expected"]
    if vector["key"]:
        headers = keys.sign_api_request(key_of(vector["key"], "private"), credentials, request)
    else:
        headers = keys.sign_hmac_v2_request(credentials, request)

    assert sorted(headers) == sorted(expected["headers"])
    for name, value in expected["headers"].items():
        if value is not None:
            assert headers[name] == value, name
    if expected["keypairSignature"] == "none":
        assert expected["keypairSignedStringBase64"] is None
        return

    # The key-pair string carries the x-api-key the request is sent with, on its second line.
    received = dict(request, apiKey=headers["x-api-key"])
    signed_string = keys.keypair_request_message(received)
    assert signed_string.split(b"\n")[:2] == [b"vaultody-request-keypair-v1", credentials["apiKey"].encode("ascii")]
    assert base64.b64encode(signed_string).decode("ascii") == expected["keypairSignedStringBase64"]
    if expected["keypairSignature"] == "exact":
        assert headers["x-api-keypair-sign"] == expected["headers"]["x-api-keypair-sign"]
    # Whatever the algorithm, the signature must verify the way the gateway checks it.
    registered = key_of(vector["key"], "public")
    verdict = keys.verify_keypair_request([registered], received, headers["x-api-keypair-id"], headers["x-api-keypair-sign"])
    assert verdict == {"valid": True}
    if registered.algorithm == keys.P256:
        registered.public_key.verify(base64.b64decode(headers["x-api-keypair-sign"]), signed_string, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("api_key", [None, "", "line\nbreak", "carriage\rreturn", 7])
def test_the_key_pair_string_needs_the_api_key_on_one_line(api_key):
    request = dict(FULL_VECTORS["cases"][0]["request"], apiKey=api_key)
    with pytest.raises(keys.UsageError):
        keys.keypair_request_message(request)


def test_the_hmac_v2_string_has_no_api_key():
    credentials = FULL_VECTORS["credentials"]
    request = FULL_VECTORS["cases"][0]["request"]
    assert keys.hmac_v2_request_message(dict(request, apiKey=credentials["apiKey"])) == keys.hmac_v2_request_message(request)
    assert credentials["apiKey"].encode("ascii") not in keys.hmac_v2_request_message(request)


def test_a_fresh_nonce_and_the_time_when_none_is_given():
    credentials = FULL_VECTORS["credentials"]
    request = dict(FULL_VECTORS["cases"][0]["request"], nonce=None, timestamp=None)
    first = keys.sign_hmac_v2_request(credentials, request)
    second = keys.sign_hmac_v2_request(credentials, request)
    assert keys.NONCE_PATTERN.fullmatch(first["x-api-nonce"]) and len(first["x-api-nonce"]) == 32
    assert first["x-api-nonce"] != second["x-api-nonce"]
    assert first["x-api-timestamp"].isdigit()


def test_no_secret_in_the_headers():
    credentials = FULL_VECTORS["credentials"]
    headers = keys.sign_hmac_v2_request(credentials, FULL_VECTORS["cases"][0]["request"])
    assert credentials["apiSecret"] not in headers.values()


def test_refuses_missing_credentials_a_bad_nonce_and_a_public_key():
    credentials = FULL_VECTORS["credentials"]
    request = FULL_VECTORS["cases"][0]["request"]
    for bad in ({"apiKey": ""}, {"passphrase": None}, {"apiSecret": "!!!!"}):
        with pytest.raises(keys.UsageError):
            keys.sign_hmac_v2_request(dict(credentials, **bad), request)
    for nonce in ("has space", "x" * 129, "ü"):
        with pytest.raises(keys.UsageError):
            keys.sign_hmac_v2_request(credentials, dict(request, nonce=nonce))
    with pytest.raises(TypeError):
        keys.sign_api_request(key_of("p256", "public"), credentials, request)
