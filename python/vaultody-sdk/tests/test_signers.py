"""Request signers: key files, callbacks (KMS-style, sync and async), P-256 encodings and the local check."""

import asyncio
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature

from vaultody_sdk import AsyncCallbackSigner, CallbackSigner, ConfigurationError, FileSigner, PemSigner, SignerError
from vaultody_sdk.signers import MAX_KEY_FILE_BYTES, SignerInfo, normalise_signature
from vaultody_verify import read_signing_key

from conftest import make_client, run
from mock_gateway import CLIENT_KEYS, MockGateway
from sdk_vectors import load

ED25519 = CLIENT_KEYS["ed25519"]
P256 = CLIENT_KEYS["p256"]
MESSAGE = b"vaultody-request-keypair-v1\nTEST"
P1363_VECTORS = load("p1363-der-v1.json")


def p256_private():
    return read_signing_key(P256["privateKeyPkcs8Pem"]).private_key


def p1363(der):
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_pem_signer_signs_and_never_shows_the_key():
    signer = PemSigner(ED25519["privateKeyPkcs8Pem"])
    assert signer.algorithm == "ed25519" and signer.fingerprint == ED25519["fingerprint"]
    assert len(signer.sign(MESSAGE)) == 64
    assert "PRIVATE" not in repr(signer) and ED25519["privateKeyPkcs8Pem"] not in repr(vars(signer))
    assert signer.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")


@pytest.mark.parametrize("pem,code", [
    (ED25519["publicKeySpkiPem"], "public_key"),
    ("not a key", "invalid_key"),
    ("", "invalid_key"),
])
def test_pem_signer_needs_a_private_key(pem, code):
    with pytest.raises(ConfigurationError) as raised:
        PemSigner(pem)
    assert raised.value.code == code


def test_file_signer_reads_a_key_file_with_the_clis_rules(tmp_path):
    path = tmp_path / "private.pem"
    path.write_text(P256["privateKeyPkcs8Pem"])
    assert FileSigner(path).fingerprint == P256["fingerprint"]
    big = tmp_path / "big.pem"
    big.write_bytes(b"x" * (MAX_KEY_FILE_BYTES + 1))
    with pytest.raises(ConfigurationError) as raised:
        FileSigner(big)
    assert raised.value.code == "invalid_key"
    with pytest.raises(ConfigurationError) as raised:
        FileSigner(tmp_path)
    assert raised.value.code == "unreadable_key_file"
    with pytest.raises(ConfigurationError):
        FileSigner(tmp_path / "missing.pem")


def test_callback_signer_with_a_kms_digest():
    key = p256_private()

    def kms_sign(digest):
        assert len(digest) == 32
        return key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    signer = CallbackSigner("p-256", P256["publicKeySpkiPem"], kms_sign, digest_only=True)
    info = SignerInfo(signer, allow_async=False)
    assert info.input_for(MESSAGE) == hashlib.sha256(MESSAGE).digest()
    text = normalise_signature(info, MESSAGE, signer.sign(info.input_for(MESSAGE)))
    assert read_signing_key(P256["publicKeySpkiPem"]).public_key.verify(base64.b64decode(text), MESSAGE, ec.ECDSA(hashes.SHA256())) is None


def test_p1363_output_is_turned_into_der_and_checked():
    key = p256_private()
    signer = CallbackSigner("p-256", P256["publicKeySpkiPem"], lambda message: p1363(key.sign(message, ec.ECDSA(hashes.SHA256()))))
    info = SignerInfo(signer, allow_async=False)
    public = read_signing_key(P256["publicKeySpkiPem"]).public_key
    for _ in range(20):
        der = base64.b64decode(normalise_signature(info, MESSAGE, signer.sign(MESSAGE)))
        assert der[0] == 0x30
        public.verify(der, MESSAGE, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("verify_locally", [True, False])
def test_64_bytes_that_start_like_der_are_p1363_through_the_signer(verify_locally):
    """p1363-der-v1.json p1363_starts_like_der: a P-256 signer's 64 bytes are r || s even when r starts like a
    DER SEQUENCE (0x30 then 62), converted to the vector's DER, with or without the check against the signer's
    key."""
    vector = next(case for case in P1363_VECTORS["cases"] if case["name"] == "p1363_starts_like_der")
    message = base64.b64decode(vector["messageBase64"])
    output = bytes.fromhex(vector["p1363Hex"])
    assert len(output) == 64 and output[:2] == b"\x30\x3e"
    pem = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n".format(P1363_VECTORS["publicKeySpkiDerBase64"])
    signer = CallbackSigner("p-256", pem, lambda data: output if data == message else b"")
    info = SignerInfo(signer, allow_async=False)
    text = normalise_signature(info, message, signer.sign(info.input_for(message)), verify_locally=verify_locally)
    assert base64.b64decode(text).hex() == vector["expected"]["derHex"]


def test_64_bytes_are_never_read_as_der():
    """Even 64 bytes that are a whole canonical DER signature are taken as r || s: one reading in every SDK."""
    der = encode_dss_signature(2 ** 224 + 1, 2 ** 224 + 3)
    assert len(der) == 64
    info = SignerInfo(CallbackSigner("p-256", P256["publicKeySpkiPem"], lambda message: der), allow_async=False)
    sent = base64.b64decode(normalise_signature(info, MESSAGE, der, verify_locally=False))
    assert sent != der and decode_dss_signature(sent) == (int.from_bytes(der[:32], "big"), int.from_bytes(der[32:], "big"))


def test_a_p256_signature_neither_der_nor_64_bytes_is_refused():
    info = SignerInfo(CallbackSigner("p-256", P256["publicKeySpkiPem"], lambda message: b""), allow_async=False)
    for output in (b"\x01" * 63, b"\x01" * 65, b"\x30" + b"\x01" * 70):
        with pytest.raises(SignerError) as raised:
            normalise_signature(info, MESSAGE, output, verify_locally=False)
        assert raised.value.code == "invalid_length"


def test_a_signature_from_the_wrong_key_fails_here_not_as_a_401():
    other = read_signing_key(CLIENT_KEYS["p256_other"]["privateKeyPkcs8Pem"]).private_key
    signer = CallbackSigner("p-256", P256["publicKeySpkiPem"], lambda message: other.sign(message, ec.ECDSA(hashes.SHA256())))
    with pytest.raises(SignerError) as raised:
        normalise_signature(SignerInfo(signer, allow_async=False), MESSAGE, signer.sign(MESSAGE))
    assert raised.value.code == "does_not_verify"
    assert P256["fingerprint"] in str(raised.value)


@pytest.mark.parametrize("output,code", [(b"\x00" * 63, "invalid_length"), ("text", "invalid_signature_type"), (b"\x01" * 65, "invalid_length")])
def test_an_ed25519_signature_must_be_64_bytes(output, code):
    signer = CallbackSigner("ed25519", ED25519["publicKeySpkiPem"], lambda message: output)
    with pytest.raises(SignerError) as raised:
        normalise_signature(SignerInfo(signer, allow_async=False), MESSAGE, output)
    assert raised.value.code == code


@pytest.mark.parametrize("algorithm,pem,code", [
    ("rsa", ED25519["publicKeySpkiPem"], "unsupported_algorithm"),
    ("p-256", ED25519["publicKeySpkiPem"], "algorithm_mismatch"),
    ("ed25519", ED25519["privateKeyPkcs8Pem"], "api_key_public_key_is_private"),
])
def test_callback_signer_setup_errors(algorithm, pem, code):
    with pytest.raises(ConfigurationError) as raised:
        CallbackSigner(algorithm, pem, lambda message: b"")
    assert raised.value.code == code


def test_digest_only_is_for_p256():
    with pytest.raises(ConfigurationError):
        CallbackSigner("ed25519", ED25519["publicKeySpkiPem"], lambda message: b"", digest_only=True)


def test_an_async_signer_needs_the_async_client():
    async def sign(message):
        return b""

    signer = AsyncCallbackSigner("ed25519", ED25519["publicKeySpkiPem"], sign)
    with pytest.raises(ConfigurationError) as raised:
        make_client("sync", None, signer=signer)
    assert raised.value.code == "async_signer"
    with pytest.raises(ConfigurationError):
        CallbackSigner("ed25519", ED25519["publicKeySpkiPem"], sign)


@pytest.mark.parametrize("style", ["async", "sync-in-thread"])
def test_the_async_client_takes_both_kinds_of_signer(clock, style):
    key = read_signing_key(ED25519["privateKeyPkcs8Pem"]).private_key

    def sync_sign(message):
        return key.sign(message)

    async def async_sign(message):
        await asyncio.sleep(0)
        return key.sign(message)

    signer = AsyncCallbackSigner("ed25519", ED25519["publicKeySpkiPem"], async_sign) if style == "async" else CallbackSigner("ed25519", ED25519["publicKeySpkiPem"], sync_sign)
    gateway = MockGateway(clock, registered_keys=["ed25519"])
    client = make_client("async", gateway, signer=signer)

    async def scenario(api):
        return await api.request("GET", "/ping")

    assert run("async", client, scenario).item == {"pong": True}
    assert gateway.received[0].headers["x-api-keypair-id"] == ED25519["fingerprint"]


def test_the_gateway_accepts_a_p256_kms_signer_end_to_end(kind, clock):
    key = p256_private()
    signer = CallbackSigner("p-256", P256["publicKeySpkiPem"], lambda digest: p1363(key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))), digest_only=True)
    gateway = MockGateway(clock, registered_keys=["p256"])
    client = make_client(kind, gateway, signer=signer)

    async def scenario(api):
        return await api.check_signing_key()

    status = run(kind, client, scenario)
    assert status == dict(status, outcome="active", signature="verified", fingerprint=P256["fingerprint"])
