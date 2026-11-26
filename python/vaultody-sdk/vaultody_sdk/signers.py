"""Request signers: what makes x-api-keypair-sign, so the private key never has to sit in this process.

A signer has three attributes and one method:

- ``algorithm``: ``"ed25519"`` or ``"p-256"`` (ECDSA P-256 with SHA-256);
- ``public_key_pem``: the public key registered on the API key, one ``PUBLIC KEY`` PEM block;
- ``digest_only`` (optional, P-256 only): True when ``sign`` takes the SHA-256 digest of the message
  instead of the message, as KMS signing with a digest does;
- ``sign(message: bytes) -> bytes``, or ``async def sign`` for the async client.

The SDK takes the fingerprint (x-api-keypair-id) from ``public_key_pem``, turns a P-256 signature of 64 bytes,
always taken as IEEE P1363 (r || s, as Web Crypto, Azure Key Vault and some KMS APIs return it), into the DER
the gateway requires (any other length must be DER), refuses an Ed25519 signature that is not 64 bytes, and by default checks every signature against
``public_key_pem`` before sending it, so a wrong KMS key fails here with SignerError instead of as a 401
from the API.

Shipped: ``PemSigner`` and ``FileSigner`` (the key in memory), ``CallbackSigner`` and
``AsyncCallbackSigner`` (any KMS, HSM or vault: you pass the function that signs).
"""

import base64
import hashlib
import inspect
import os
import stat
from typing import Awaitable, Callable, Protocol, Union, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from vaultody_verify import SignatureFormatError, UsageError, p1363_to_der, read_signing_key
from vaultody_verify.keys import ED25519, P256, verify_message

from .errors import ConfigurationError, SignerError

#: A key file is never larger than this; an Ed25519 or P-256 PEM is a few hundred bytes (as the CLI reads it).
MAX_KEY_FILE_BYTES = 16 * 1024

_ED25519_SIGNATURE_BYTES = 64
_P1363_BYTES = 64


@runtime_checkable
class Signer(Protocol):
    """A synchronous request signer."""

    algorithm: str
    public_key_pem: str

    def sign(self, message: bytes) -> bytes: ...


@runtime_checkable
class AsyncSigner(Protocol):
    """An asynchronous request signer, for AsyncVaultody."""

    algorithm: str
    public_key_pem: str

    async def sign(self, message: bytes) -> bytes: ...


class PemSigner:
    """Signs with a private key held in memory: an unencrypted PKCS#8 or SEC1 PEM, Ed25519 or P-256.

    ``repr`` never shows the key.
    """

    digest_only = False

    def __init__(self, private_key_pem: Union[str, bytes]):
        try:
            key = read_signing_key(private_key_pem)
        except UsageError as error:
            raise ConfigurationError("the request-signing key is not usable: {}".format(error), "invalid_key") from None
        if key.private_key is None:
            raise ConfigurationError("signing needs the private key, not the public key", "public_key")
        self._key = key
        self.algorithm = key.algorithm
        self.public_key_pem = _public_pem(key)

    @property
    def fingerprint(self) -> str:
        return self._key.fingerprint

    def sign(self, message: bytes) -> bytes:
        if self.algorithm == ED25519:
            return self._key.private_key.sign(bytes(message))
        return self._key.private_key.sign(bytes(message), ec.ECDSA(hashes.SHA256()))

    def __repr__(self) -> str:
        return "PemSigner({}, {})".format(self.algorithm, self._key.fingerprint)


class FileSigner(PemSigner):
    """A PemSigner reading the key from a file: a regular file of at most 16 KiB holding one private key."""

    def __init__(self, path: Union[str, "os.PathLike[str]"]):
        super().__init__(_read_key_file(path))


class CallbackSigner:
    """Signs through a function of yours: a KMS, an HSM, Vault Transit.

    :param algorithm: ``"ed25519"`` or ``"p-256"``
    :param public_key_pem: the public key registered on the API key
    :param sign: ``sign(message) -> signature bytes``; Ed25519 the raw 64 bytes, P-256 DER or P1363 (64 bytes)
    :param digest_only: P-256 only: ``sign`` gets SHA-256(message) instead of the message
    """

    def __init__(self, algorithm: str, public_key_pem: Union[str, bytes], sign: Callable[[bytes], bytes], *, digest_only: bool = False):
        if inspect.iscoroutinefunction(sign):
            raise ConfigurationError("this sign function is async: use AsyncCallbackSigner", "async_signer")
        _init_callback(self, algorithm, public_key_pem, sign, digest_only)

    def sign(self, message: bytes) -> bytes:
        return self._sign(message)

    def __repr__(self) -> str:
        return "CallbackSigner({}, {})".format(self.algorithm, self.fingerprint)


class AsyncCallbackSigner:
    """CallbackSigner for an ``async def sign(message) -> bytes``; for AsyncVaultody only."""

    def __init__(self, algorithm: str, public_key_pem: Union[str, bytes], sign: Callable[[bytes], Awaitable[bytes]], *, digest_only: bool = False):
        _init_callback(self, algorithm, public_key_pem, sign, digest_only)

    async def sign(self, message: bytes) -> bytes:
        return await self._sign(message)

    def __repr__(self) -> str:
        return "AsyncCallbackSigner({}, {})".format(self.algorithm, self.fingerprint)


def _init_callback(signer, algorithm, public_key_pem, sign, digest_only):
    if algorithm not in (ED25519, P256):
        raise ConfigurationError('the signer algorithm must be "ed25519" or "p-256"', "unsupported_algorithm")
    if not callable(sign):
        raise ConfigurationError("sign must be a function", "invalid_signer")
    if digest_only and algorithm != P256:
        raise ConfigurationError("only a P-256 signer can sign a digest", "invalid_signer")
    key = read_public_key(public_key_pem)
    if key.algorithm != algorithm:
        raise ConfigurationError("the public key is {}, not {}".format(key.algorithm, algorithm), "algorithm_mismatch")
    signer.algorithm = algorithm
    signer.public_key_pem = _public_pem(key)
    signer.digest_only = bool(digest_only)
    signer.fingerprint = key.fingerprint
    signer._sign = sign


def read_public_key(public_key_pem):
    """The SigningKey of a public key PEM; ConfigurationError for anything else (a private key included)."""
    if isinstance(public_key_pem, str):
        text = public_key_pem
    elif isinstance(public_key_pem, (bytes, bytearray)):
        text = bytes(public_key_pem).decode("ascii", "replace")
    else:
        raise ConfigurationError("public_key_pem must be the PEM text of the public key", "invalid_key")
    if "PRIVATE KEY" in text:
        # Where only a public key belongs, a private one is refused before it is read any further.
        raise ConfigurationError("public_key_pem holds a private key; pass the public key only", "api_key_public_key_is_private")
    try:
        key = read_signing_key(text)
    except UsageError as error:
        code = "api_key_public_key_unsupported_algorithm" if error.code == "unsupported_algorithm" else "invalid_key"
        raise ConfigurationError("the public key is not usable: {}".format(error), code) from None
    return key


def _public_pem(key):
    from cryptography.hazmat.primitives import serialization

    return key.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _read_key_file(path):
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY)
    except OSError as error:
        raise ConfigurationError("cannot read the key file {!r}: {}".format(os.fspath(path), error.strerror or "error"), "unreadable_key_file") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigurationError("{!r} is not a file".format(os.fspath(path)), "unreadable_key_file")
        if info.st_size > MAX_KEY_FILE_BYTES:
            raise ConfigurationError("the key file is far larger than an Ed25519 or P-256 key", "invalid_key")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(MAX_KEY_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_KEY_FILE_BYTES:
        raise ConfigurationError("the key file is far larger than an Ed25519 or P-256 key", "invalid_key")
    return data


# ---------------------------------------------------------------------------------------------------
# What the core does around a signer
# ---------------------------------------------------------------------------------------------------


class SignerInfo:
    """A configured signer, checked once: its algorithm, fingerprint and public key, and how to call it."""

    __slots__ = ("signer", "algorithm", "fingerprint", "public_key", "digest_only", "is_async")

    def __init__(self, signer, *, allow_async):
        for name in ("algorithm", "public_key_pem", "sign"):
            if not hasattr(signer, name):
                raise ConfigurationError("a signer needs algorithm, public_key_pem and sign()", "invalid_signer")
        if signer.algorithm not in (ED25519, P256):
            raise ConfigurationError('the signer algorithm must be "ed25519" or "p-256"', "unsupported_algorithm")
        key = read_public_key(signer.public_key_pem)
        if key.algorithm != signer.algorithm:
            raise ConfigurationError("the signer's public key is {}, not {}".format(key.algorithm, signer.algorithm), "algorithm_mismatch")
        digest_only = bool(getattr(signer, "digest_only", False))
        if digest_only and signer.algorithm != P256:
            raise ConfigurationError("only a P-256 signer can sign a digest", "invalid_signer")
        is_async = inspect.iscoroutinefunction(signer.sign)
        if is_async and not allow_async:
            raise ConfigurationError("an async signer needs AsyncVaultody; Vaultody signs synchronously", "async_signer")
        self.signer = signer
        self.algorithm = signer.algorithm
        self.fingerprint = key.fingerprint
        self.public_key = key
        self.digest_only = digest_only
        self.is_async = is_async

    def input_for(self, message):
        """What to pass to ``sign``: the message, or its SHA-256 for a digest-only signer."""
        return hashlib.sha256(message).digest() if self.digest_only else message


def _is_der_signature(data):
    try:
        r, s = decode_dss_signature(data)
    except ValueError:
        return False
    # Only the one canonical encoding counts as DER; anything else is not taken as DER.
    return encode_dss_signature(r, s) == data


def normalise_signature(info, message, signature, *, verify_locally=True):
    """x-api-keypair-sign for one signature: standard padded base64 of Ed25519's 64 bytes or P-256 DER.

    :param info: the SignerInfo
    :param message: the key-pair string that was signed
    :param signature: what the signer returned
    :param verify_locally: check the signature against the signer's public key first (the default)
    :raises SignerError: ``invalid_signature_type``, ``invalid_length``, ``zero_integer``,
        ``invalid_encoding`` or ``does_not_verify``
    """
    if isinstance(signature, (bytearray, memoryview)):
        signature = bytes(signature)
    if not isinstance(signature, bytes):
        raise SignerError("invalid_signature_type", "the signer must return the signature as bytes")
    if info.algorithm == ED25519:
        if len(signature) != _ED25519_SIGNATURE_BYTES:
            raise SignerError("invalid_length", "an Ed25519 signature is 64 bytes, not {}".format(len(signature)))
        sent = signature
    elif len(signature) == _P1363_BYTES:
        # Exactly 64 bytes is IEEE P1363 r || s, always, even when it starts like DER: a P-256 DER signature is
        # 70 to 72 bytes for every signature a key makes in practice, and one reading keeps every SDK sending the
        # same bytes (p1363-der-v1.json).
        try:
            sent = p1363_to_der(signature)
        except SignatureFormatError as error:
            raise SignerError(error.code, "a 64-byte P-256 signature must be IEEE P1363 r || s: {}".format(error)) from None
    elif _is_der_signature(signature):
        sent = signature
    else:
        raise SignerError(
            "invalid_length", "a P-256 signature must be DER or IEEE P1363 r || s (64 bytes); this is {} bytes and not DER".format(len(signature))
        )
    text = base64.b64encode(sent).decode("ascii")
    if not verify_locally or verify_message(info.public_key, message, text):
        return text
    raise SignerError(
        "does_not_verify",
        "the signer's signature does not verify with its public key {}: is it the right key?".format(info.fingerprint),
    )


__all__ = [
    "MAX_KEY_FILE_BYTES",
    "AsyncCallbackSigner",
    "AsyncSigner",
    "CallbackSigner",
    "FileSigner",
    "PemSigner",
    "Signer",
    "normalise_signature",
    "read_public_key",
]
