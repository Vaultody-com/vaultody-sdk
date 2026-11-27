"""The root public keys this package trusts.

Every response certificate is signed by a Vaultody root key that never leaves a hardware security
module. Its public half is embedded here as the "current" root and, during a rotation, the "next" one,
so a release can start trusting a new root before the gateway switches to it, and a later release
drops the old one.

Each root is pinned by its fingerprint: the lowercase hex SHA-256 of its SubjectPublicKeyInfo DER. It
is the rootId that certificates name, and the value Vaultody publishes to clients outside Cloudflare,
so it can be compared by hand against this file.
"""

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .errors import ConfigurationError

# Production roots: SubjectPublicKeyInfo PEM and fingerprint.
#
# "current" is the production root (root-prod, a P-256 key in Cloud KMS that never leaves its HSM); "next"
# stays empty until a rotation. A PEM without its fingerprint, or one whose fingerprint doesn't match,
# stops the import. To trust another environment's root instead, pass ``roots=``.
CURRENT_ROOT_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1ikEmarTSQWW1eSFI1gjyXo3ctGp
nY25exvYPRD0rNOwrpfTf+PvUIeVdZrydIpxK/A6Ck9jrIjG/Wg98JeMYA==
-----END PUBLIC KEY-----
"""
CURRENT_ROOT_FINGERPRINT = "0194e94f295844b04dbdfb885338fb4242095e55479a01a03caafee3e36cdd76"

NEXT_ROOT_PEM = ""
NEXT_ROOT_FINGERPRINT = ""

_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_PEM_LABEL = re.compile(r"-----BEGIN ([^-]*)-----")
_PEM_BODY = re.compile(r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", re.DOTALL)
# A P-256 SubjectPublicKeyInfo with a named curve and an uncompressed point is this fixed 27-byte header
# (algorithm ecPublicKey, curve prime256v1, uncompressed-point marker) followed by the 64-byte point.
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
_P256_SPKI_BYTES = len(_P256_SPKI_PREFIX) + 64


@dataclass(frozen=True)
class Root:
    """A pinned root: its id (the SPKI SHA-256 fingerprint) and its P-256 public key."""

    root_id: str
    public_key: ec.EllipticCurvePublicKey


def _check_curve(key):
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ConfigurationError("a response-signing root must be an EC P-256 public key")


def _from_key(key):
    # A key object has no original bytes; cryptography always exports a P-256 key as a named-curve,
    # uncompressed SPKI, which is the one accepted layout.
    _check_curve(key)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return Root(root_id=hashlib.sha256(der).hexdigest(), public_key=key)


def _pem_to_der(data):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigurationError("a response-signing root PEM must be ASCII") from None
    labels = _PEM_LABEL.findall(text)
    body = _PEM_BODY.search(text)
    if labels != ["PUBLIC KEY"] or body is None:
        raise ConfigurationError('a response-signing root must hold exactly one "PUBLIC KEY" PEM block')
    try:
        return base64.b64decode("".join(body.group(1).split()), validate=True)
    except (binascii.Error, ValueError):
        raise ConfigurationError("a response-signing root PEM is not valid base64") from None


def _from_der(der):
    try:
        key = serialization.load_der_public_key(der)
    except Exception as error:  # any parse failure is a setup mistake, reported the same way
        raise ConfigurationError("could not read a response-signing root public key: {}".format(error)) from None
    _check_curve(key)
    # The id is a hash of the DER bytes as given, so every party must hash the same bytes for the same
    # key. Only the one standard layout is accepted, the one Cloud KMS publishes; a compressed point or
    # explicit curve parameters would describe the same key with different bytes and a different id.
    if len(der) != _P256_SPKI_BYTES or not der.startswith(_P256_SPKI_PREFIX):
        raise ConfigurationError(
            "a response-signing root must be a P-256 key in standard SPKI form (named curve, uncompressed point)"
        )
    return Root(root_id=hashlib.sha256(der).hexdigest(), public_key=key)


def load_root(value):
    """Turns one root into a Root.

    ``value`` is a SubjectPublicKeyInfo PEM (str or bytes), SubjectPublicKeyInfo DER bytes, a
    ``cryptography`` EC public key, or a Root. A PEM or DER must be a P-256 key with a named curve and
    an uncompressed point; anything else raises ConfigurationError.
    """
    if isinstance(value, Root):
        return value
    if hasattr(value, "public_bytes"):
        # A key object from cryptography; _from_key refuses anything but EC P-256.
        return _from_key(value)
    if isinstance(value, str):
        value = value.encode("ascii", "replace")
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        if data.lstrip().startswith(b"-----BEGIN"):
            return _from_der(_pem_to_der(data))
        return _from_der(data)
    raise TypeError(
        "a root must be SubjectPublicKeyInfo PEM or DER, or an EC public key, not {}".format(type(value).__name__)
    )


def parse_roots(values=None):
    """Reads ``roots=`` without requiring it to hold a root.

    A malformed root is a setup mistake and raises ConfigurationError at once. Returns None when
    ``values`` is None (use the embedded roots), else a tuple, possibly empty: whether any root is needed
    depends on the response, and an unsigned one needs none.
    """
    if values is None:
        return None
    if isinstance(values, (str, bytes, bytearray, memoryview)):
        raise TypeError("roots must be a list of roots, not a single PEM or DER value")
    if isinstance(values, Mapping):
        values = values.values()
    return tuple(load_root(value) for value in values if not _is_empty(value))


def require_roots(parsed):
    """The roots to check a signed response against: ``parsed`` (from parse_roots) or the embedded ones.

    Called only once a response carries a signature. Raises ConfigurationError when that leaves no root
    at all, so a missing root can never turn into a signed response that passes unchecked.
    """
    roots = EMBEDDED_ROOTS if parsed is None else parsed
    if not roots:
        raise ConfigurationError(
            "no response-signing roots are configured: pass the roots to trust with roots=[...]"
        )
    return roots


def load_roots(values=None):
    """The roots to trust: ``values`` when given, else the embedded ones.

    Raises ConfigurationError when that leaves no root at all, so a missing root can never turn into a
    response that passes unchecked.
    """
    return require_roots(parse_roots(values))


def _is_empty(value):
    # An empty slot is allowed in a mapping or list, because "next" exists only around a rotation.
    return value is None or (isinstance(value, (str, bytes, bytearray)) and len(value) == 0)


def _embedded_root(name, pem, fingerprint):
    """Loads one embedded root and checks it against the fingerprint recorded next to it."""
    if not pem and not fingerprint:
        return None
    if not pem or not fingerprint:
        raise ConfigurationError("embedded {} root: the PEM and its fingerprint must be set together".format(name))
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise ConfigurationError("embedded {} root: the fingerprint must be 64 lowercase hex characters".format(name))
    root = load_root(pem)
    if root.root_id != fingerprint:
        raise ConfigurationError(
            "embedded {} root: the PEM's SHA-256 fingerprint is {}, not the recorded {}".format(
                name, root.root_id, fingerprint
            )
        )
    return root


def _embedded_roots():
    pairs = (
        ("current", CURRENT_ROOT_PEM, CURRENT_ROOT_FINGERPRINT),
        ("next", NEXT_ROOT_PEM, NEXT_ROOT_FINGERPRINT),
    )
    loaded = (_embedded_root(name, pem, fingerprint) for name, pem, fingerprint in pairs)
    return tuple(root for root in loaded if root is not None)


# Checked at import, so a release with a mistyped key or fingerprint fails loudly the first time it is
# imported instead of rejecting (or worse, trusting) responses later.
EMBEDDED_ROOTS: Tuple[Root, ...] = _embedded_roots()


def embedded_fingerprints():
    """The fingerprints of the embedded roots, to compare against the ones Vaultody published."""
    return tuple(root.root_id for root in EMBEDDED_ROOTS)


__all__ = [
    "CURRENT_ROOT_PEM",
    "CURRENT_ROOT_FINGERPRINT",
    "NEXT_ROOT_PEM",
    "NEXT_ROOT_FINGERPRINT",
    "EMBEDDED_ROOTS",
    "Root",
    "load_root",
    "load_roots",
    "parse_roots",
    "require_roots",
    "embedded_fingerprints",
]
