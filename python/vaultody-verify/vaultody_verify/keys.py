"""Request signing for Vaultody API keys: the HMAC v2 signature and the customer key-pair signature.

Every request is signed with the API secret (``x-api-sign``, version 2). An API key that holds a
request-signing key pair of the customer's own (Ed25519 or ECDSA P-256) also needs ``x-api-keypair-sign``,
the private key's signature over the x-api-key and the same fields under another tag, so a leaked API secret
alone can no longer sign requests.

The wire formats are shared with the API gateway, the Node package and the docs, and pinned by the shared
vectors (test-vectors/request-hmac-v2.json, request-full-v1.json, request-keypair-v1.json and
p1363-der-v1.json). No error raised here carries key material, the API secret, the passphrase or the API
key.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import VaultodyVerifyError

ED25519 = "ed25519"
P256 = "p-256"
ALGORITHMS = (ED25519, P256)

#: "SHA256:" + base64 without padding of SHA-256 over the canonical SubjectPublicKeyInfo DER: 50 characters
FINGERPRINT_PREFIX = "SHA256:"
#: The tag of the HMAC v2 string (x-api-sign with x-api-sign-version: 2)
HMAC_V2_TAG = "v2"
#: The string signed for x-api-keypair-sign: this tag, the x-api-key, then the HMAC v2 fields in the same order
REQUEST_TAG = "vaultody-request-keypair-v1"
#: x-api-nonce: printable ASCII without spaces, 1 to 128 characters (fullmatch)
NONCE_PATTERN = re.compile(r"[\x21-\x7e]{1,128}")

API_HEADERS = {
    "api_key": "x-api-key",
    "passphrase": "x-api-passphrase",
    "timestamp": "x-api-timestamp",
    "sign": "x-api-sign",
    "sign_version": "x-api-sign-version",
    "nonce": "x-api-nonce",
    "api_version": "x-api-version",
    "keypair_sign": "x-api-keypair-sign",
    "keypair_id": "x-api-keypair-id",
}

ACTIVE = "active"

# Standard base64, padding optional: how Vaultody issues API secrets (10 random bytes, padded).
_API_SECRET_SHAPE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())
_P1363_SIGNATURE_BYTES = 64


class UsageError(VaultodyVerifyError):
    """A wrong argument or setting: the caller must change how it asks.

    ``code`` is a stable code where callers need one, such as ``"invalid_api_secret"``; else None.
    """

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class SignatureFormatError(VaultodyVerifyError):
    """A signature in a form that can't be converted (see p1363_to_der). ``code`` says why."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class UnexpectedResponseError(VaultodyVerifyError):
    """The API answered something other than a verdict on the key: a server error, an unknown shape."""

    def __init__(self, message, status=None, request_id=None, code=None):
        super().__init__(message)
        self.status = status
        self.request_id = request_id
        self.code = code


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 or P-256 key: its algorithm, fingerprint and canonical SPKI, and the private half if read.

    ``repr`` never shows the private key.
    """

    algorithm: str
    fingerprint: str
    spki_der: bytes
    public_key: object
    private_key: Optional[object] = None

    def __repr__(self):
        kind = "private" if self.private_key is not None else "public"
        return "SigningKey({}, {}, {})".format(self.algorithm, kind, self.fingerprint)


def _strict_base64(text):
    if not isinstance(text, str) or not text or not _BASE64.fullmatch(text):
        return None
    data = base64.b64decode(text)
    return data if base64.b64encode(data).decode("ascii") == text else None


def fingerprint_of(spki_der):
    """``SHA256:`` + unpadded base64 of SHA-256 over the canonical SubjectPublicKeyInfo DER."""
    return FINGERPRINT_PREFIX + base64.b64encode(hashlib.sha256(spki_der).digest()).decode("ascii").rstrip("=")


def _describe(public_key, private_key=None):
    if isinstance(public_key, Ed25519PublicKey):
        algorithm = ED25519
    elif isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.curve.name == "secp256r1":
        algorithm = P256
    else:
        raise UsageError("only Ed25519 and ECDSA P-256 keys are supported", "unsupported_algorithm")
    # cryptography always exports a P-256 point uncompressed here, whatever form the key was read in.
    spki_der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return SigningKey(algorithm, fingerprint_of(spki_der), spki_der, public_key, private_key)


def read_signing_key(pem):
    """Reads one Ed25519 or P-256 key in PEM: a public key (SPKI) or an unencrypted private key (PKCS#8, SEC1).

    :returns: SigningKey, with ``private_key`` set only for a private key
    :raises UsageError: not one readable Ed25519 or P-256 key (code ``invalid_key``, ``unsupported_algorithm``)
    """
    if isinstance(pem, str):
        pem = pem.encode("ascii", "replace")
    if not isinstance(pem, (bytes, bytearray)) or not pem.strip():
        raise UsageError("this is not a usable signing key: it is empty", "invalid_key")
    try:
        if b"PRIVATE KEY" in pem:
            private_key = serialization.load_pem_private_key(bytes(pem), password=None)
            return _describe(private_key.public_key(), private_key)
        return _describe(serialization.load_pem_public_key(bytes(pem)))
    except UsageError:
        raise
    except Exception:
        raise UsageError("this is not a usable signing key: it is not a PEM key, or it is encrypted", "invalid_key") from None


def _tagged_request_message(head, fields):
    """The fields both request signatures cover, newline-joined after ``head`` (the tag, and for the key pair
    the API key), as UTF-8 with no trailing newline.

    ``fields`` holds timestamp, method, path (no query; with the /v2 prefix if used), apiVersion (the
    x-api-version sent, or empty), passphrase, nonce, query (the raw text after "?") and body (the raw
    body as sent). Header values, the nonce and the query can't hold a raw newline; the body can, so it
    goes last.
    """
    parts = (
        *head,
        fields["timestamp"],
        fields["method"],
        fields["path"],
        fields.get("apiVersion") or "",
        fields["passphrase"],
        fields.get("nonce") or "",
        fields.get("query") or "",
        fields.get("body") or "",
    )
    return "\n".join(parts).encode("utf-8")


def hmac_v2_request_message(fields):
    """The string signed with the API secret for x-api-sign, version 2."""
    return _tagged_request_message((HMAC_V2_TAG,), fields)


def keypair_request_message(fields):
    """The string signed with the private key for x-api-keypair-sign: the tag, the x-api-key the request is
    sent with (``apiKey``), then the HMAC v2 fields. The API key is in it because two API keys may hold the
    same public key: a request signed for one is then refused under the other.

    :raises UsageError: the API key is not one line of text (empty, or holding a carriage return or newline)
    """
    api_key = fields.get("apiKey")
    if not isinstance(api_key, str) or not api_key or "\r" in api_key or "\n" in api_key:
        raise UsageError("the API key must be one line of text")
    return _tagged_request_message((REQUEST_TAG, api_key), fields)


def decode_api_secret(api_secret):
    """The HMAC key of an API secret.

    Only standard base64 is taken (padding optional), decoding to at least one byte; anything else is
    refused rather than decoded leniently, so every language derives the same key from the same text or
    refuses it.

    :raises UsageError: code ``invalid_api_secret``; the message never contains the secret
    """
    message = "the API secret must be the base64 text the dashboard shows"
    if not isinstance(api_secret, str) or not api_secret or not _API_SECRET_SHAPE.fullmatch(api_secret):
        raise UsageError(message, "invalid_api_secret")
    try:
        key = base64.b64decode(api_secret + "=" * (-len(api_secret) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise UsageError(message, "invalid_api_secret") from None
    if not key:
        raise UsageError(message, "invalid_api_secret")
    return key


def hmac_v2_signature(api_secret, fields):
    """x-api-sign, version 2: base64 HMAC-SHA256 keyed with the decoded API secret over the v2 string."""
    digest = hmac.new(decode_api_secret(api_secret), hmac_v2_request_message(fields), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def _require_credentials(credentials):
    for name in ("apiKey", "passphrase"):
        value = credentials.get(name)
        if not isinstance(value, str) or not value:
            raise UsageError("the {} is missing".format(name))
    decode_api_secret(credentials.get("apiSecret"))


def _request_fields(passphrase, request):
    fields = dict(request)
    fields["timestamp"] = request.get("timestamp") or str(int(time.time()))
    fields["nonce"] = request.get("nonce") or os.urandom(16).hex()
    if not NONCE_PATTERN.fullmatch(fields["nonce"]):
        raise UsageError("the nonce must be 1 to 128 printable ASCII characters without spaces")
    fields["passphrase"] = passphrase
    return fields


def sign_hmac_v2_request(credentials, request):
    """The authentication headers of one request signed with the API secret only (HMAC v2).

    For an API key without a request-signing key pair. A fresh nonce and the current time are used unless
    given, so the gateway's replay protection can tell a resend from a new request.

    :param credentials: a mapping with ``apiKey``, ``apiSecret`` and ``passphrase``
    :param request: a mapping with ``method``, ``path`` and optionally ``query``, ``body``, ``apiVersion``,
        ``timestamp`` and ``nonce``
    :returns: dict of header name → value
    """
    _require_credentials(credentials)
    fields = _request_fields(credentials["passphrase"], request)
    headers = {
        API_HEADERS["api_key"]: credentials["apiKey"],
        API_HEADERS["passphrase"]: credentials["passphrase"],
        API_HEADERS["timestamp"]: fields["timestamp"],
        API_HEADERS["sign"]: hmac_v2_signature(credentials["apiSecret"], fields),
        API_HEADERS["sign_version"]: "2",
        API_HEADERS["nonce"]: fields["nonce"],
    }
    if request.get("apiVersion"):
        headers[API_HEADERS["api_version"]] = request["apiVersion"]
    return headers


def _sign_message(key, message):
    if not isinstance(key, SigningKey) or key.private_key is None:
        raise TypeError("key must be a private key read by read_signing_key")
    if key.algorithm == ED25519:
        signature = key.private_key.sign(message)
    else:
        signature = key.private_key.sign(message, _ECDSA_SHA256)
    return base64.b64encode(signature).decode("ascii")


def sign_api_request(key, credentials, request):
    """The authentication headers of one request signed both ways: HMAC v2 and the key pair.

    :param key: a private key from read_signing_key
    :returns: dict of header name → value, with x-api-keypair-sign and x-api-keypair-id
    """
    if not isinstance(key, SigningKey) or key.private_key is None:
        raise TypeError("key must be a private key read by read_signing_key")
    _require_credentials(credentials)
    fields = _request_fields(credentials["passphrase"], request)
    headers = sign_hmac_v2_request(credentials, fields)
    api_version = headers.pop(API_HEADERS["api_version"], None)
    message = keypair_request_message(dict(fields, apiKey=credentials["apiKey"]))
    headers[API_HEADERS["keypair_sign"]] = _sign_message(key, message)
    headers[API_HEADERS["keypair_id"]] = key.fingerprint
    if api_version is not None:
        headers[API_HEADERS["api_version"]] = api_version
    return headers


def verify_message(key, message, signature_text):
    """Verifies a signature the way the gateway does: canonical padded base64, Ed25519 exactly 64 bytes,
    P-256 DER only (IEEE P1363 r||s, and DER OpenSSL would not write that way, refused)."""
    signature = _strict_base64(signature_text)
    if signature is None:
        return False
    try:
        if key.algorithm == ED25519:
            if len(signature) != 64:
                return False
            key.public_key.verify(signature, message)
        else:
            key.public_key.verify(signature, message, _ECDSA_SHA256)
    except Exception:
        return False
    return True


def verify_keypair_request(registered_keys, fields, keypair_id, keypair_sign):
    """Checks x-api-keypair-sign the way the gateway does: over the request as received, under the x-api-key it
    was received with (``apiKey`` in ``fields``).

    :returns: ``{"valid": True}`` or ``{"valid": False, "reason": "unknown_api_keypair_id" | "invalid_api_keypair_sign"}``
    """
    key = next((candidate for candidate in registered_keys if candidate.fingerprint == keypair_id), None)
    if key is None:
        return {"valid": False, "reason": "unknown_api_keypair_id"}
    if verify_message(key, keypair_request_message(fields), keypair_sign):
        return {"valid": True}
    return {"valid": False, "reason": "invalid_api_keypair_sign"}


def _der_integer(data):
    start = 0
    while start < len(data) - 1 and data[start] == 0:
        start += 1
    body = data[start:]
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes((0x02, len(body))) + body


def p1363_to_der(signature):
    """A P-256 signature as IEEE P1363 (r || s, 32 bytes each) in the DER form the gateway requires.

    Web Crypto, Azure Key Vault and some KMS APIs return P1363.

    :param signature: exactly 64 bytes
    :returns: DER SEQUENCE { INTEGER r, INTEGER s }
    :raises SignatureFormatError: ``invalid_length`` unless 64 bytes; ``zero_integer`` when r or s is zero
    """
    if not isinstance(signature, (bytes, bytearray, memoryview)) or len(signature) != _P1363_SIGNATURE_BYTES:
        raise SignatureFormatError("invalid_length", "a P1363 P-256 signature is 64 bytes")
    data = bytes(signature)
    r, s = data[:32], data[32:]
    if not any(r) or not any(s):
        raise SignatureFormatError("zero_integer", "r and s of a signature are never zero")
    body = _der_integer(r) + _der_integer(s)
    return bytes((0x30, len(body))) + body


def _parse_json(body, status):
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise UnexpectedResponseError(
            "the API answered {} with a body that is not JSON".format(status), status=status
        ) from None


def read_signing_keys_response(status, body, fingerprint):
    """Reads a verified answer of GET /api-keys/current/signing-keys.

    No I/O: verify the response signature first (test-vectors/signing-keys-v1.json).

    :param status: the HTTP status
    :param body: the raw body bytes (``str`` is taken as UTF-8)
    :param fingerprint: the fingerprint of the key that signed the request
    :returns: dict with ``outcome`` (``active``, ``inactive``, ``not_listed`` or ``refused``), ``status``,
        ``request_id``, ``keys`` (each with fingerprint, algorithm, status, createdTimestamp,
        approvedTimestamp) and ``error`` (``{"code", "message"}`` for a refusal, else None)
    :raises UnexpectedResponseError: an answer that is neither the list nor a refusal
    """
    if isinstance(body, str):
        body = body.encode("utf-8")
    body = bytes(body)
    result = {"fingerprint": fingerprint, "status": status, "request_id": None, "keys": [], "error": None}

    if status in (401, 403):
        parsed = _parse_json(body, status)
        error = parsed.get("error") if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict) else {}
        result["request_id"] = parsed.get("requestId") if isinstance(parsed, dict) and isinstance(parsed.get("requestId"), str) else None
        result["error"] = {
            "code": error["code"] if isinstance(error.get("code"), str) else "unknown",
            "message": error["message"] if isinstance(error.get("message"), str) else "",
        }
        result["outcome"] = "refused"
        return result

    if status != 200:
        code = None
        request_id = None
        try:
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict):
                if isinstance(parsed.get("error"), dict) and isinstance(parsed["error"].get("code"), str):
                    code = parsed["error"]["code"]
                if isinstance(parsed.get("requestId"), str):
                    request_id = parsed["requestId"]
        except (UnicodeDecodeError, ValueError):
            pass  # not JSON: the status says enough
        raise UnexpectedResponseError(
            "the API answered {}{}".format(status, " ({})".format(code) if code else ""),
            status=status,
            request_id=request_id,
            code=code,
        )

    parsed = _parse_json(body, status)
    data = parsed.get("data") if isinstance(parsed, dict) else None
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise UnexpectedResponseError("the API answered 200 without a list of signing keys", status=status)
    result["request_id"] = parsed["requestId"] if isinstance(parsed.get("requestId"), str) else None
    result["keys"] = [
        {
            "fingerprint": str(item.get("fingerprint")),
            "algorithm": str(item.get("algorithm")),
            "status": str(item.get("status")),
            "createdTimestamp": item.get("createdTimestamp"),
            "approvedTimestamp": item.get("approvedTimestamp"),
        }
        for item in items
        if isinstance(item, dict)
    ]
    listed = next((item for item in result["keys"] if item["fingerprint"] == fingerprint), None)
    if listed is None:
        result["outcome"] = "not_listed"
    else:
        result["outcome"] = "active" if listed["status"] == ACTIVE else "inactive"
    return result


__all__ = [
    "ALGORITHMS",
    "API_HEADERS",
    "ED25519",
    "FINGERPRINT_PREFIX",
    "HMAC_V2_TAG",
    "NONCE_PATTERN",
    "P256",
    "REQUEST_TAG",
    "SignatureFormatError",
    "SigningKey",
    "UnexpectedResponseError",
    "UsageError",
    "decode_api_secret",
    "fingerprint_of",
    "hmac_v2_request_message",
    "hmac_v2_signature",
    "keypair_request_message",
    "p1363_to_der",
    "read_signing_key",
    "read_signing_keys_response",
    "sign_api_request",
    "sign_hmac_v2_request",
    "verify_keypair_request",
    "verify_message",
]
