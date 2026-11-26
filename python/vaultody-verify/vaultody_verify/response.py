"""Verification of signed Vaultody API responses, wire format v1.

Cloudflare terminates TLS in front of the Vaultody API, so TLS alone doesn't prove a response came
from Vaultody unchanged. The API gateway signs every response instead:

- A P-256 root key that never leaves a hardware security module signs a short-lived certificate (an hour
  at most) for each gateway pod's own Ed25519 key (``x-api-response-cert``).
- The pod signs each response with that key (``x-api-response-sign``). The signed message binds the
  response (status, body bytes, time) to the request it answers (method, path, query, a hash of the
  request body, the client's own ``x-api-sign`` and its ``x-api-keypair-sign``), so a genuine response
  can't be moved onto a different request.

This module checks the certificate against the pinned roots and then the response. Every field has
exactly one accepted spelling and anything else is refused, never normalised, so this verifier and the
gateway (and the Node helper) always agree on the bytes.
"""

import base64
import hashlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import roots as _roots
from .errors import ResponseSignatureError

SIGN_VERSION = "1"
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300
# The longest a gateway certificate may be valid. A fixed rule, not an option: a looser value would let a
# certificate the root signed by mistake be used for years.
MAX_CERT_LIFETIME_SECONDS = 3600

HEADER_SIGN = "x-api-response-sign"
HEADER_TIMESTAMP = "x-api-response-timestamp"
HEADER_VERSION = "x-api-response-sign-version"
HEADER_CERT = "x-api-response-cert"

# Checked in this order, so the reason for a response with several problems is the same in every helper.
_HEADERS = (HEADER_SIGN, HEADER_TIMESTAMP, HEADER_VERSION, HEADER_CERT)

_CERT_TAG = "vaultody-response-key-v1"
_MESSAGE_TAG = "vaultody-response-v1"
_CERT_LINES = 6

# Signed in place of the request body hash when the gateway didn't read the whole request body (too large,
# or the client aborted). Such a response is authentic but not bound to the body the client sent.
_UNREAD_BODY = "unread"

# The largest integer every verifier language holds exactly (JavaScript numbers stop at 2^53 - 1), so a
# decimal past it is refused rather than compared with rounding in one language and not another.
_MAX_SECONDS = 2 ** 53 - 1
_MAX_SECONDS_DIGITS = len(str(_MAX_SECONDS))

# Patterns are always used with fullmatch: Python's "$" would also accept a trailing newline.
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")
_ROOT_ID = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[0-9a-f]{32}")
_CERT_TEXT = re.compile(r"[\x20-\x7e\n]+")
# Request fields come from the request line and headers. The gateway signs them only as printable ASCII,
# which also rules out a newline moving text into the next field of the message.
_REQUEST_FIELD = re.compile(r"[\x20-\x7e]*")

_ECDSA_SHA256 = ec.ECDSA(hashes.SHA256())


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of a verification that didn't raise.

    ``verified`` is True when the response is signed and checks out. It is False only in non-strict mode
    for a response without any signature headers; ``reason`` is then ``"missing"`` and the other fields
    are None.
    """

    verified: bool
    reason: Optional[str] = None
    key_id: Optional[str] = None
    root_id: Optional[str] = None
    timestamp: Optional[int] = None


def _strict_base64(text):
    """Standard padded base64, accepted only in the exact spelling an encoder writes.

    Lenient decoders skip unknown characters, missing padding and stray bits past the data, which would
    let two different header values carry the same bytes; the shape check plus the round trip refuse all
    of those.
    """
    if not text or not _BASE64.fullmatch(text):
        return None
    data = base64.b64decode(text)
    if base64.b64encode(data).decode("ascii") != text:
        return None
    return data


def _strict_seconds(text):
    """A canonical decimal: ASCII digits only, no sign, no leading zero, at most 2^53 - 1."""
    # The length check comes first because int() refuses very long digit strings with a ValueError
    # on recent Pythons, which must surface as "invalid" and not as a crash.
    if len(text) > _MAX_SECONDS_DIGITS or not _DECIMAL.fullmatch(text):
        return None
    value = int(text)
    return value if value <= _MAX_SECONDS else None


def _header_values(headers, name):
    """Every value of one header, its name matched case-insensitively.

    Works with a dict, any Mapping, ``requests``' CaseInsensitiveDict and ``http.client.HTTPMessage``.
    Repeated headers come back as several values (or, from clients that join them, as one value with
    ", " in it); either way the checks further on refuse them.
    """
    if headers is None:
        return []
    return [
        value
        for key, value in headers.items()
        if isinstance(key, str) and key.isascii() and key.lower() == name and value is not None
    ]


def _as_bytes(body, what):
    if body is None:
        return b""
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    raise TypeError("{} must be bytes, str or None, not {}".format(what, type(body).__name__))


def _required(mapping, key, what):
    if not isinstance(mapping, Mapping):
        raise TypeError("{} must be a mapping".format(what))
    if key not in mapping:
        raise TypeError("{} is missing {!r}".format(what, key))
    return mapping[key]


def _fail(reason, detail):
    return ResponseSignatureError(reason, detail)


def verify_response(
    request,
    response,
    *,
    require_response_signature=True,
    roots=None,
    now=None,
    max_clock_skew_seconds=DEFAULT_MAX_CLOCK_SKEW_SECONDS,
):
    """Checks that a response was signed by the Vaultody API gateway, unchanged, for this request.

    :param request: the request exactly as sent, a mapping with

        - ``method``: e.g. ``"POST"``;
        - ``url``: the path and query as sent on the wire, e.g. ``"/vaults/abc/addresses?limit=10"``.
          Not a full URL; percent-encoding exactly as sent. The path is everything before the first
          ``?``, the query everything after it;
        - ``body``: the request body bytes as sent (``str`` is taken as UTF-8; None or absent for none);
        - ``api_sign``: the ``x-api-sign`` header sent, or None/absent;
        - ``keypair_sign``: the ``x-api-keypair-sign`` header sent, or None/absent.
    :param response: the response as received, a mapping with ``status`` (int), ``headers`` (a dict or
        any Mapping; names are matched case-insensitively) and ``body`` (the raw bytes, before any JSON
        parsing; ``str`` is taken as UTF-8).
    :param require_response_signature: strict mode (the default) raises for a response without
        signature headers. With False, a response with none of the four headers returns
        ``VerificationResult(verified=False, reason="missing")``; anything else is still checked in full.
    :param roots: the roots to trust instead of the embedded ones: a list of SubjectPublicKeyInfo PEM
        (str or bytes), DER bytes or EC public keys (or a mapping whose values are those).
    :param now: the current time in Unix seconds, for tests; defaults to the system clock.
    :param max_clock_skew_seconds: how far the local clock may run past the certificate's end.
    :returns: VerificationResult
    :raises ResponseSignatureError: the response is not proven to be genuine; ``.reason`` says why.
    :raises ConfigurationError: a given root is unusable, or the response is signed and no roots are
        configured. An unsigned response needs no root.
    """
    # Parsed now, so a malformed root is reported at once. A root is required only once the response turns
    # out to be signed (step 2), so an unsigned response in non-strict mode needs none.
    parsed_roots = _roots.parse_roots(roots)

    method = _required(request, "method", "request")
    url = _required(request, "url", "request")
    if not isinstance(method, str) or not isinstance(url, str):
        raise TypeError("request method and url must be str")
    if not url.startswith("/"):
        raise ValueError("request url must be the path and query as sent (starting with '/'), not a full URL")
    path, _, query = url.partition("?")
    api_sign = request.get("api_sign")
    if api_sign is None:
        api_sign = ""
    if not isinstance(api_sign, str):
        raise TypeError("request api_sign must be str or None")
    keypair_sign = request.get("keypair_sign")
    if keypair_sign is None:
        keypair_sign = ""
    if not isinstance(keypair_sign, str):
        raise TypeError("request keypair_sign must be str or None")
    request_body = _as_bytes(request.get("body"), "request body")

    status = _required(response, "status", "response")
    if not isinstance(status, int) or isinstance(status, bool):
        raise TypeError("response status must be an int")
    headers = _required(response, "headers", "response")
    if headers is not None and not hasattr(headers, "items"):
        raise TypeError("response headers must be a mapping")
    response_body = _as_bytes(response.get("body"), "response body")

    if now is None:
        now = int(time.time())
    for name, value in (("now", now), ("max_clock_skew_seconds", max_clock_skew_seconds)):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError("{} must be a number of seconds".format(name))
    if max_clock_skew_seconds < 0:
        raise ValueError("max_clock_skew_seconds must not be negative")

    # 1. The four headers, then the version.
    found = {name: _header_values(headers, name) for name in _HEADERS}
    if all(value == "" for values in found.values() for value in values):
        # Only a response with no signature at all may pass unverified, and only when the caller opted
        # out of strict mode (for example while response signing is being rolled out). A response with
        # some of the headers stripped is treated as tampered with in both modes.
        if not require_response_signature:
            return VerificationResult(verified=False, reason="missing")
        raise _fail("missing", "the response carries no signature headers")
    raw = {}
    for name in _HEADERS:
        values = found[name]
        if not values or values[0] == "":
            raise _fail("missing", "{} is absent or empty".format(name))
        if len(values) > 1 or not isinstance(values[0], str):
            raise _fail("invalid", "{} appears more than once or is not text".format(name))
        raw[name] = values[0]

    if raw[HEADER_VERSION] != SIGN_VERSION:
        raise _fail("unsupported_version", "{} is not {!r}".format(HEADER_VERSION, SIGN_VERSION))

    # 2. Find the root the certificate names and check its signature over the certificate bytes. Only the
    # tag and the rootId are read before that; the rest is parsed only once the root vouches for it.
    cert_parts = raw[HEADER_CERT].split(".")
    if len(cert_parts) != 2:
        raise _fail("invalid", "{} is not two base64 parts joined by '.'".format(HEADER_CERT))
    cert_bytes = _strict_base64(cert_parts[0])
    root_signature = _strict_base64(cert_parts[1])
    if cert_bytes is None or root_signature is None or any(byte > 0x7F for byte in cert_bytes):
        raise _fail("invalid", "{} is not canonical base64 of an ASCII certificate".format(HEADER_CERT))
    cert_text = cert_bytes.decode("ascii")
    lines = cert_text.split("\n")
    if lines[0] != _CERT_TAG or len(lines) < 2 or not _ROOT_ID.fullmatch(lines[1]):
        raise _fail("invalid", "the certificate has an unknown tag or a malformed rootId")

    # The roots are looked up only now that the response carries a signature: with none configured, a signed
    # response fails closed here, while an unsigned one was decided above without them.
    pinned = _roots.require_roots(parsed_roots)
    root = next((candidate for candidate in pinned if candidate.root_id == lines[1]), None)
    if root is None:
        raise _fail("unknown_root", "the certificate names root {}, which is not pinned".format(lines[1]))

    try:
        root.public_key.verify(root_signature, cert_bytes, _ECDSA_SHA256)
    except Exception:  # InvalidSignature, or a signature too malformed to parse: either way not genuine
        raise _fail("invalid", "the root signature does not verify over the certificate") from None

    # 3. The certificate must be in its one canonical form, its keyId matching its key, and valid for at most
    # an hour: a longer one is refused whatever its window says.
    if len(lines) != _CERT_LINES or not _CERT_TEXT.fullmatch(cert_text):
        raise _fail("invalid", "the certificate is not exactly six printable ASCII lines")
    pod_public_key = _strict_base64(lines[2])
    if pod_public_key is None or len(pod_public_key) != 32:
        raise _fail("invalid", "the certificate public key is not canonical base64 of 32 bytes")
    key_id = lines[3]
    if not _KEY_ID.fullmatch(key_id) or key_id != hashlib.sha256(pod_public_key).hexdigest()[:32]:
        raise _fail("invalid", "the certificate keyId does not match its public key")
    not_before = _strict_seconds(lines[4])
    not_after = _strict_seconds(lines[5])
    if not_before is None or not_after is None:
        raise _fail("invalid", "the certificate validity is not canonical decimal seconds")
    if not_after - not_before > MAX_CERT_LIFETIME_SECONDS:
        raise _fail("invalid", "the certificate is valid for more than {} seconds".format(MAX_CERT_LIFETIME_SECONDS))

    # 4. The signature time must fall inside the certificate window, and the local clock must not be past
    # that window by more than the allowed skew. A pod keeps signing with an expired certificate when its
    # renewal fails, so this is what turns that into a rejection on the client.
    timestamp = _strict_seconds(raw[HEADER_TIMESTAMP])
    if timestamp is None:
        raise _fail("invalid", "{} is not canonical decimal seconds".format(HEADER_TIMESTAMP))
    if timestamp < not_before or timestamp > not_after or now > not_after + max_clock_skew_seconds:
        raise _fail("expired", "the response is outside its certificate's validity")

    # 5. The pod's Ed25519 signature over the message rebuilt from the request as sent and the response
    # as received.
    signature = _strict_base64(raw[HEADER_SIGN])
    if signature is None or len(signature) != 64:
        raise _fail("invalid", "{} is not canonical base64 of 64 bytes".format(HEADER_SIGN))
    try:
        pod_key = Ed25519PublicKey.from_public_bytes(pod_public_key)
    except Exception:
        raise _fail("invalid", "the certificate public key is not a usable Ed25519 key") from None

    for value in (method, path, query, api_sign, keypair_sign):
        if not _REQUEST_FIELD.fullmatch(value):
            raise _fail("invalid", "the request method, path, query, x-api-sign or x-api-keypair-sign is not printable ASCII")
    if method == "" or path == "":
        raise _fail("invalid", "the request method and path must not be empty")

    def verifies(body_hash):
        head = "\n".join(
            (_MESSAGE_TAG, raw[HEADER_TIMESTAMP], str(int(status)), method, path, query, body_hash, api_sign, keypair_sign)
        )
        try:
            pod_key.verify(signature, head.encode("ascii") + b"\n" + response_body)
        except Exception:
            return False
        return True

    if verifies(hashlib.sha256(request_body).hexdigest()):
        return VerificationResult(verified=True, key_id=key_id, root_id=root.root_id, timestamp=timestamp)
    # Tried only after the real hash fails: a genuine response whose request body the gateway never read.
    if verifies(_UNREAD_BODY):
        raise _fail("request_unbound", "the gateway did not read the request body, so the response is not bound to it")
    raise _fail("invalid", "the response signature does not verify for this request and response")


def verify_requests_response(resp, **options):
    """``verify_response`` for a ``requests.Response``.

    Uses what ``requests`` actually sent: ``resp.request.method``, ``resp.request.path_url`` (path and
    query after requests' own encoding), ``resp.request.body`` and the ``x-api-sign`` and
    ``x-api-keypair-sign`` request headers, with ``resp.status_code``, ``resp.headers`` and ``resp.content`` (the body bytes, Content-Encoding
    already removed). Keyword arguments are passed on to ``verify_response``.

    ``requests`` itself is never imported here; it is an optional extra.
    """
    sent = getattr(resp, "request", None)
    if sent is None:
        raise TypeError("expected a requests.Response with the request that produced it")

    body = sent.body
    if body is not None and not isinstance(body, (bytes, bytearray, memoryview, str)):
        # A file or generator has been consumed by the time the response arrives, so the bytes that were
        # sent are no longer known and the response can't be bound to them.
        raise TypeError("a streamed request body can't be verified afterwards; send it as bytes or str")

    def sent_header(name):
        value = sent.headers.get(name)
        return value.decode("latin-1") if isinstance(value, bytes) else value

    return verify_response(
        {
            "method": sent.method,
            "url": sent.path_url,
            "body": body,
            "api_sign": sent_header("x-api-sign"),
            "keypair_sign": sent_header("x-api-keypair-sign"),
        },
        {"status": resp.status_code, "headers": resp.headers, "body": resp.content},
        **options
    )
