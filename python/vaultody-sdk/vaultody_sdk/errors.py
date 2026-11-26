"""The errors the SDK raises, the same names in every language, and the reading of a response envelope
into a result or a typed error (test-vectors/envelope-errors-v1.json).

Callers branch on the class and on ``code``, never on ``message``.
"""

import json
from collections.abc import Mapping

from vaultody_verify import WebhookSignatureError as _VerifyWebhookSignatureError

# The two conflicts the docs say to retry at once: collisions with no side effect.
_RETRYABLE_CODES = frozenset(("address_derivation_conflict", "vault_accounts_creation_failed"))


class VaultodyError(Exception):
    """The base of every error the SDK raises on purpose."""


class ApiError(VaultodyError):
    """An answer the SDK can't return as a result: an error status, or a success it can't read.

    ``message`` is the API's own message (or None), written for people; never branch on it. ``details``
    exists only when the answer carried ``error.details``.
    """

    def __init__(self, status, code=None, message=None, request_id=None, api_version=None, replayed=False, **details):
        super().__init__(status, code, message)
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id
        self.api_version = api_version
        self.replayed = replayed
        self.retryable = code in _RETRYABLE_CODES
        if "details" in details:
            self.details = details["details"]

    def __str__(self):
        if self.message:
            return self.message
        return "Vaultody API answered {}{}".format(self.status, " " + self.code if self.code else "")

    def __reduce__(self):
        extra = {"details": self.details} if hasattr(self, "details") else {}
        return (_rebuild_api_error, (type(self), self.status, self.code, self.message, self.request_id, self.api_version, self.replayed, extra))


def _rebuild_api_error(cls, status, code, message, request_id, api_version, replayed, extra):
    return cls(status, code, message, request_id, api_version, replayed, **extra)


class AuthenticationError(ApiError):
    """401: the API key, signature or timestamp was refused."""


class RequestSigningError(ApiError):
    """The key-pair signature was required, missing or refused."""


class PermissionDeniedError(ApiError):
    """403: the key, plan, IP address or vault scope does not allow this."""


class NotFoundError(ApiError):
    """404."""


class InvalidRequestError(ApiError):
    """400, 415, 422, and the 409 validation codes: the request itself is wrong."""


class ConflictError(ApiError):
    """409: a business conflict."""


class DuplicateTransferError(ApiError):
    """409 double_spending: the same transfer was requested already."""


class RateLimitError(ApiError):
    """429."""


class ServerError(ApiError):
    """5xx."""


class RequestOutcomeUnknownError(VaultodyError):
    """A write may or may not have been carried out: it was sent, and its outcome could not be learned.

    Check with getTransactionRequestDetails or the dashboard before sending it again.
    """

    def __init__(self, in_progress=False, nonce=None, timestamp=None, request_id=None):
        super().__init__(
            "the request was received and is still being processed; its outcome is not known yet"
            if in_progress
            else "the request may or may not have been carried out; its outcome is not known"
        )
        self.in_progress = in_progress
        self.nonce = nonce
        self.timestamp = timestamp
        self.request_id = request_id


class TransportError(VaultodyError):
    """A network failure. ``sent`` is False only when the request certainly never left (transport_errors)."""

    def __init__(self, message, sent="unknown"):
        super().__init__(message)
        self.sent = sent


class ParameterError(VaultodyError):
    """Arguments of a call that can't be turned into a request. ``code`` says why; ``param`` names the
    field when the error is about one (``recipients[0].amount`` for a nested one). The value passed is
    never part of the error."""

    def __init__(self, code, message, param=None):
        super().__init__(message)
        self.code = code
        self.param = param


class PaginationError(VaultodyError):
    """A list that can't be paged through safely. ``code`` says why."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class VaultKeyChangedError(VaultodyError):
    """A vault's xpub differs from the one pinned, or a pinned one is gone.

    Each alarm names the vault, the algorithm, the reason and short hashes of both xpubs, never an xpub.
    """

    def __init__(self, alarms):
        names = ", ".join("vault {} ({})".format(alarm["vaultId"], alarm["algorithm"]) for alarm in alarms)
        super().__init__("the xpub of {} differs from the one pinned; nothing in the response was used".format(names))
        self.alarms = alarms


class AddressVerificationError(VaultodyError):
    """An address that is not proven to belong to its vault; nothing in the response was used.

    ``code``: ``mismatch`` (it does not derive from the pinned xpub, or differs from the address sent),
    ``network_mismatch``, ``missing_key``, ``unsupported`` (a blockchain, network or format the SDK can't
    derive), ``unknown_vault`` (the vault is in neither vault list) or ``invalid`` (malformed path fields).
    """

    def __init__(self, code, message, vault_id=None, address=None):
        super().__init__(message)
        self.code = code
        self.vault_id = vault_id
        self.address = address


class ConfigurationError(VaultodyError):
    """The client is set up wrong: credentials, base URL, roots, signer or the vault key store.

    It says nothing about a response; it is never retried.
    """

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class VaultKeyStoreError(ConfigurationError):
    """The vault key store can't be read, parsed or written. It is never treated as empty.

    ``code``, the same in every language (docs/vault-keys-file.md): a file that is refused is ``not_json``,
    ``unknown_format``, ``malformed``, ``insecure_permissions``, ``not_regular_file`` or ``too_large``; a
    file that can't be used is ``unreadable``, ``unwritable`` or ``locked``; a pin or latch handed to the
    store that the file could not hold is ``invalid_pin``.
    """


class SignerError(VaultodyError):
    """The request signer gave a signature that can't be sent: wrong length or encoding, or one that does
    not verify against the signer's own public key. ``code`` says why."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class ResponseVerificationError(VaultodyError):
    """A response failed its signature check: its body was not parsed and nothing of it was used.

    ``reason`` is vaultody_verify's: ``missing``, ``invalid``, ``expired``, ``unknown_root``,
    ``request_unbound`` or ``unsupported_version``. Never retried; the security event hook was called first.
    """

    def __init__(self, reason, message, status=None):
        super().__init__(message)
        self.reason = reason
        self.status = status


class WebhookSignatureError(VaultodyError, _VerifyWebhookSignatureError):
    """A webhook delivery's X-Signature does not check out: treat its body as untrusted and do not act on it.

    ``reason`` is ``missing``, ``malformed`` or ``mismatch``. A VaultodyError, as in Node and PHP; it is also
    the vaultody_verify.WebhookSignatureError it reports, so code that catches that one still does.
    """


class WebhookPayloadError(VaultodyError):
    """A webhook delivery whose signature checked out but whose body is not a Vaultody event."""


# The error class of a code, before the class of its status.
_CLASS_OF_CODE = {
    "api_keypair_required": RequestSigningError,
    "missing_api_keypair_sign": RequestSigningError,
    "missing_api_nonce": RequestSigningError,
    # The gateway's idempotency: the nonce was used before for a different request; never retried.
    "api_nonce_reused": RequestSigningError,
    "unknown_api_keypair_id": RequestSigningError,
    "invalid_api_keypair_sign": RequestSigningError,
    "invalid_api_key": AuthenticationError,
    "invalid_api_sign": AuthenticationError,
    "invalid_api_timestamp": AuthenticationError,
    "missing_authorization_header": AuthenticationError,
    "invalid_data": InvalidRequestError,
    "missing_required_attributes": InvalidRequestError,
    "extra_body_attributes": InvalidRequestError,
    "extra_query_attributes": InvalidRequestError,
    "invalid_api_version": InvalidRequestError,
    "double_spending": DuplicateTransferError,
}

_CLASS_OF_STATUS = {
    400: InvalidRequestError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    415: InvalidRequestError,
    422: InvalidRequestError,
    429: RateLimitError,
}


def error_class_for(status, code):
    """The ApiError class for a status and code: the code's class first, then the status's."""
    if code is not None and code in _CLASS_OF_CODE:
        return _CLASS_OF_CODE[code]
    if 500 <= status <= 599:
        return ServerError
    return _CLASS_OF_STATUS.get(status, ApiError)


def _header(headers, name):
    if headers is None:
        return None
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name:
            return value
    return None


def _string_or_none(value):
    return value if isinstance(value, str) else None


def _number_or_none(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def read_envelope(status, headers, body):
    """Reads an API response, already verified, into a result or a typed error.

    :param status: the HTTP status
    :param headers: the response headers, any Mapping; names matched case-insensitively
    :param body: the raw body (bytes; str is taken as UTF-8)
    :returns: a dict: ``{"kind": "item", "item", "api_version", "request_id", "context", "replayed"}`` or
        ``{"kind": "page", "paging": "cursor"|"offset", "items", "limit", "has_more", "starting_after"}``
        (cursor) / ``"offset", "total"`` (offset), with the same metadata
    :raises ApiError: an error status, or a success the SDK can't read
    """
    replayed = _header(headers, "x-api-replayed") == "true"
    text = body if isinstance(body, str) else bytes(body or b"").decode("utf-8", "replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    top = parsed if isinstance(parsed, dict) else {}
    meta = {
        "api_version": _string_or_none(top.get("apiVersion")),
        "request_id": _string_or_none(top.get("requestId")),
        "context": _string_or_none(top.get("context")),
        "replayed": replayed,
    }

    if 200 <= status <= 299:
        data = top.get("data") if isinstance(top.get("data"), dict) else None
        if data is not None and isinstance(data.get("item"), dict):
            return dict(kind="item", item=data["item"], **meta)
        if data is not None and isinstance(data.get("items"), list):
            limit = _number_or_none(data.get("limit"))
            if "offset" in data or "total" in data:
                return dict(
                    kind="page", paging="offset", items=data["items"], limit=limit,
                    offset=_number_or_none(data.get("offset")), total=_number_or_none(data.get("total")), **meta
                )
            return dict(
                kind="page", paging="cursor", items=data["items"], limit=limit,
                has_more=data.get("hasMore") is True, starting_after=_string_or_none(data.get("startingAfter")), **meta
            )
        raise ApiError(status, None, None, meta["request_id"], meta["api_version"], replayed)

    error = top.get("error") if isinstance(top.get("error"), Mapping) else {}
    code = _string_or_none(error.get("code"))
    extra = {"details": error["details"]} if "details" in error else {}
    raise error_class_for(status, code)(
        status, code, _string_or_none(error.get("message")), meta["request_id"], meta["api_version"], replayed, **extra
    )


__all__ = [
    "AddressVerificationError",
    "ApiError",
    "AuthenticationError",
    "ConfigurationError",
    "ConflictError",
    "DuplicateTransferError",
    "InvalidRequestError",
    "NotFoundError",
    "PaginationError",
    "ParameterError",
    "PermissionDeniedError",
    "RateLimitError",
    "RequestOutcomeUnknownError",
    "RequestSigningError",
    "ResponseVerificationError",
    "ServerError",
    "SignerError",
    "TransportError",
    "VaultKeyChangedError",
    "VaultKeyStoreError",
    "VaultodyError",
    "WebhookPayloadError",
    "error_class_for",
    "read_envelope",
]
