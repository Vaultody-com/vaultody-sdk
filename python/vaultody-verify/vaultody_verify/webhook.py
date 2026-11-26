"""Checks the X-Signature Vaultody puts on every webhook delivery.

The signature is the lowercase hex HMAC-SHA256, keyed with the webhook's signing secret (UTF-8), over the
raw body bytes (test-vectors/webhook-v1.json). The scheme has no timestamp, and Vaultody may deliver the
same event more than once, so a valid signature does not prove a delivery is new: before acting on an event,
check whether it was acted on already, keyed on what the event is about (the docs' Webhook Notifications page
names the fields). Several secrets can be given, to keep accepting deliveries while a secret is rotated.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass

from .errors import ConfigurationError, VaultodyVerifyError

SIGNATURE_HEADER = "x-signature"
# Exactly what the signer writes: no prefix, no whitespace, lowercase (fullmatch).
_SIGNATURE_FORMAT = re.compile(r"[0-9a-f]{64}")

_REASON_TEXT = {
    "missing": "the delivery has no X-Signature header, or an empty one",
    "malformed": "X-Signature must be one value of 64 lowercase hex characters",
    "mismatch": "no configured secret produces this signature over the body received",
}


class WebhookSignatureError(VaultodyVerifyError):
    """A delivery's signature does not check out; treat its body as untrusted. ``reason`` says why."""

    REASONS = tuple(_REASON_TEXT)

    def __init__(self, reason):
        if reason not in _REASON_TEXT:
            raise ValueError("unknown webhook signature failure reason: {!r}".format(reason))
        super().__init__(reason)
        self.reason = reason

    def __str__(self):
        return "{}: {}".format(self.reason, _REASON_TEXT[self.reason])


@dataclass(frozen=True)
class WebhookVerification:
    """A delivery whose signature checked out: ``secret_index`` is the first configured secret that matched."""

    valid: bool
    secret_index: int


def _signature_header(headers):
    if headers is None or not hasattr(headers, "items"):
        raise TypeError("headers must be the request headers, a dict or any Mapping")
    values = []
    for key, value in headers.items():
        if not (isinstance(key, str) and key.isascii() and key.lower() == SIGNATURE_HEADER) or value is None:
            continue
        values.extend(value if isinstance(value, (list, tuple)) else [value])
    if not values or all(value == "" for value in values):
        raise WebhookSignatureError("missing")
    if len(values) > 1 or not isinstance(values[0], str) or not _SIGNATURE_FORMAT.fullmatch(values[0]):
        raise WebhookSignatureError("malformed")
    return bytes.fromhex(values[0])


def _read_secrets(secrets):
    candidates = [secrets] if isinstance(secrets, str) else secrets
    if not isinstance(candidates, (list, tuple)) or not candidates or not all(
        isinstance(secret, str) and secret for secret in candidates
    ):
        raise ConfigurationError(
            "the webhook signing secret must be a non-empty string, or a non-empty list of them during a rotation"
        )
    return list(candidates)


def verify_webhook_signature(raw_body, headers, secrets):
    """Verifies one webhook delivery before its body is parsed.

    :param raw_body: the body exactly as received, ``bytes`` (``str`` is taken as UTF-8); never parsed JSON
    :param headers: the request headers, a dict or any Mapping; X-Signature is matched case-insensitively
    :param secrets: the signing secret, or the secrets accepted during a rotation, in order
    :returns: WebhookVerification(valid=True, secret_index=...)
    :raises WebhookSignatureError: the signature is missing, malformed or matches no secret
    :raises ConfigurationError: no usable secret is configured
    :raises TypeError: a body that is not bytes or str
    """
    candidates = _read_secrets(secrets)
    if isinstance(raw_body, str):
        body = raw_body.encode("utf-8")
    elif isinstance(raw_body, (bytes, bytearray, memoryview)):
        body = bytes(raw_body)
    else:
        raise TypeError("raw_body must be the raw body bytes (or str); verify the delivery before parsing it as JSON")
    received = _signature_header(headers)

    # Every secret is tried, so the time taken does not tell which one matched.
    secret_index = -1
    for index, secret in enumerate(candidates):
        expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
        if hmac.compare_digest(expected, received) and secret_index == -1:
            secret_index = index
    if secret_index == -1:
        raise WebhookSignatureError("mismatch")
    return WebhookVerification(valid=True, secret_index=secret_index)


__all__ = ["SIGNATURE_HEADER", "WebhookSignatureError", "WebhookVerification", "verify_webhook_signature"]
