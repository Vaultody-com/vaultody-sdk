"""Webhook deliveries: check X-Signature on the raw body, then read the event.

    event = vaultody_sdk.webhooks.verify(raw_body, request.headers, [new_secret, old_secret])

The signature is checked before the body is parsed, against each secret given (several cover a rotation),
in constant time (vaultody_verify.verify_webhook_signature, test-vectors/webhook-v1.json). Only raw bytes
are taken: a body already parsed as JSON and serialised again is not what was signed.

The scheme has no timestamp, and Vaultody may deliver the same event more than once, so a valid signature
does not prove a delivery is new. Before acting on an event, check whether you already acted on it, keyed
on what the event is about, as the Webhook Notifications page of the docs says: for outgoing transaction
events ``item["requestId"]`` and ``event``; for incoming ones ``item["transactionId"]``, ``item["address"]``,
``event`` and ``item["currentConfirmations"]`` (an internal transfer has no ``transactionId``: use
``parentTransactionId`` and ``operationId`` in its place). The SDK stores nothing. ``headers`` is taken
whole so a future timestamped signature header fits without a change to this call.
"""

import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional

from vaultody_verify import WebhookSignatureError as _VerifyWebhookSignatureError
from vaultody_verify import verify_webhook_signature

from .errors import WebhookPayloadError, WebhookSignatureError

OUTGOING_EVENTS = frozenset((
    "TRANSACTION_REQUEST",
    "TRANSACTION_APPROVED",
    "TRANSACTION_REJECTED",
    "TRANSACTION_BROADCASTED",
    "OUTGOING_MINED",
    "OUTGOING_MINED_WITH_ERRORS",
    "OUTGOING_FAILED",
))
INCOMING_EVENTS = frozenset((
    "INCOMING_MINED_TX",
    "INCOMING_CONFIRMED_COIN_TX",
    "INCOMING_CONFIRMED_TOKEN_TX",
    "INCOMING_CONFIRMED_INTERNAL_TX",
))
#: A deposit already reported was removed from the chain by a reorganisation (opt-in; final for that deposit).
REVERTED_EVENT = "INCOMING_TX_REVERTED"


@dataclass(frozen=True)
class WebhookEvent:
    """One verified delivery.

    ``event`` is ``data.event``; ``item`` is ``data.item`` as sent (unknown fields kept, amounts as
    strings); ``vault_id`` is the payload's ``walletId``. ``secret_index`` says which configured secret
    matched. ``raw`` is the whole parsed payload.
    """

    event: str
    item: Mapping[str, Any]
    vault_id: Optional[str]
    webhook_id: Optional[str]
    idempotency_key: Optional[str]
    api_version: Optional[str]
    secret_index: int
    raw: Mapping[str, Any] = field(repr=False)

    @property
    def known(self) -> bool:
        return True


class OutgoingTransactionEvent(WebhookEvent):
    """A transaction request of yours moved on: TRANSACTION_REQUEST ... OUTGOING_FAILED."""


class IncomingTransactionEvent(WebhookEvent):
    """A deposit to one of your addresses: INCOMING_MINED_TX and the INCOMING_CONFIRMED_* events."""


class IncomingTransactionRevertedEvent(WebhookEvent):
    """INCOMING_TX_REVERTED: a deposit reported earlier is no longer on the chain (a reorganisation).

    ``inclusion`` is the item's block inclusion details, when the payload carries them.
    """

    @property
    def inclusion(self) -> Optional[Mapping[str, Any]]:
        value = self.item.get("inclusion")
        return value if isinstance(value, Mapping) else None


class UnknownWebhookEvent(WebhookEvent):
    """An event this SDK version does not know yet: verified all the same, returned as is."""

    @property
    def known(self) -> bool:
        return False


def _class_of(event):
    if event in OUTGOING_EVENTS:
        return OutgoingTransactionEvent
    if event in INCOMING_EVENTS:
        return IncomingTransactionEvent
    if event == REVERTED_EVENT:
        return IncomingTransactionRevertedEvent
    return UnknownWebhookEvent


def _text(value):
    return value if isinstance(value, str) else None


def verify(raw_body, headers, secrets):
    """Verifies one delivery and returns its event.

    :param raw_body: the request body exactly as received, bytes (str is taken as UTF-8)
    :param headers: the request headers, any mapping; X-Signature is matched case-insensitively
    :param secrets: the webhook's signing secret, or a list of them during a rotation
    :returns: a WebhookEvent subclass: OutgoingTransactionEvent, IncomingTransactionEvent,
        IncomingTransactionRevertedEvent or UnknownWebhookEvent
    :raises WebhookSignatureError: ``missing``, ``malformed`` or ``mismatch``; the body was not parsed
    :raises WebhookPayloadError: the signature checked out but the body is not a Vaultody event
    :raises vaultody_verify.ConfigurationError: no usable secret
    """
    try:
        verification = verify_webhook_signature(raw_body, headers, secrets)
    except _VerifyWebhookSignatureError as error:
        raise WebhookSignatureError(error.reason) from None
    body = raw_body.encode("utf-8") if isinstance(raw_body, str) else bytes(raw_body)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebhookPayloadError("the delivery is not JSON") from None
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("event"), str) or not data["event"]:
        raise WebhookPayloadError("the delivery has no data.event")
    item = data.get("item")
    if item is None:
        item = {}
    if not isinstance(item, dict):
        raise WebhookPayloadError("the delivery's data.item is not an object")
    return _class_of(data["event"])(
        event=data["event"],
        item=MappingProxyType(item),
        vault_id=_text(payload.get("walletId")),
        webhook_id=_text(payload.get("webhookId")),
        idempotency_key=_text(payload.get("idempotencyKey")),
        api_version=_text(payload.get("apiVersion")),
        secret_index=verification.secret_index,
        raw=MappingProxyType(payload),
    )


class Webhooks:
    """``client.webhooks``: the same ``verify``; it needs no network, so it is the same on both clients."""

    verify = staticmethod(verify)

    def __repr__(self):
        return "Webhooks()"


__all__ = [
    "INCOMING_EVENTS",
    "OUTGOING_EVENTS",
    "REVERTED_EVENT",
    "IncomingTransactionEvent",
    "IncomingTransactionRevertedEvent",
    "OutgoingTransactionEvent",
    "UnknownWebhookEvent",
    "WebhookEvent",
    "WebhookSignatureError",
    "Webhooks",
    "verify",
]
