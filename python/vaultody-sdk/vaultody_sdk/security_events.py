"""The security events the client hands to ``on_security_event``: their names and fields, the same in every
language (test-vectors/security-events-v1.json). An event never carries a secret, an xpub or an address."""

from typing import Any, Dict, Mapping, Tuple

SECURITY_EVENTS: Dict[str, Tuple[str, ...]] = {
    "unsigned_response_accepted": ("type", "origin", "operationId"),
    "response_signature_latched": ("type", "origin", "rootId", "latchedAt"),
    "response_verification_failed": ("type", "origin", "operationId", "status", "reason"),
    "vault_key_pinned": ("type", "origin", "vaultId", "status"),
    "vault_key_verified": ("type", "origin", "vaultId", "status"),
    "vault_key_changed": ("type", "origin", "alarms"),
    "address_verification_failed": ("type", "origin", "operationId", "vaultId", "code"),
}


def security_event(data: Mapping[str, Any]) -> Dict[str, Any]:
    """The event of a type with exactly its fields, in the catalogue's order; a field not given is None.

    A type or a field that is not in the catalogue is a mistake in the SDK and raises TypeError, so no event
    can grow or rename a field the other languages don't send (every place that raises an event runs in the
    tests).
    """
    kind = data.get("type")
    fields = SECURITY_EVENTS.get(kind) if isinstance(kind, str) else None
    if fields is None:
        raise TypeError("no security event {!r}".format(data.get("type")))
    extra = [name for name in data if name not in fields]
    if extra:
        raise TypeError("{} has no field {}".format(data["type"], ", ".join(extra)))
    return {name: data.get(name) for name in fields}


__all__ = ["SECURITY_EVENTS", "security_event"]
