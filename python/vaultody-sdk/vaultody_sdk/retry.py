"""Whether and how to try a call again after one attempt, without I/O (test-vectors/retry-v1.json).

The rule that matters most: a write is never signed again with a new nonce once any attempt of it may
have reached the gateway, because the gateway's replay protection recognises a duplicate only by its
nonce. A resend of the same signed request is safe: within about 3 s the gateway answers it with the
first request's answer (x-api-replayed), later it refuses it (duplicate_api_request). Where the outcome
can't be learned, the caller gets RequestOutcomeUnknownError instead of a second transfer.

Every retry of a write keeps the call's x-api-nonce (and its body): a resend is the same signed request,
and a re-signed write gets a fresh x-api-timestamp and fresh signatures over the same nonce, so the
gateway's idempotency (per API key and nonce) always sees one
operation. One exception: the one immediate retry after address_derivation_conflict or
vault_accounts_creation_failed, which say that nothing was executed, is signed again with a new nonce and
the same body; with the same nonce the gateway would only replay the 409. Later retries of that call keep
the new nonce. A read re-signed gets a new nonce. ``nonce`` in a retry decision says which: ``same`` or
``new``.
"""

import math
from types import MappingProxyType

RETRY = MappingProxyType(
    {
        "maxAttempts": 5,
        "baseDelayMs": 1000,
        "maxDelayMs": 8000,
        "deadlineMs": 30000,
        # The gateway replays the first answer to a duplicate for 3 s; resend only well inside that.
        "resendWindowMs": 2500,
        # A signature is accepted for about 30 s (+10 s drift); a resend must arrive before that.
        "signatureMaxAgeMs": 25000,
    }
)

# The conflicts the docs say to retry at once: collisions with no side effect.
_CONFLICT_RETRY_CODES = frozenset(("address_derivation_conflict", "vault_accounts_creation_failed"))


def _server_error(status):
    return 500 <= status <= 599


def backoff_ms(attempt, random, retry_after_seconds=None):
    """Full jitter: a random delay up to min(cap, base × 2^(attempt − 1)), raised to a longer Retry-After."""
    ceiling = min(RETRY["maxDelayMs"], RETRY["baseDelayMs"] * 2 ** (attempt - 1))
    jitter = math.floor(random * ceiling)
    asked = retry_after_seconds * 1000 if isinstance(retry_after_seconds, (int, float)) and retry_after_seconds > 0 else 0
    return max(jitter, asked)


def decide_retry(attempt_result):
    """The decision after one attempt.

    :param attempt_result: a mapping with ``operation`` (``read`` | ``write``), ``keyMode`` (``keypair``
        only when the key pair was confirmed active, else ``legacy``), ``attempt`` (attempts made, this one
        included), ``elapsedMs``, ``signedAgeMs``, ``sinceFirstSendMs``, ``resends``, ``mayHaveRun``,
        ``conflictRetried``, ``random`` (a draw in [0, 1)) and ``outcome``: ``{"type": "not_sent" |
        "sent_unknown" | "verification_failed"}`` or ``{"type": "response", "status", "code", "replayed",
        "retryAfterSeconds"}``
    :returns: ``{"action": "return" | "fail"}``, ``{"action": "retry", "mode": "resign" | "resend",
        "nonce": "same" | "new", "delayMs"}`` or ``{"action": "outcome_unknown", "inProgress"}``
    """
    a = attempt_result
    outcome = a["outcome"]
    is_write = a["operation"] == "write"
    is_response = outcome["type"] == "response"
    status = outcome["status"] if is_response else None
    code = outcome.get("code") if is_response else None

    if outcome["type"] == "verification_failed":
        return {"action": "fail"}
    if is_response and 200 <= status <= 299:
        return {"action": "return"}

    this_may_have_run = outcome["type"] == "sent_unknown" or (is_response and _server_error(status))
    any_may_have_run = a["mayHaveRun"] or this_may_have_run

    def stop():
        # What happens when no (further) retry is made
        if is_write and any_may_have_run:
            return {"action": "outcome_unknown", "inProgress": False}
        return {"action": "return" if is_response else "fail"}

    def retry(mode, delay_ms, nonce=None):
        if a["attempt"] >= RETRY["maxAttempts"] or a["elapsedMs"] + delay_ms > RETRY["deadlineMs"]:
            return stop()
        if nonce is None:
            nonce = "same" if is_write else "new"
        return {"action": "retry", "mode": mode, "nonce": nonce, "delayMs": delay_ms}

    if is_write and is_response:
        if code == "duplicate_api_request_in_progress":
            return {"action": "outcome_unknown", "inProgress": True}
        if code == "duplicate_api_request" and a["resends"] > 0:
            return {"action": "outcome_unknown", "inProgress": False}
        if outcome.get("replayed") and _server_error(status):
            return {"action": "outcome_unknown", "inProgress": False}

    if is_response and code in _CONFLICT_RETRY_CODES:
        if not a["conflictRetried"] and not (is_write and a["mayHaveRun"]):
            # Nothing was executed: a new nonce, or the gateway would answer with the replayed 409.
            return retry("resign", 0, "new")
        return {"action": "return"}

    transient = not is_response or status == 429 or _server_error(status)
    if not transient:
        return {"action": "return"}

    delay_ms = backoff_ms(a["attempt"], a["random"], outcome.get("retryAfterSeconds") if is_response else None)
    if not is_write:
        return retry("resign", delay_ms)

    if this_may_have_run:
        # Sent, outcome unknown: only an immediate resend of the same request can still learn it, and only
        # where a duplicate is certainly refused.
        if a["keyMode"] == "keypair" and a["resends"] == 0 and a["sinceFirstSendMs"] < RETRY["resendWindowMs"]:
            return retry("resend", 0)
        return {"action": "outcome_unknown", "inProgress": False}

    # Not sent, or a 429 (refused before the route): it did not run.
    if a["signedAgeMs"] + delay_ms < RETRY["signatureMaxAgeMs"]:
        return retry("resend", delay_ms)
    if not a["mayHaveRun"]:
        return retry("resign", delay_ms)
    return {"action": "outcome_unknown", "inProgress": False}


__all__ = ["RETRY", "backoff_ms", "decide_retry"]
