"""Whether a request that failed on the network may have reached the gateway
(test-vectors/transport-errors-v1.json).

Only a failure that proves the request never left counts as not sent: httpx's ConnectError (the name
could not be resolved, the connection was refused, the TLS handshake or its certificate failed) and
ConnectTimeout. Everything else is ``"unknown"``, and a write in that state is never sent again as new.
"""

import httpx

_NOT_SENT = (httpx.ConnectError, httpx.ConnectTimeout)
_MAX_DEPTH = 8


def classify_transport_error(error):
    """``{"sent": False}`` when ``error`` (or an exception it was raised from) proves the request never
    left, else ``{"sent": "unknown"}``."""
    current = error
    for _ in range(_MAX_DEPTH):
        if not isinstance(current, BaseException):
            break
        if isinstance(current, _NOT_SENT):
            return {"sent": False}
        current = current.__cause__
    return {"sent": "unknown"}


__all__ = ["classify_transport_error"]
