"""Exceptions raised by vaultody_verify."""


class VaultodyVerifyError(Exception):
    """Base class of every error this package raises on purpose."""


class ConfigurationError(VaultodyVerifyError):
    """The verifier is set up wrong (for example no roots are pinned), so it cannot judge any response.

    It is deliberately not a ResponseSignatureError: it says nothing about the response, and code that
    treats a bad signature as "drop this response and carry on" must not quietly absorb a broken setup.
    """


_REASON_TEXT = {
    "missing": "a signature header is absent or empty",
    "invalid": "malformed signature headers or certificate, or a signature that does not verify",
    "expired": "the signature time is outside the certificate window, or the local clock is past it",
    "unknown_root": "the certificate names a root that is not pinned",
    "request_unbound": "authentic, but the gateway did not read the request body, so it is not bound to it",
    "unsupported_version": "a signature version this verifier does not know",
}


class ResponseSignatureError(VaultodyVerifyError):
    """The response failed verification. Treat its body as untrusted.

    ``reason`` is one of ``REASONS``; the message adds which check failed, for logs.
    """

    REASONS = tuple(_REASON_TEXT)

    def __init__(self, reason, detail=None):
        if reason not in _REASON_TEXT:
            raise ValueError("unknown response signature failure reason: {!r}".format(reason))
        # Both values go to Exception so the error survives pickling (multiprocessing, task queues).
        super().__init__(reason, detail)
        self.reason = reason
        self.detail = detail if detail is not None else _REASON_TEXT[reason]

    def __str__(self):
        return "{}: {}".format(self.reason, self.detail)
