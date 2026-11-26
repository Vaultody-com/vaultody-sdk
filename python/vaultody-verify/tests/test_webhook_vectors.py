"""test-vectors/webhook-v1.json: X-Signature on webhook deliveries."""

import base64
import json

import pytest

from vaultody_verify import ConfigurationError, WebhookSignatureError, WebhookVerification, verify_webhook_signature

from vaultody_vectors import load

VECTORS = load("webhook-v1.json")


class _CaseInsensitive(dict):
    """A stand-in for a framework's header map (requests, Werkzeug): another Mapping type."""


@pytest.mark.parametrize("vector", VECTORS["cases"], ids=[vector["name"] for vector in VECTORS["cases"]])
def test_webhook(vector):
    body = base64.b64decode(vector["bodyBase64"])
    secrets = vector["secrets"][0] if len(vector["secrets"]) == 1 else vector["secrets"]
    expected = vector["expected"]
    if expected["valid"]:
        verdict = WebhookVerification(valid=True, secret_index=expected["secretIndex"])
        assert verify_webhook_signature(body, vector["headers"], secrets) == verdict
        assert verify_webhook_signature(body.decode("utf-8"), _CaseInsensitive(vector["headers"]), vector["secrets"]) == verdict
    else:
        with pytest.raises(WebhookSignatureError) as raised:
            verify_webhook_signature(body, vector["headers"], secrets)
        assert raised.value.reason == expected["reason"]


def test_refuses_a_parsed_body():
    vector = VECTORS["cases"][0]
    parsed = json.loads(base64.b64decode(vector["bodyBase64"]))
    with pytest.raises(TypeError):
        verify_webhook_signature(parsed, vector["headers"], vector["secrets"])


@pytest.mark.parametrize("secrets", [None, "", [], [""], ["x", 42]])
def test_refuses_to_run_without_a_secret(secrets):
    vector = VECTORS["cases"][0]
    with pytest.raises(ConfigurationError):
        verify_webhook_signature(base64.b64decode(vector["bodyBase64"]), vector["headers"], secrets)


def test_refuses_the_header_given_twice():
    vector = VECTORS["cases"][0]
    value = vector["headers"]["X-Signature"]
    with pytest.raises(WebhookSignatureError) as raised:
        verify_webhook_signature(base64.b64decode(vector["bodyBase64"]), {"x-signature": [value, value]}, vector["secrets"])
    assert raised.value.reason == "malformed"
