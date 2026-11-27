"""Verify that Vaultody API responses and webhook deliveries come unchanged from Vaultody, and sign requests."""

from .address import AddressCheckResult, AddressVerificationError, check_address, network_of_vault
from .errors import ConfigurationError, ResponseSignatureError, VaultodyVerifyError
from .keys import (
    SignatureFormatError,
    SigningKey,
    UnexpectedResponseError,
    UsageError,
    decode_api_secret,
    fingerprint_of,
    hmac_v2_request_message,
    hmac_v2_signature,
    keypair_request_message,
    p1363_to_der,
    read_signing_key,
    read_signing_keys_response,
    sign_api_request,
    sign_hmac_v2_request,
    verify_keypair_request,
)
from .response import VerificationResult, verify_requests_response, verify_response
from .webhook import WebhookSignatureError, WebhookVerification, verify_webhook_signature

__version__ = "0.9.0rc1"

__all__ = [
    "AddressCheckResult",
    "AddressVerificationError",
    "ConfigurationError",
    "ResponseSignatureError",
    "SignatureFormatError",
    "SigningKey",
    "UnexpectedResponseError",
    "UsageError",
    "VaultodyVerifyError",
    "VerificationResult",
    "WebhookSignatureError",
    "WebhookVerification",
    "check_address",
    "decode_api_secret",
    "fingerprint_of",
    "hmac_v2_request_message",
    "hmac_v2_signature",
    "keypair_request_message",
    "network_of_vault",
    "p1363_to_der",
    "read_signing_key",
    "read_signing_keys_response",
    "sign_api_request",
    "sign_hmac_v2_request",
    "verify_keypair_request",
    "verify_requests_response",
    "verify_response",
    "verify_webhook_signature",
]
