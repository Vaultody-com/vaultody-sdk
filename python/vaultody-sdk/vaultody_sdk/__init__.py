"""vaultody_sdk: the official Vaultody SDK for Python.

``Vaultody`` (sync) and ``AsyncVaultody`` (asyncio) share one core without I/O (_core.py): request signing
(HMAC v2 with a nonce, and the key-pair signature through a signer), response signature verification with
the strict latch, vault xpub pinning and address checks, retries that never run a write twice, the rate
limiter, typed errors and paging. ``webhooks.verify`` checks a webhook delivery.

Every documented operation is a method, grouped as the docs group them (``client.vaults``,
``client.vault_accounts``, ``client.assets_addresses``, ``client.transactions``, ``client.api_keys``), with
its arguments checked against the documented operation before anything is sent; models.py types them.
"""

from . import models, webhooks
from ._async_client import AsyncVaultody
from ._client import Vaultody
from ._core import Item, Page, ResponseMeta
from ._operations import OPERATIONS
from ._version import API_VERSION, __version__
from .errors import (
    AddressVerificationError,
    ApiError,
    AuthenticationError,
    ConfigurationError,
    ConflictError,
    DuplicateTransferError,
    InvalidRequestError,
    NotFoundError,
    PaginationError,
    ParameterError,
    PermissionDeniedError,
    RateLimitError,
    RequestOutcomeUnknownError,
    RequestSigningError,
    ResponseVerificationError,
    ServerError,
    SignerError,
    TransportError,
    VaultKeyChangedError,
    VaultKeyStoreError,
    VaultodyError,
    WebhookPayloadError,
    WebhookSignatureError,
    error_class_for,
    read_envelope,
)
from .pagination import AsyncPages, Pages, apaginate, paginate
from .request_target import build_request_target, percent_encode
from .retry import RETRY, backoff_ms, decide_retry
from .security_events import SECURITY_EVENTS
from .signers import AsyncCallbackSigner, AsyncSigner, CallbackSigner, FileSigner, PemSigner, Signer
from .stores import FileVaultKeyStore, MemoryVaultKeyStore, VaultKeyStore, default_vault_key_store
from .transport_errors import classify_transport_error
from .vault_keys import ADDRESS_CHECK_STATUS, PIN_STATUS, address_check_status, observe_vaults, read_vault_list, xpub_hash

__all__ = [
    "ADDRESS_CHECK_STATUS",
    "API_VERSION",
    "OPERATIONS",
    "PIN_STATUS",
    "RETRY",
    "SECURITY_EVENTS",
    "AddressVerificationError",
    "ApiError",
    "AsyncCallbackSigner",
    "AsyncPages",
    "AsyncSigner",
    "AsyncVaultody",
    "AuthenticationError",
    "CallbackSigner",
    "ConfigurationError",
    "ConflictError",
    "DuplicateTransferError",
    "FileSigner",
    "FileVaultKeyStore",
    "InvalidRequestError",
    "Item",
    "MemoryVaultKeyStore",
    "NotFoundError",
    "Page",
    "Pages",
    "PaginationError",
    "ParameterError",
    "PemSigner",
    "PermissionDeniedError",
    "RateLimitError",
    "RequestOutcomeUnknownError",
    "RequestSigningError",
    "ResponseMeta",
    "ResponseVerificationError",
    "ServerError",
    "Signer",
    "SignerError",
    "TransportError",
    "VaultKeyChangedError",
    "VaultKeyStore",
    "VaultKeyStoreError",
    "Vaultody",
    "VaultodyError",
    "WebhookPayloadError",
    "WebhookSignatureError",
    "__version__",
    "address_check_status",
    "apaginate",
    "backoff_ms",
    "build_request_target",
    "classify_transport_error",
    "decide_retry",
    "default_vault_key_store",
    "error_class_for",
    "models",
    "observe_vaults",
    "paginate",
    "percent_encode",
    "read_envelope",
    "read_vault_list",
    "webhooks",
    "xpub_hash",
]
