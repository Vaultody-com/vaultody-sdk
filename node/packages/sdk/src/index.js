'use strict';

/**
 * @vaultody/sdk: the client, with a method for every documented API operation (vaultody.<group>.<operationId>),
 * its transport (signing, response verification, vault xpub pins and address checks, retries, the rate
 * limiter, paging, webhooks), and the pieces it is built from.
 *
 * Every export is a plain name in the object literal below (no spread, no `a: b.c`): that is the form Node's
 * ESM loader reads a CommonJS module's names from, so `import { X } from '@vaultody/sdk'` works for each of
 * them (test/package-exports.test.js).
 */

const { API_VERSION, SDK_VERSION } = require('./version');
const { OPERATIONS, operationById } = require('./operations');
const {
    VaultodyError,
    ApiError,
    AuthenticationError,
    RequestSigningError,
    PermissionDeniedError,
    NotFoundError,
    InvalidRequestError,
    ConflictError,
    DuplicateTransferError,
    RateLimitError,
    ServerError,
    RequestOutcomeUnknownError,
    TransportError,
    ParameterError,
    PaginationError,
    VaultKeyChangedError,
    AddressVerificationError,
    ResponseVerificationError,
    ConfigurationError,
    WebhookSignatureError,
    WebhookPayloadError,
    VaultKeyStoreError,
    errorClassFor,
    readEnvelope,
} = require('./errors');
const { RETRY, decideRetry } = require('./retry');
const { paginate } = require('./pagination');
const { classifyTransportError } = require('./transportErrors');
const { buildRequestTarget, percentEncode } = require('./requestTarget');
const {
    PIN_STATUS, ADDRESS_CHECK_STATUS, readVaultList, observeVaults, addressCheckStatus, xpubHash,
} = require('./vaultKeys');
const { Vaultody } = require('./client');
const { Page, Pager } = require('./page');
const { MemoryVaultKeyStore, FileVaultKeyStore, defaultVaultKeysFile } = require('./vaultKeyStore');
const {
    pemSigner, fileSigner, awsKmsSigner, gcpKmsSigner, vaultTransitSigner,
} = require('./signer');
const { verifyWebhook, WEBHOOK_EVENTS } = require('./webhooks');
const { MODES: RESPONSE_SIGNATURE_MODES } = require('./responseVerification');
const { SECURITY_EVENTS } = require('./securityEvents');

module.exports = {
    // The client
    Vaultody,
    API_VERSION,
    SDK_VERSION,
    OPERATIONS,
    operationById,
    RESPONSE_SIGNATURE_MODES,
    SECURITY_EVENTS,

    // Errors: the same names in every language
    VaultodyError,
    ApiError,
    AuthenticationError,
    RequestSigningError,
    PermissionDeniedError,
    NotFoundError,
    InvalidRequestError,
    ConflictError,
    DuplicateTransferError,
    RateLimitError,
    ServerError,
    RequestOutcomeUnknownError,
    TransportError,
    ParameterError,
    PaginationError,
    VaultKeyChangedError,
    AddressVerificationError,
    ResponseVerificationError,
    ConfigurationError,
    WebhookSignatureError,
    WebhookPayloadError,
    VaultKeyStoreError,
    errorClassFor,
    readEnvelope,

    // Retries, paging, request targets
    RETRY,
    decideRetry,
    paginate,
    Page,
    Pager,
    classifyTransportError,
    buildRequestTarget,
    percentEncode,

    // Vault xpub pins and address checks
    PIN_STATUS,
    ADDRESS_CHECK_STATUS,
    readVaultList,
    observeVaults,
    addressCheckStatus,
    xpubHash,
    MemoryVaultKeyStore,
    FileVaultKeyStore,
    defaultVaultKeysFile,

    // Signers
    pemSigner,
    fileSigner,
    awsKmsSigner,
    gcpKmsSigner,
    vaultTransitSigner,

    // Webhooks
    verifyWebhook,
    WEBHOOK_EVENTS,
};
