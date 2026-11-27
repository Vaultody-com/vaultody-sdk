'use strict';

// The package root re-exports each module's public API. Each module is also reachable on its own
// subpath (for example "@vaultody-com/verify/response"), so new modules can be added beside it.
//
// Every export is a plain name in the object literal below (no spread, no `a: b.c`): that is the form Node's
// ESM loader reads a CommonJS module's names from, so `import { verifyResponse } from '@vaultody-com/verify'`
// works for each of them (test/package-exports.test.js).

const {
    verifyResponse, verifyFetchResponse, ResponseSignatureError, ConfigurationError, REASONS, DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    MAX_CERT_LIFETIME_SECONDS,
} = require('./response');
const {
    readSigningKey, readSigningKeyFile, inspectPublicKey, generateSigningKeyPair, signChallengeProof, verifyChallengeProof,
    signApiRequest, signHmacV2Request, p1363ToDer, readSigningKeysResponse, SigningKeyError, SignatureFormatError,
} = require('./keys');
const { verifyWebhookSignature, WebhookSignatureError, WEBHOOK_REASONS } = require('./webhook');
const {
    checkAddress, networkOfVault, AddressVerificationError, ADDRESS_REASONS,
} = require('./address');

module.exports = {
    verifyResponse,
    verifyFetchResponse,
    ResponseSignatureError,
    ConfigurationError,
    REASONS,
    DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    MAX_CERT_LIFETIME_SECONDS,

    // Request-signing key pairs (also on "@vaultody-com/verify/keys")
    readSigningKey,
    readSigningKeyFile,
    inspectPublicKey,
    generateSigningKeyPair,
    signChallengeProof,
    verifyChallengeProof,
    signApiRequest,
    signHmacV2Request,
    p1363ToDer,
    readSigningKeysResponse,
    SigningKeyError,
    SignatureFormatError,

    // Webhook deliveries (also on "@vaultody-com/verify/webhook")
    verifyWebhookSignature,
    WebhookSignatureError,
    WEBHOOK_REASONS,

    // Addresses against the vault xpub (also on "@vaultody-com/verify/address")
    checkAddress,
    networkOfVault,
    AddressVerificationError,
    ADDRESS_REASONS,
};
