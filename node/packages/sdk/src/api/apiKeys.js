'use strict';

/**
 * API keys: the request-signing keys registered on the API key that makes the call.
 *
 * The `apiKeys` namespace of the client: `vaultody.apiKeys.<operationId>(params, options)`. The operation is
 * documented but not published on production yet (contract/pending/); the client also calls it itself, to
 * confirm its signer's key is active before it resends a write (Vaultody#confirmSigningKey).
 */

const { bindOperations } = require('./common');

/** @typedef {import('./common').CallOptions} CallOptions */

/**
 * @typedef {Object} ListApiKeySigningKeysParams The params of listApiKeySigningKeys: none. The list covers the
 *           API key in `x-api-key`.
 */

/**
 * @typedef {Object} ListApiKeySigningKeysResult One item of the list of listApiKeySigningKeys.
 * @property {string} [fingerprint] The key's fingerprint: `SHA256:` followed by the Base64 of the SHA-256 of the
 *           public key in DER form, without `=` padding. Send it in `x-api-keypair-id` with requests signed with
 *           this key.
 * @property {string} [algorithm] The key's algorithm: `ed25519` or `p-256` (ECDSA P-256).
 * @property {string} [status] The key's status. The list holds approved keys only, so it is always `active`.
 * @property {number} [createdTimestamp] When the key was sent for approval in the Dashboard, as a Unix timestamp
 *           in seconds.
 * @property {number} [approvedTimestamp] When an owner approved the key, as a Unix timestamp in seconds. Requests
 *           on the API key need the key-pair signature from then on.
 */

class ApiKeys {
    #invoke;

    /** @param {function(string, Object, Object): Promise<Object>} invoke the client's call */
    constructor(invoke) {
        this.#invoke = invoke;
    }

    /**
     * List API Key Signing Keys: `GET /api-keys/current/signing-keys`.
     *
     * Takes no params: call it as `listApiKeySigningKeys()`, or `listApiKeySigningKeys({}, options)`. The list
     * holds at most two keys and comes in one page. Compare each `fingerprint` with your own key's
     * (`vaultody.signerFingerprint`); verify the answer's signature first (`page.meta.signature`).
     *
     * @param {ListApiKeySigningKeysParams} [params]
     * @param {CallOptions} [options]
     * @returns {import('./common').PageRequest<ListApiKeySigningKeysResult>}
     */
    listApiKeySigningKeys(params, options) {
        return this.#invoke('listApiKeySigningKeys', params, options);
    }
}

module.exports = {
    ApiKeys: bindOperations(ApiKeys),
};
