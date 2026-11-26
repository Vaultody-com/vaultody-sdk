'use strict';

/**
 * The security events the client hands to onSecurityEvent: their names and fields, the same in every language
 * (test-vectors/security-events-v1.json). An event never carries a secret, an xpub or an address.
 */

const SECURITY_EVENTS = Object.freeze({
    unsigned_response_accepted: Object.freeze(['type', 'origin', 'operationId']),
    response_signature_latched: Object.freeze(['type', 'origin', 'rootId', 'latchedAt']),
    response_verification_failed: Object.freeze(['type', 'origin', 'operationId', 'status', 'reason']),
    vault_key_pinned: Object.freeze(['type', 'origin', 'vaultId', 'status']),
    vault_key_verified: Object.freeze(['type', 'origin', 'vaultId', 'status']),
    vault_key_changed: Object.freeze(['type', 'origin', 'alarms']),
    address_verification_failed: Object.freeze(['type', 'origin', 'operationId', 'vaultId', 'code']),
});

/**
 * The event of a type with exactly its fields, in the catalogue's order; a field not given is null. A type or a
 * field that is not in the catalogue is a mistake in the SDK and throws, so no event can grow or rename a field
 * the other languages don't send (every place that raises an event runs in the tests).
 *
 * @param {Object} data { type, ...fields }
 * @returns {Readonly<Object>}
 */
function securityEvent(data) {
    const fields = Object.hasOwn(SECURITY_EVENTS, data.type) ? SECURITY_EVENTS[data.type] : null;
    if (!fields) {
        throw new TypeError(`no security event ${data.type}`);
    }
    const extra = Object.keys(data).filter(field => !fields.includes(field));
    if (extra.length > 0) {
        throw new TypeError(`${data.type} has no field ${extra.join(', ')}`);
    }

    return Object.freeze(Object.fromEntries(fields.map(field => [field, data[field] === undefined ? null : data[field]])));
}

module.exports = { SECURITY_EVENTS, securityEvent };
