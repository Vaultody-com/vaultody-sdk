'use strict';

/**
 * Why an address was not verified. Callers branch on these strings, so they are part of the public API
 * and are the same in every language the helper ships in.
 */
const ADDRESS_REASONS = Object.freeze({
    // The address is not the one the vault's key derives at the given path and format.
    MISMATCH: 'mismatch',
    // The address has no derivation path (account index, change or address index is absent), as for
    // addresses a smart-contract vault creates. It cannot be checked against the vault's key.
    NOT_VERIFIABLE: 'not_verifiable',
    // The vault is not among the keys taken from the signed vault list.
    UNKNOWN_VAULT: 'unknown_vault',
    // The vault has no key for the algorithm this chain uses, or its key in the signed response cannot be read.
    MISSING_KEY: 'missing_key',
    // The network does not belong with the vault's type: "mainnet" needs a main vault, any other
    // network a test vault.
    NETWORK_MISMATCH: 'network_mismatch',
    // A chain, network or address format this version of the helper does not know.
    UNSUPPORTED: 'unsupported',
});

/**
 * Thrown when an address cannot be verified. `reason` is one of ADDRESS_REASONS; the message adds
 * detail for logs but is not meant to be matched on.
 */
class AddressVerificationError extends Error {
    constructor(reason, detail) {
        super(`Vaultody address check failed (${reason}): ${detail}`);
        this.name = 'AddressVerificationError';
        this.reason = reason;
    }
}

module.exports = {
    ADDRESS_REASONS,
    AddressVerificationError,
};
