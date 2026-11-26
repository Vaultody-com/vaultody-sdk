'use strict';

/**
 * The two build defaults a stable release changes, in a file with no dependency so the release guard
 * (scripts/release/guard.mjs) can read it without installing anything. Python (vaultody_sdk/_defaults.py) and PHP
 * (Transport::DEFAULT_RESPONSE_SIGNATURE, Transport::ADDRESS_PATHS_PUBLIC) hold the same values: the guard refuses a
 * commit where the three differ, and a stable release where either is still a release candidate's value.
 */

/**
 * The response-signature mode when none is given (option responseSignature, VAULTODY_RESPONSE_SIGNATURE):
 * 'when-present' while production does not sign responses (release candidates), 'required' from the stable release
 * on. A client with response-signing roots is strict whatever this says (responseVerification.js).
 */
const DEFAULT_RESPONSE_SIGNATURE = 'when-present';

/**
 * Whether the API answers every address it derives with its derivation path (accountIndex, isChange, addressIndex).
 * false while those fields are hidden; the release that ships after they are public sets it to true. It is the
 * default of the option requireAddressPaths: with it on, generateDepositAddress refuses an address of a vault with
 * MPC keys that comes without its path (addressGuard.js).
 */
const ADDRESS_PATHS_PUBLIC = false;

module.exports = {
    DEFAULT_RESPONSE_SIGNATURE,
    ADDRESS_PATHS_PUBLIC,
};
