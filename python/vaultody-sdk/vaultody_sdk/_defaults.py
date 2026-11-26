"""The two build defaults a stable release changes.

No imports, so the release guard (scripts/release/guard.mjs) reads this file with Python's parser without
installing anything. Node (``src/defaults.js``) and PHP (``Transport::DEFAULT_RESPONSE_SIGNATURE``,
``Transport::ADDRESS_PATHS_PUBLIC``) hold the same values: the guard refuses a commit where the three differ, and
a stable release where either is still a release candidate's value.
"""

#: The response-signature mode when none is given (``response_signature``, ``VAULTODY_RESPONSE_SIGNATURE``):
#: ``"when-present"`` while production does not sign responses (release candidates), ``"required"`` from the stable
#: release on. A client with response-signing roots is strict whatever this says.
DEFAULT_RESPONSE_SIGNATURE = "when-present"

#: Whether the API answers every address it derives with its derivation path (accountIndex, isChange,
#: addressIndex). False while those fields are hidden; the release that ships after they are public sets it to True.
#: It is the default of ``require_address_paths``: with it on, generate_deposit_address refuses an address of a
#: vault with MPC keys that comes without its path.
ADDRESS_PATHS_PUBLIC = False
