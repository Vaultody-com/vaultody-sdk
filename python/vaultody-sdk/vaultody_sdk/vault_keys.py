"""Vault xpub pins: the data model and the decisions, without storage (test-vectors/vault-key-pins-v1.json).

The stores (a file by default, a custom one) come with the transport; pins given in configuration
(``pinned_vault_keys``) are read here, by ``configured_pins``.

A pin records the xpub of each MPC algorithm of a vault, as first seen in GET /vaults/{networkType}:

- ``verified``: a signed answer, checked against a pinned root, showed these xpubs, or the pin was given in
  configuration;
- ``unverified``: only an unsigned answer did (trust on first use), allowed for release candidates while
  production does not sign. It is never reported as verified, and becomes verified when a signed answer
  shows the same xpubs.

An xpub that differs from its pin, a pinned one that is gone, an algorithm the pin did not have, or another
vault type is an alarm: the whole answer is refused and no pin changes. Only an explicit re-pin, after the
client confirmed the change (the command line's ``vault-keys accept``, or the store's ``replace()``), ever
changes a pin. A vault without MPC keys (SMART, AUTOMATION) has nothing to pin: its addresses are not
verifiable, never verified. An address without its derivation path is not verifiable either, except a new one
(generateDepositAddress) of a vault with MPC keys when the client requires the path (``require_address_paths``):
that one is refused as ``path_missing``.

A pin given in configuration counts as verified. It is compared with every answer exactly as a stored pin,
is never written to the store, and takes the place of the stored pin of the same vault.

Pins are plain dicts with the stored field names, the same in every language: ``vaultId``, ``type``,
``keys`` (``ECDSA``, ``EDDSA``: xpub or None), ``status``, ``firstSeenAt``, ``verifiedAt`` and
``verification`` (``{"rootId", "timestamp"}`` or None).
"""

import hashlib
from collections.abc import Mapping
from types import MappingProxyType

from .errors import AddressVerificationError, ConfigurationError, VaultKeyChangedError

PIN_STATUS = MappingProxyType({"VERIFIED": "verified", "UNVERIFIED": "unverified"})

ADDRESS_CHECK_STATUS = MappingProxyType({"VERIFIED": "verified", "UNVERIFIED": "unverified", "NOT_VERIFIABLE": "not_verifiable"})

#: The MPC algorithms pinned, in the order alarms list them.
ALGORITHMS = ("ECDSA", "EDDSA")

OUTCOMES = MappingProxyType({"PINNED": "pinned", "UNCHANGED": "unchanged", "UPGRADED": "upgraded", "NOT_VERIFIABLE": "not_verifiable"})


def xpub_hash(xpub):
    """What an alarm names instead of an xpub: the first 16 hex characters of its SHA-256."""
    return hashlib.sha256(xpub.encode("utf-8")).hexdigest()[:16]


_CONFIGURED_FIELDS = frozenset(("vaultId", "type", "keys"))


class _ConfiguredPins(dict):
    """vaultId → configured pin. Its repr names no vault and no xpub (an xpub reveals every address)."""

    def __repr__(self):
        return "<{} configured vault pins>".format(len(self))


def configured_pins(entries):
    """The pins given in configuration (``pinned_vault_keys``), checked and copied.

    :param entries: None, or a list or tuple of ``{"vaultId": str, "type": "main" | "test", "keys":
        {"ECDSA": xpub or None, "EDDSA": xpub or None}}``, exactly those fields, at least one xpub, each
        vault once
    :returns: vaultId → pin, each with status ``verified`` (never stored, so with no time or evidence)
    :raises ConfigurationError: ``invalid_pinned_vault_keys``; the message names the entry, never an xpub
    """
    pins = _ConfiguredPins()
    if entries is None:
        return pins
    if not isinstance(entries, (list, tuple)):
        raise ConfigurationError("pinned_vault_keys must be a list of pins", "invalid_pinned_vault_keys")
    for index, entry in enumerate(entries):
        where = "pinned_vault_keys[{}]".format(index)
        if not isinstance(entry, Mapping) or set(entry.keys()) != _CONFIGURED_FIELDS:
            raise ConfigurationError(
                '{} must have exactly vaultId, type and keys'.format(where), "invalid_pinned_vault_keys"
            )
        vault_id, vault_type, keys = entry["vaultId"], entry["type"], entry["keys"]
        if not isinstance(vault_id, str) or not vault_id:
            raise ConfigurationError("{}.vaultId must be a non-empty string".format(where), "invalid_pinned_vault_keys")
        if vault_type not in ("main", "test"):
            raise ConfigurationError('{}.type must be "main" or "test"'.format(where), "invalid_pinned_vault_keys")
        if not isinstance(keys, Mapping) or set(keys.keys()) != set(ALGORITHMS):
            raise ConfigurationError("{}.keys must have exactly ECDSA and EDDSA".format(where), "invalid_pinned_vault_keys")
        for algorithm in ALGORITHMS:
            xpub = keys[algorithm]
            if xpub is not None and (not isinstance(xpub, str) or not xpub):
                raise ConfigurationError(
                    "{}.keys.{} must be an xpub or None".format(where, algorithm), "invalid_pinned_vault_keys"
                )
        if not _has_keys(keys):
            raise ConfigurationError("{} has no xpub".format(where), "invalid_pinned_vault_keys")
        if vault_id in pins:
            raise ConfigurationError("{} pins vault {} a second time".format(where, vault_id), "invalid_pinned_vault_keys")
        pins[vault_id] = {
            "vaultId": vault_id,
            "type": vault_type,
            "keys": {algorithm: keys[algorithm] for algorithm in ALGORITHMS},
            "status": PIN_STATUS["VERIFIED"],
            "firstSeenAt": None,
            "verifiedAt": None,
            "verification": None,
        }
    return pins


def read_vault_list(items):
    """The vaults of one answer of GET /vaults/{networkType} (its ``data.items``).

    :returns: list of ``{"vaultId", "type", "keys": {"ECDSA", "EDDSA"}}``
    """
    if not isinstance(items, list):
        raise TypeError("expected the items of a vault list")
    vaults = []
    for item in items:
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str) or not item["id"]:
            raise TypeError("a vault in the list has no id")
        keys = {"ECDSA": None, "EDDSA": None}
        mpc_keys = item.get("mpcKeys")
        if mpc_keys is None:
            mpc_keys = []
        if not isinstance(mpc_keys, list):
            raise TypeError("vault {} has a malformed mpcKeys list".format(item["id"]))
        for entry in mpc_keys:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("algorithm"), str) or not isinstance(entry.get("xpub"), str) or not entry["xpub"]:
                raise TypeError("vault {} has an mpcKeys entry without an algorithm and an xpub".format(item["id"]))
            algorithm = entry["algorithm"].upper()
            # As on the server (mpcKeys.find): the first key of an algorithm counts; others are ignored.
            if algorithm in keys and keys[algorithm] is None:
                keys[algorithm] = entry["xpub"]
        vaults.append({"vaultId": item["id"], "type": item.get("type"), "keys": keys})
    return vaults


def _has_keys(keys):
    return any(keys[algorithm] is not None for algorithm in ALGORITHMS)


def observe_vaults(pins, vaults, evidence):
    """Compares the vaults of one answer with the pins of its origin.

    :param pins: vaultId → pin, the current pins of this API origin
    :param vaults: from read_vault_list
    :param evidence: ``{"signed": bool, "rootId", "timestamp", "now"}``: whether the answer was signed and
        verified, the root that certified it and its response time, and the time now
    :returns: ``(outcomes, changes)``: ``[{"vaultId", "outcome"}]`` in the order of the answer, and the pins
        to write (new and upgraded ones)
    :raises VaultKeyChangedError: when any xpub differs from its pin; nothing may be written then
    """
    current = dict(pins or {})
    outcomes = []
    changes = []
    alarms = []
    signed = bool(evidence.get("signed"))
    verification = {"rootId": evidence.get("rootId"), "timestamp": evidence.get("timestamp")} if signed else None

    for vault in vaults:
        vault_id = vault["vaultId"]
        pin = current.get(vault_id)
        if pin is None:
            if not _has_keys(vault["keys"]):
                outcomes.append({"vaultId": vault_id, "outcome": OUTCOMES["NOT_VERIFIABLE"]})
                continue
            created = {
                "vaultId": vault_id,
                "type": vault["type"],
                "keys": {"ECDSA": vault["keys"]["ECDSA"], "EDDSA": vault["keys"]["EDDSA"]},
                "status": PIN_STATUS["VERIFIED"] if signed else PIN_STATUS["UNVERIFIED"],
                "firstSeenAt": evidence["now"],
                "verifiedAt": evidence["now"] if signed else None,
                "verification": verification,
            }
            current[vault_id] = created
            changes.append(created)
            outcomes.append({"vaultId": vault_id, "outcome": OUTCOMES["PINNED"]})
            continue

        found = []
        for algorithm in ALGORITHMS:
            pinned = pin["keys"][algorithm]
            seen = vault["keys"][algorithm]
            if pinned is not None and seen != pinned:
                found.append({
                    "vaultId": vault_id,
                    "algorithm": algorithm,
                    "reason": "xpub_missing" if seen is None else "xpub_changed",
                    "pinned": xpub_hash(pinned),
                    "seen": None if seen is None else xpub_hash(seen),
                })
            elif pinned is None and seen is not None:
                # Refused on purpose: the client confirms a new algorithm and re-pins the vault.
                found.append({"vaultId": vault_id, "algorithm": algorithm, "reason": "xpub_added", "pinned": None, "seen": xpub_hash(seen)})
        if vault["type"] != pin["type"]:
            # Refused on purpose as well: the client confirms the change and re-pins the vault.
            found.append({"vaultId": vault_id, "algorithm": None, "reason": "type_changed", "pinned": None, "seen": None})
        if found:
            alarms.extend(found)
            continue

        if pin["status"] == PIN_STATUS["UNVERIFIED"] and signed:
            upgraded = dict(pin, status=PIN_STATUS["VERIFIED"], verifiedAt=evidence["now"], verification=verification)
            current[vault_id] = upgraded
            changes.append(upgraded)
            outcomes.append({"vaultId": vault_id, "outcome": OUTCOMES["UPGRADED"]})
        else:
            outcomes.append({"vaultId": vault_id, "outcome": OUTCOMES["UNCHANGED"]})

    if alarms:
        raise VaultKeyChangedError(alarms)
    return outcomes, changes


def address_path_required(require_address_paths, operation_id, chain_known):
    """Whether an address answered without its derivation path is refused (``path_missing``) rather than not
    verifiable: only on generateDepositAddress, whose answer is always a new address, with the client's
    ``require_address_paths`` on, and on a chain the SDK can derive. Lists and addAssetToVaultAccount may
    answer older rows that never had a path.

    :param require_address_paths: the client's option
    :param operation_id: the operation that answered the address
    :param chain_known: whether the address's chain is one the SDK derives addresses for
    """
    return require_address_paths is True and operation_id == "generateDepositAddress" and chain_known is True


def address_check_status(pin, vault_has_keys, path_fields, derivation, path_required=False):
    """The status of one returned address, once its derivation was compared with the vault's pinned xpub.

    :param pin: the vault's pin (a mapping with ``status``), or None for a vault without MPC keys
    :param vault_has_keys: whether the vault has MPC keys at all
    :param path_fields: whether the address carries accountIndex, isChange and addressIndex
    :param derivation: ``"match"``, ``"mismatch"`` or None when no derivation was possible
    :param path_required: address_path_required() for this address
    :returns: ``"verified"``, ``"unverified"`` or ``"not_verifiable"``
    :raises AddressVerificationError: ``mismatch`` when the address does not derive from the pinned xpub;
        ``path_missing`` when a path is required and the address of a vault with MPC keys comes without it
    """
    if not vault_has_keys:
        return ADDRESS_CHECK_STATUS["NOT_VERIFIABLE"]
    if not path_fields:
        if path_required:
            raise AddressVerificationError(
                "path_missing",
                "the address came without its derivation path (accountIndex, isChange, addressIndex), so it can't be "
                "checked against the vault's pinned xpub",
            )
        return ADDRESS_CHECK_STATUS["NOT_VERIFIABLE"]
    if pin is None:
        raise TypeError("a vault with MPC keys is pinned before its addresses are checked")
    if derivation != "match":
        raise AddressVerificationError("mismatch", "the address does not derive from the vault's pinned xpub")
    return ADDRESS_CHECK_STATUS["VERIFIED"] if pin["status"] == PIN_STATUS["VERIFIED"] else ADDRESS_CHECK_STATUS["UNVERIFIED"]


__all__ = [
    "ADDRESS_CHECK_STATUS",
    "ALGORITHMS",
    "OUTCOMES",
    "PIN_STATUS",
    "address_check_status",
    "address_path_required",
    "configured_pins",
    "observe_vaults",
    "read_vault_list",
    "xpub_hash",
]
