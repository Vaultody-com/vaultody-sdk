'use strict';

/**
 * Vault xpub pins: the data model and the decisions, without storage (test-vectors/vault-key-pins-v1.json).
 * The stores (a file by default, or a custom one) and the pins given in configuration come with the client.
 *
 * A pin records the xpub of each MPC algorithm of a vault, as first seen in GET /vaults/{networkType}:
 *  - verified: a signed answer, checked against a pinned root, showed these xpubs;
 *  - unverified: only an unsigned answer did (trust on first use), allowed for release candidates while
 *    production does not sign. It is never reported as verified, and becomes verified when a signed answer
 *    shows the same xpubs.
 *  - a pin given in configuration (the client's pinnedVaultKeys) counts as verified. It is never stored, and
 *    it is checked against every answer like any other pin.
 * An xpub that differs from its pin, or a pinned one that is gone, is an alarm: the whole answer is
 * refused and no pin changes. So is an algorithm a pinned vault did not have, and a vault type change: the
 * client confirms a legitimate change out of band and re-pins the vault. Only an explicit replace (the
 * command line's `vault-keys accept`, or the store's replace()) ever changes a pinned xpub.
 *
 * A vault without MPC keys (SMART, AUTOMATION) has nothing to pin: its addresses are not verifiable,
 * never verified.
 */

const crypto = require('node:crypto');

const { AddressVerificationError, VaultKeyChangedError } = require('./errors');

const PIN_STATUS = Object.freeze({ VERIFIED: 'verified', UNVERIFIED: 'unverified' });

const ADDRESS_CHECK_STATUS = Object.freeze({ VERIFIED: 'verified', UNVERIFIED: 'unverified', NOT_VERIFIABLE: 'not_verifiable' });

/** The MPC algorithms pinned, in the order alarms list them. */
const ALGORITHMS = Object.freeze(['ECDSA', 'EDDSA']);

const OUTCOMES = Object.freeze({ PINNED: 'pinned', UNCHANGED: 'unchanged', UPGRADED: 'upgraded', NOT_VERIFIABLE: 'not_verifiable' });

/** What an alarm names instead of an xpub: the first 16 hex characters of its SHA-256. */
const xpubHash = xpub => crypto.createHash('sha256').update(xpub, 'utf8').digest('hex').slice(0, 16);

/**
 * The vaults of one answer of GET /vaults/{networkType}: data.items.
 *
 * @param {Array<Object>} items
 * @returns {Array<{ vaultId: string, type: string, keys: { ECDSA: string|null, EDDSA: string|null } }>}
 */
function readVaultList(items) {
    if (!Array.isArray(items)) {
        throw new TypeError('expected the items of a vault list');
    }

    return items.map(item => {
        if (!item || typeof item !== 'object' || typeof item.id !== 'string' || item.id === '') {
            throw new TypeError('a vault in the list has no id');
        }
        const keys = { ECDSA: null, EDDSA: null };
        const mpcKeys = item.mpcKeys === undefined || item.mpcKeys === null ? [] : item.mpcKeys;
        if (!Array.isArray(mpcKeys)) {
            throw new TypeError(`vault ${item.id} has a malformed mpcKeys list`);
        }
        for (const entry of mpcKeys) {
            if (!entry || typeof entry.algorithm !== 'string' || typeof entry.xpub !== 'string' || entry.xpub === '') {
                throw new TypeError(`vault ${item.id} has an mpcKeys entry without an algorithm and an xpub`);
            }
            const algorithm = entry.algorithm.toUpperCase();
            // As on the server (mpcKeys.find): the first key of an algorithm counts; others are ignored.
            if (ALGORITHMS.includes(algorithm) && keys[algorithm] === null) {
                keys[algorithm] = entry.xpub;
            }
        }

        return { vaultId: item.id, type: item.type, keys };
    });
}

const hasKeys = keys => ALGORITHMS.some(algorithm => keys[algorithm] !== null);

/**
 * Compares the vaults of one answer with the pins of its origin.
 *
 * @param {Map<string, Object>|Object} pins vaultId → pin, the current pins of this API origin
 * @param {Array<Object>} vaults from readVaultList
 * @param {{ signed: boolean, rootId?: string, timestamp?: number, now: number }} evidence whether the answer
 *        was signed and verified, the root that certified it and its response time, and the time now
 * @returns {{ outcomes: Array<{ vaultId: string, outcome: string }>, changes: Array<Object> }} the pins to
 *          write: new ones and upgraded ones, in the order of the answer
 * @throws {VaultKeyChangedError} when any xpub differs from its pin; nothing may be written then
 */
function observeVaults(pins, vaults, evidence) {
    const current = new Map(pins instanceof Map ? pins : Object.entries(pins || {}));
    const outcomes = [];
    const changes = [];
    const alarms = [];
    const verification = evidence.signed ? { rootId: evidence.rootId, timestamp: evidence.timestamp } : null;

    for (const vault of vaults) {
        const pin = current.get(vault.vaultId);
        if (!pin) {
            if (!hasKeys(vault.keys)) {
                outcomes.push({ vaultId: vault.vaultId, outcome: OUTCOMES.NOT_VERIFIABLE });
                continue;
            }
            const created = {
                vaultId: vault.vaultId,
                type: vault.type,
                keys: { ECDSA: vault.keys.ECDSA, EDDSA: vault.keys.EDDSA },
                status: evidence.signed ? PIN_STATUS.VERIFIED : PIN_STATUS.UNVERIFIED,
                firstSeenAt: evidence.now,
                verifiedAt: evidence.signed ? evidence.now : null,
                verification,
            };
            current.set(vault.vaultId, created);
            changes.push(created);
            outcomes.push({ vaultId: vault.vaultId, outcome: OUTCOMES.PINNED });
            continue;
        }

        const found = [];
        for (const algorithm of ALGORITHMS) {
            const pinned = pin.keys[algorithm];
            const seen = vault.keys[algorithm];
            if (pinned !== null && seen !== pinned) {
                found.push({ vaultId: vault.vaultId, algorithm, reason: seen === null ? 'xpub_missing' : 'xpub_changed', pinned: xpubHash(pinned), seen: seen === null ? null : xpubHash(seen) });
            } else if (pinned === null && seen !== null) {
                // Refused on purpose: a new key on a pinned vault is confirmed by the client and re-pinned.
                found.push({ vaultId: vault.vaultId, algorithm, reason: 'xpub_added', pinned: null, seen: xpubHash(seen) });
            }
        }
        if (vault.type !== pin.type) {
            // Refused as well, until the client re-pins the vault.
            found.push({ vaultId: vault.vaultId, algorithm: null, reason: 'type_changed', pinned: null, seen: null });
        }
        if (found.length > 0) {
            alarms.push(...found);
            continue;
        }

        if (pin.status === PIN_STATUS.UNVERIFIED && evidence.signed) {
            const upgraded = { ...pin, status: PIN_STATUS.VERIFIED, verifiedAt: evidence.now, verification };
            current.set(vault.vaultId, upgraded);
            changes.push(upgraded);
            outcomes.push({ vaultId: vault.vaultId, outcome: OUTCOMES.UPGRADED });
        } else {
            outcomes.push({ vaultId: vault.vaultId, outcome: OUTCOMES.UNCHANGED });
        }
    }

    if (alarms.length > 0) {
        throw new VaultKeyChangedError(alarms);
    }

    return { outcomes, changes };
}

const CONFIGURED_FIELDS = ['vaultId', 'type', 'keys'];
const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hasExactly = (object, keys) => isPlainObject(object) && Object.keys(object).length === keys.length && keys.every(key => Object.hasOwn(object, key));

/**
 * Reads the pins given in configuration (the client's pinnedVaultKeys): a list of
 * { vaultId, type: 'main'|'test', keys: { ECDSA: xpub|null, EDDSA: xpub|null } }, at least one xpub each, no
 * other field, each vault once. Each becomes a pin that counts as verified; it is never stored.
 *
 * @param {Array<Object>} entries
 * @returns {Map<string, Object>} vaultId → pin
 * @throws {TypeError} naming the entry, never an xpub
 */
function readConfiguredPins(entries) {
    if (!Array.isArray(entries)) {
        throw new TypeError('expected a list of { vaultId, type, keys: { ECDSA, EDDSA } }');
    }
    const pins = new Map();
    entries.forEach((entry, index) => {
        const where = `entry ${index}`;
        if (!hasExactly(entry, CONFIGURED_FIELDS)) {
            throw new TypeError(`${where} must have exactly vaultId, type and keys`);
        }
        if (typeof entry.vaultId !== 'string' || entry.vaultId === '') {
            throw new TypeError(`${where}: vaultId must be a non-empty string`);
        }
        if (entry.type !== 'main' && entry.type !== 'test') {
            throw new TypeError(`${where}: type must be "main" or "test"`);
        }
        if (!hasExactly(entry.keys, ALGORITHMS) || !ALGORITHMS.every(algorithm => entry.keys[algorithm] === null || (typeof entry.keys[algorithm] === 'string' && entry.keys[algorithm] !== ''))) {
            throw new TypeError(`${where}: keys must be exactly { ECDSA, EDDSA }, each an xpub or null`);
        }
        if (!hasKeys(entry.keys)) {
            throw new TypeError(`${where}: keys must hold at least one xpub`);
        }
        if (pins.has(entry.vaultId)) {
            throw new TypeError(`${where}: vault ${entry.vaultId} is given twice`);
        }
        pins.set(entry.vaultId, Object.freeze({
            vaultId: entry.vaultId,
            type: entry.type,
            keys: Object.freeze({ ECDSA: entry.keys.ECDSA, EDDSA: entry.keys.EDDSA }),
            status: PIN_STATUS.VERIFIED,
            configured: true,
        }));
    });

    return pins;
}

/**
 * Whether an address answered without its derivation path is refused (path_missing) rather than not verifiable:
 * only on generateDepositAddress, whose answer is always a new address, with the client's requireAddressPaths on and
 * on a chain the SDK can derive. Lists and addAssetToVaultAccount may answer older rows that never had a path.
 *
 * @param {{ requireAddressPaths: boolean, operationId: string, chainKnown: boolean }} given
 * @returns {boolean}
 */
function addressPathRequired({ requireAddressPaths, operationId, chainKnown }) {
    return requireAddressPaths === true && operationId === 'generateDepositAddress' && chainKnown === true;
}

/**
 * The status of one returned address, once its derivation was compared with the vault's pinned xpub.
 *
 * @param {{ pin: { status: string }|null, vaultHasKeys: boolean, pathFields: boolean, derivation: 'match'|'mismatch'|null,
 *           pathRequired?: boolean }} check pathRequired: addressPathRequired()
 * @returns {'verified'|'unverified'|'not_verifiable'}
 * @throws {AddressVerificationError} 'mismatch' when the address does not derive from the pinned xpub; 'path_missing'
 *         when a path is required and the address of a vault with MPC keys comes without it
 */
function addressCheckStatus({ pin, vaultHasKeys, pathFields, derivation, pathRequired = false }) {
    if (!vaultHasKeys) {
        return ADDRESS_CHECK_STATUS.NOT_VERIFIABLE;
    }
    if (!pathFields) {
        if (pathRequired) {
            throw new AddressVerificationError('path_missing', 'the address came without its derivation path (accountIndex, isChange, addressIndex), '
                + 'so it can\'t be checked against the vault\'s pinned xpub');
        }

        return ADDRESS_CHECK_STATUS.NOT_VERIFIABLE;
    }
    if (!pin) {
        throw new TypeError('a vault with MPC keys is pinned before its addresses are checked');
    }
    if (derivation !== 'match') {
        throw new AddressVerificationError('mismatch', 'the address does not derive from the vault\'s pinned xpub');
    }

    return pin.status === PIN_STATUS.VERIFIED ? ADDRESS_CHECK_STATUS.VERIFIED : ADDRESS_CHECK_STATUS.UNVERIFIED;
}

module.exports = {
    PIN_STATUS,
    ADDRESS_CHECK_STATUS,
    ALGORITHMS,
    OUTCOMES,
    xpubHash,
    readVaultList,
    observeVaults,
    addressPathRequired,
    addressCheckStatus,
    readConfiguredPins,
};
