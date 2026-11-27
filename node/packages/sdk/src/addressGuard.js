'use strict';

/**
 * Vault xpub pins and the address check, on top of the pin model (vaultKeys.js), a store (vaultKeyStore.js)
 * and @vaultody-com/verify's derivation.
 *
 * Pins come only from GET /vaults/{main|test} (listVaults). Every answer of it, the client's own calls
 * included, is compared with the pins first: a new vault is pinned (verified when the answer was signed,
 * unverified otherwise: trust on first use), an unverified pin is confirmed by a signed answer, and any
 * difference from a pin (an xpub changed or gone, an algorithm added, a type changed) is the alarm:
 * onSecurityEvent, then VaultKeyChangedError, no pin touched and nothing returned. Only an explicit
 * store.replace() ever re-pins.
 *
 * Pins given in configuration (pinnedVaultKeys) count as verified. They take the place of the stored pin of their
 * vault, which is then neither read nor changed, are compared with every answer like any pin, and are never
 * written to the store.
 *
 * Addresses are checked on the operations that return them. An address with its derivation path
 * (accountIndex, isChange, addressIndex) must derive from its vault's pinned xpub, or the whole response is
 * refused with AddressVerificationError. An address without the path, or of a vault without MPC keys
 * (SMART, AUTOMATION), is reported as not_verifiable, never as verified, except with requireAddressPaths on: then
 * generateDepositAddress, whose answer is always a new address, must carry the path for a vault with MPC keys on a
 * chain the SDK can derive, or it is refused (path_missing). A vault seen for the first time is pinned by listing
 * the vaults of its type through the full pipeline, page by page.
 */

const { checkAddress, networkOfVault, isKnownChain, AddressVerificationError: VerifyAddressError } = require('@vaultody-com/verify/address');
const { AddressVerificationError, VaultKeyChangedError, VaultKeyStoreError } = require('./errors');
const { readVaultList, observeVaults, addressPathRequired, addressCheckStatus, ADDRESS_CHECK_STATUS, OUTCOMES, ALGORITHMS } = require('./vaultKeys');

const VAULT_TYPES = new Set(['main', 'test']);
// How long a vault seen without MPC keys is remembered, and how often an unverified pin is re-confirmed.
const RECHECK_MS = 10 * 60 * 1000;

/**
 * The operations that return vault addresses: where the vault, chain and network of each address come from.
 * The response fields blockchain/network win when present and must agree with the request's.
 */
const ADDRESS_OPERATIONS = Object.freeze({
    generateDepositAddress: Object.freeze({ kind: 'item', blockchainParam: 'blockchain', networkParam: 'network' }),
    listAddressesByVaultAccountId: Object.freeze({ kind: 'page', blockchainParam: 'blockchain', networkParam: null }),
    addAssetToVaultAccount: Object.freeze({ kind: 'item', blockchainParam: null, networkParam: null, sentAddressParam: 'address' }),
});

const present = value => value !== undefined && value !== null;
const hasPathFields = entry => present(entry.accountIndex) && present(entry.isChange) && present(entry.addressIndex);
const sameKeys = (a, b) => a.type === b.type && ALGORITHMS.every(algorithm => a.keys[algorithm] === b.keys[algorithm]);
const fail = (code, message) => new AddressVerificationError(code, message);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/** A vault list that can't be taken as one; the client refuses the answer with ApiError. */
class InvalidVaultList extends Error {}
const invalidList = message => new InvalidVaultList(message);

class AddressGuard {
    /**
     * @param {{ origin: string, store: Object, configured?: Map<string, Object>, securityEvent: function(Object): void,
     *           clock: function(): number, requireAddressPaths?: boolean,
     *           listVaultPages: function(string): AsyncIterable<{ items: Array, meta: Object }> }} options
     *        configured: the pins given in configuration (vaultKeys.readConfiguredPins); listVaultPages(type) pages
     *        through listVaults with the client, every page signed, verified and observed like any other answer
     */
    constructor({ origin, store, configured = new Map(), securityEvent, clock, requireAddressPaths = false, listVaultPages }) {
        this.origin = origin;
        this.requireAddressPaths = requireAddressPaths;
        this.store = store;
        this.configured = configured;
        this.securityEvent = securityEvent;
        this.clock = clock;
        this.listVaultPages = listVaultPages;
        this.withoutKeys = new Map();
        this.confirmedAt = new Map();
        this.listing = new Map();
    }

    /**
     * Compares one answer of listVaults with the pins and stores what is new or confirmed.
     *
     * @param {string} networkType the networkType the request was made for
     * @param {Array} items data.items of the answer
     * @param {{ signature: string, rootId?: string, timestamp?: number }} verdict the signature check of the answer
     * @returns {Promise<Array<{ vaultId: string, status: string, outcome: string }>>} one per vault, in answer order:
     *          status is the vault's pin after this answer (verified, unverified) or not_verifiable (no MPC keys);
     *          outcome is what the answer did: pinned, unchanged, upgraded or not_verifiable
     * @throws {VaultKeyChangedError} the alarm
     * @throws {InvalidVaultList} the list is malformed, or lists a vault under the other type (the client
     *         refuses the answer with ApiError, as Python and PHP do)
     */
    async observeVaultList(networkType, items, verdict) {
        const type = typeof networkType === 'string' ? networkType.toLowerCase() : null;
        if (!VAULT_TYPES.has(type)) {
            throw invalidList('vault keys are taken only from GET /vaults/main or GET /vaults/test');
        }
        if (!Array.isArray(items)) {
            throw invalidList('the vault list has no items');
        }
        let vaults;
        try {
            vaults = readVaultList(items.map(item => (item && typeof item === 'object' && typeof item.type === 'string' ? { ...item, type: item.type.toLowerCase() } : item)));
        } catch (error) {
            throw invalidList(`the vault list can't be read: ${error.message}`);
        }
        for (const vault of vaults) {
            if (vault.type !== type) {
                throw invalidList(`vault ${vault.vaultId} is listed under ${type} vaults with type ${vault.type}`);
            }
        }

        const now = Math.floor(this.clock() / 1000);
        const evidence = verdict.signature === 'verified'
            ? { signed: true, rootId: verdict.rootId, timestamp: verdict.timestamp, now }
            : { signed: false, now };
        // A configured pin takes the place of the stored one: it is verified, so the answer never changes it.
        const pins = new Map([...(await this.store.list(this.origin)).map(pin => [pin.vaultId, pin]), ...this.configured]);
        const { outcomes, changes } = this.observe(pins, vaults, evidence);
        const statusOf = new Map([...pins].map(([vaultId, pin]) => [vaultId, pin.status]));

        for (const change of changes) {
            const before = pins.get(change.vaultId);
            const stored = before
                ? await this.store.upgradeTrust(this.origin, change)
                : await this.store.pinIfAbsent(this.origin, change);
            if (!stored) {
                // Another writer removed the pin between the read and the write: nothing is returned, as in
                // Python and PHP; calling again reads the store afresh.
                throw new VaultKeyStoreError('store_conflict', `the pin of vault ${change.vaultId} changed in the store while this client wrote it; call again`);
            }
            if (!sameKeys(stored, change)) {
                // Another process pinned this vault in the meantime, with other xpubs: the same alarm.
                this.observe(new Map([[change.vaultId, stored]]), vaults.filter(vault => vault.vaultId === change.vaultId), evidence);
            }
            statusOf.set(change.vaultId, stored.status);
            this.securityEvent({
                type: before ? 'vault_key_verified' : 'vault_key_pinned',
                origin: this.origin,
                vaultId: change.vaultId,
                status: stored.status,
            });
        }
        for (const { vaultId, outcome } of outcomes) {
            if (outcome === OUTCOMES.NOT_VERIFIABLE) {
                this.withoutKeys.set(vaultId, this.clock());
            } else {
                this.withoutKeys.delete(vaultId);
            }
        }

        return outcomes.map(({ vaultId, outcome }) => ({
            vaultId,
            status: outcome === OUTCOMES.NOT_VERIFIABLE ? ADDRESS_CHECK_STATUS.NOT_VERIFIABLE : statusOf.get(vaultId),
            outcome,
        }));
    }

    observe(pins, vaults, evidence) {
        try {
            return observeVaults(pins, vaults, evidence);
        } catch (error) {
            if (error instanceof VaultKeyChangedError) {
                this.securityEvent({ type: 'vault_key_changed', origin: this.origin, alarms: error.alarms });
            }
            throw error;
        }
    }

    /** Lists every vault of a type once at a time, which pins them all. */
    pinVaultsOfType(type) {
        if (!this.listing.has(type)) {
            const run = (async () => {
                // eslint-disable-next-line no-unused-vars
                for await (const page of this.listVaultPages(type)) {
                    // each page is observed by the client as it arrives
                }
            })();
            this.listing.set(type, run);
            run.then(() => this.listing.delete(type), () => this.listing.delete(type));
        }

        return this.listing.get(type);
    }

    /**
     * The pin of a vault, pinning it first when it is new.
     *
     * @returns {Promise<{ pin: Object|null, withoutKeys: boolean }>}
     */
    async vaultFor(vaultId, typeHint) {
        if (this.configured.has(vaultId)) {
            return { pin: this.configured.get(vaultId), withoutKeys: false };
        }
        const pin = await this.store.get(this.origin, vaultId);
        if (pin) {
            return { pin, withoutKeys: false };
        }
        const seenWithoutKeys = this.withoutKeys.get(vaultId);
        if (seenWithoutKeys !== undefined && this.clock() - seenWithoutKeys < RECHECK_MS) {
            return { pin: null, withoutKeys: true };
        }
        for (const type of typeHint ? [typeHint] : ['main', 'test']) {
            await this.pinVaultsOfType(type);
            const pinned = await this.store.get(this.origin, vaultId);
            if (pinned) {
                return { pin: pinned, withoutKeys: false };
            }
            if (this.withoutKeys.has(vaultId)) {
                return { pin: null, withoutKeys: true };
            }
        }

        throw fail('unknown_vault', `vault ${vaultId} is not in the vault list, so its addresses can't be checked`);
    }

    /** An unverified pin, met in a signed answer: list the vaults again, which confirms it (or raises the alarm). */
    async confirm(vaultId, pin) {
        const last = this.confirmedAt.get(vaultId);
        if (last !== undefined && this.clock() - last < RECHECK_MS) {
            return pin;
        }
        this.confirmedAt.set(vaultId, this.clock());
        await this.pinVaultsOfType(pin.type);

        return (await this.store.get(this.origin, vaultId)) || pin;
    }

    /**
     * Checks every address in a successful answer of an address operation.
     *
     * @param {string} operationId
     * @param {Object} params the call's params
     * @param {{ kind: string, item?: Object, items?: Array }} envelope the answer
     * @param {{ signature: string }} verdict
     * @returns {Promise<Array<{ vaultId: string, address: string, status: string }>|null>} one per address, in
     *          answer order (the same entries in every language); null for other operations
     * @throws {AddressVerificationError}
     */
    async check(operationId, params, envelope, verdict) {
        const spec = Object.prototype.hasOwnProperty.call(ADDRESS_OPERATIONS, operationId) ? ADDRESS_OPERATIONS[operationId] : null;
        if (!spec) {
            return null;
        }
        try {
            const entries = spec.kind === 'item' ? (envelope.kind === 'item' ? [envelope.item] : null) : (envelope.kind === 'page' ? envelope.items : null);
            if (!Array.isArray(entries) || !entries.every(entry => isObject(entry) && typeof entry.address === 'string' && entry.address !== '')) {
                throw fail('invalid', `the answer of ${operationId} does not have the shape of its addresses: an item without an address`);
            }

            return await this.checkEntries(operationId, spec, params, entries, verdict);
        } catch (error) {
            if (error instanceof AddressVerificationError) {
                this.securityEvent({ type: 'address_verification_failed', origin: this.origin, operationId, vaultId: params.vaultId, code: error.code });
            }
            throw error;
        }
    }

    async checkEntries(operationId, spec, params, entries, verdict) {
        if (spec.sentAddressParam && present(params[spec.sentAddressParam]) && entries[0].address !== params[spec.sentAddressParam]) {
            throw fail('mismatch', 'the answer names another address than the one the asset was added to');
        }
        const checks = entries.map(entry => ({ vaultId: params.vaultId, address: entry.address, status: ADDRESS_CHECK_STATUS.NOT_VERIFIABLE }));
        const requestBlockchain = spec.blockchainParam ? params[spec.blockchainParam] : undefined;
        const requestNetwork = spec.networkParam ? params[spec.networkParam] : undefined;
        const pathRequired = entries.map(entry => !hasPathFields(entry) && addressPathRequired({
            requireAddressPaths: this.requireAddressPaths,
            operationId,
            chainKnown: isKnownChain(present(entry.blockchain) ? entry.blockchain : requestBlockchain),
        }));
        if (!entries.some(hasPathFields) && !pathRequired.some(Boolean)) {
            return checks;
        }

        const firstNetwork = present(requestNetwork) ? requestNetwork : entries.map(entry => entry.network).find(present);
        const typeHint = typeof firstNetwork === 'string' ? (firstNetwork === 'mainnet' ? 'main' : 'test') : null;
        let { pin, withoutKeys } = await this.vaultFor(params.vaultId, typeHint);
        if (withoutKeys) {
            return checks;
        }
        if (pin.status !== 'verified' && verdict.signature === 'verified') {
            pin = await this.confirm(params.vaultId, pin);
        }

        entries.forEach((entry, index) => {
            if (!hasPathFields(entry)) {
                // The vault has MPC keys (it is pinned): refused when the path is required, else not verifiable.
                checks[index].status = addressCheckStatus({ pin, vaultHasKeys: true, pathFields: false, derivation: null, pathRequired: pathRequired[index] });

                return;
            }
            const blockchain = present(entry.blockchain) ? entry.blockchain : requestBlockchain;
            if (present(entry.blockchain) && present(requestBlockchain) && entry.blockchain !== requestBlockchain) {
                throw fail('mismatch', `an address is on ${entry.blockchain}, but ${requestBlockchain} was asked for`);
            }
            if (present(entry.network) && present(requestNetwork) && entry.network !== requestNetwork) {
                throw fail('network_mismatch', `an address is on ${entry.network}, but ${requestNetwork} was asked for`);
            }
            if (typeof blockchain !== 'string') {
                throw fail('unsupported', 'an address carries its derivation path but the answer does not say which chain it is on');
            }
            let network = present(entry.network) ? entry.network : requestNetwork;
            if (!present(network)) {
                network = networkOfVault(blockchain, pin.type);
            }
            if (typeof network !== 'string') {
                throw fail('unsupported', `${blockchain} is not a chain this SDK can check addresses on`);
            }

            try {
                checkAddress({ type: pin.type, keys: pin.keys }, {
                    blockchain,
                    network,
                    address: entry.address,
                    accountIndex: entry.accountIndex,
                    isChange: entry.isChange,
                    addressIndex: entry.addressIndex,
                    addressFormat: entry.addressFormat,
                });
            } catch (error) {
                if (error instanceof VerifyAddressError) {
                    throw fail(error.reason, `an address in the answer of ${operationId} failed the check against vault ${params.vaultId}'s pinned xpub (${error.reason})`);
                }
                if (error instanceof TypeError) {
                    throw fail('invalid', `an address in the answer of ${operationId} has unreadable fields: ${error.message}`);
                }
                throw error;
            }
            checks[index].status = addressCheckStatus({ pin, vaultHasKeys: true, pathFields: true, derivation: 'match' });
        });

        return checks;
    }
}

module.exports = {
    ADDRESS_OPERATIONS,
    AddressGuard,
    InvalidVaultList,
};
