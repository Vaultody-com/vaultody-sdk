'use strict';

/**
 * Checks that an address the Vaultody API returned derives from its vault's extended public key (xpub).
 *
 * Every vault address is derived from the vault's xpub with public math only, at path
 * m/{accountIndex}/{isChange ? 1 : 0}/{addressIndex}. Given the xpub, a client derives the address itself
 * and compares, so a changed address fails however it was changed: in a proxy, a CDN or anywhere else.
 *
 * This module is pure: it derives and compares. Where the xpub comes from is the caller's trust decision.
 * The SDK takes it only from GET /vaults/{main|test} and pins it on first sight (an xpub never changes),
 * so an xpub swapped later is an alarm instead of a new truth.
 *
 * checkAddress runs its checks in a fixed order, shared with the other language helpers. The order decides
 * which reason a caller sees:
 *  0. argument types and ranges, else TypeError;
 *  1. the chain and network are known, else `unsupported`;
 *  2. "mainnet" goes with a main vault and any other network with a test vault, else `network_mismatch`;
 *  3. accountIndex, isChange and addressIndex are all present, else `not_verifiable` (returned instead of
 *     thrown with allowUnverifiable);
 *  4. addressFormat, when given, is a format of the chain and not a refused one (p2sh on bitcoin-cash,
 *     dogecoin and dash, p2sh-cash on bitcoin-cash), else `unsupported`;
 *  5. the vault has a readable key for the chain's algorithm, else `missing_key`;
 *  6. the address derived at the path, in the given format or in any format of the chain when none is given
 *     (refused formats are skipped), equals the address (EVM chains: ignoring letter case), else `mismatch`.
 */

const { ADDRESS_REASONS, AddressVerificationError } = require('./errors');
const { ALGORITHMS, MAX_INDEX, parseExtendedPublicKey, deriveChild } = require('./derive');
const { CHAINS, chainNetwork, isRefusedFormat } = require('./chains');

const VAULT_TYPES = new Set(['main', 'test']);
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const fail = (reason, detail) => new AddressVerificationError(reason, detail);
const isObject = value => value !== null && typeof value === 'object';

// Parsed keys and account/change nodes, so a page of addresses costs one derivation step each. Bounded,
// because the xpubs and indexes come from API responses. Public data only: never logged.
const CACHE_LIMIT = 1024;
const cache = new Map();

function cached(key, make) {
    if (cache.has(key)) {
        return cache.get(key);
    }
    const value = make();
    if (cache.size >= CACHE_LIMIT) {
        cache.delete(cache.keys().next().value);
    }
    cache.set(key, value);

    return value;
}

function readIndex(value, name) {
    if (value === undefined || value === null) {
        return null;
    }
    // The API returns indexes as numbers on some routes and as decimal strings on others.
    const number = typeof value === 'string' && DECIMAL.test(value) ? Number(value) : value;
    if (!Number.isInteger(number) || number < 0 || number > MAX_INDEX) {
        throw new TypeError(`${name} must be an integer from 0 to ${MAX_INDEX}, as a number or a decimal string`);
    }

    return number;
}

function readIsChange(value) {
    if (value === undefined || value === null) {
        return null;
    }
    if (value === true || value === 1) {
        return 1;
    }
    if (value === false || value === 0) {
        return 0;
    }
    throw new TypeError('isChange must be true, false, 0 or 1');
}

function readString(value, name) {
    if (typeof value !== 'string' || value === '') {
        throw new TypeError(`${name} must be a non-empty string`);
    }

    return value;
}

function readVault(vault) {
    if (!isObject(vault) || !VAULT_TYPES.has(vault.type) || !isObject(vault.keys)) {
        throw new TypeError('vault must be { type: "main"|"test", keys: { ECDSA: xpub|null, EDDSA: xpub|null } }');
    }
    for (const algorithm of Object.values(ALGORITHMS)) {
        const xpub = vault.keys[algorithm];
        if (xpub !== undefined && xpub !== null && typeof xpub !== 'string') {
            throw new TypeError(`vault.keys.${algorithm} must be an xpub string or null`);
        }
    }

    return vault;
}

function readParams(params) {
    if (!isObject(params)) {
        throw new TypeError('checkAddress expects { blockchain, network, accountIndex, isChange, addressIndex, addressFormat, address }');
    }
    const { addressFormat } = params;
    if (addressFormat !== undefined && addressFormat !== null && typeof addressFormat !== 'string') {
        throw new TypeError('addressFormat must be a string, or absent');
    }

    return {
        blockchain: readString(params.blockchain, 'blockchain'),
        network: readString(params.network, 'network'),
        address: readString(params.address, 'address'),
        addressFormat: addressFormat === undefined || addressFormat === null ? null : addressFormat,
        accountIndex: readIndex(params.accountIndex, 'accountIndex'),
        isChange: readIsChange(params.isChange),
        addressIndex: readIndex(params.addressIndex, 'addressIndex'),
    };
}

function readOptions(options) {
    if (options === undefined || options === null) {
        return { allowUnverifiable: false };
    }
    if (!isObject(options)) {
        throw new TypeError('options must be an object');
    }
    const { allowUnverifiable = false } = options;
    if (typeof allowUnverifiable !== 'boolean') {
        throw new TypeError('allowUnverifiable must be true or false');
    }

    return { allowUnverifiable };
}

// EVM addresses are hex, so a checksummed (EIP-55) spelling is the same address; every other chain's
// encoding is case-sensitive.
const sameAddress = (derived, given, caseInsensitive) => (caseInsensitive ? derived.toLowerCase() === given.toLowerCase() : derived === given);

/**
 * Checks that an address is the one the vault's key derives at its path.
 *
 * @param {{ type: 'main'|'test', keys: { ECDSA?: string|null, EDDSA?: string|null } }} vault the vault's
 *        type and its xpub per MPC algorithm, as pinned
 * @param {Object} params the address as the API returned it
 * @param {string} params.blockchain as in API paths, for example "bitcoin" or "binance-smart-chain"
 * @param {string} params.network as in API paths, for example "mainnet", "testnet" or "sepolia"
 * @param {number|string} [params.accountIndex]
 * @param {boolean} [params.isChange]
 * @param {number|string} [params.addressIndex]
 * @param {string} [params.addressFormat] any case; when absent, every format of the chain is tried
 * @param {string} params.address
 * @param {{ allowUnverifiable?: boolean }} [options] return { verified: false, reason: 'not_verifiable' }
 *        for an address without a derivation path instead of throwing
 * @returns {{ verified: true, algorithm: string, path: string, address: string, addressFormat: string }
 *          | { verified: false, reason: 'not_verifiable' }}
 * @throws {AddressVerificationError} when the address is not verified
 */
function checkAddress(vault, params, options) {
    const v = readVault(vault);
    const { allowUnverifiable } = readOptions(options);
    const p = readParams(params);

    const target = chainNetwork(p.blockchain, p.network);
    if (!target) {
        throw fail(ADDRESS_REASONS.UNSUPPORTED, `${p.blockchain} on ${p.network} is not a chain and network this helper knows`);
    }
    const { chain, network } = target;
    if ((v.type === 'main') !== network.main) {
        throw fail(ADDRESS_REASONS.NETWORK_MISMATCH, `${p.network} does not belong with a ${v.type} vault`);
    }

    if (p.accountIndex === null || p.isChange === null || p.addressIndex === null) {
        if (allowUnverifiable) {
            return { verified: false, reason: ADDRESS_REASONS.NOT_VERIFIABLE };
        }
        throw fail(ADDRESS_REASONS.NOT_VERIFIABLE, 'the address has no derivation path (accountIndex, isChange and addressIndex), so it cannot be checked against the vault key');
    }

    let formats = Object.keys(chain.formats);
    if (p.addressFormat !== null) {
        const format = p.addressFormat.toLowerCase();
        if (!hasOwn(chain.formats, format)) {
            throw fail(ADDRESS_REASONS.UNSUPPORTED, `${p.addressFormat} is not an address format of ${p.blockchain}`);
        }
        if (isRefusedFormat(p.blockchain, format)) {
            throw fail(ADDRESS_REASONS.UNSUPPORTED, `${p.addressFormat} on ${p.blockchain} is refused: it is P2SH-wrapped SegWit on a chain without SegWit, which anyone can spend`);
        }
        formats = [format];
    } else {
        formats = formats.filter(format => !isRefusedFormat(p.blockchain, format));
    }

    const xpub = v.keys[chain.algorithm];
    if (typeof xpub !== 'string' || xpub === '') {
        throw fail(ADDRESS_REASONS.MISSING_KEY, `the vault has no ${chain.algorithm} key`);
    }
    let root;
    try {
        root = cached(`key\u0000${chain.algorithm}\u0000${xpub}`, () => parseExtendedPublicKey(xpub, chain.algorithm));
    } catch (e) {
        throw fail(ADDRESS_REASONS.MISSING_KEY, `the vault's ${chain.algorithm} key could not be read: ${e.message}`);
    }

    const path = `m/${p.accountIndex}/${p.isChange}/${p.addressIndex}`;
    let node;
    try {
        const parent = cached(`node\u0000${chain.algorithm}\u0000${xpub}\u0000${p.accountIndex}\u0000${p.isChange}`,
            () => deriveChild(deriveChild(root, p.accountIndex), p.isChange));
        node = deriveChild(parent, p.addressIndex);
    } catch (e) {
        // Only possible past the last non-hardened index; the server cannot derive such an address either.
        throw fail(ADDRESS_REASONS.MISMATCH, `the vault key derives no address at ${path}: ${e.message}`);
    }

    for (const format of formats) {
        if (sameAddress(chain.formats[format](node, network), p.address, chain.caseInsensitive)) {
            return { verified: true, algorithm: chain.algorithm, path, address: p.address, addressFormat: format };
        }
    }

    throw fail(ADDRESS_REASONS.MISMATCH, `the address is not the ${formats.join(' or ')} address of the vault at ${path}`);
}

/**
 * The network an address of a vault is on when the response does not say: "mainnet" for a main vault, the
 * chain's one test network for a test vault.
 *
 * @param {string} blockchain
 * @param {'main'|'test'} vaultType
 * @returns {string|null} null for a chain this helper does not know
 */
function networkOfVault(blockchain, vaultType) {
    const chain = typeof blockchain === 'string' && hasOwn(CHAINS, blockchain) ? CHAINS[blockchain] : null;
    if (!chain || !VAULT_TYPES.has(vaultType)) {
        return null;
    }
    const networks = Object.entries(chain.networks).filter(([, settings]) => settings.main === (vaultType === 'main'));

    return networks.length === 1 ? networks[0][0] : null;
}

/** @returns {boolean} whether this helper can check addresses of the chain */
const isKnownChain = blockchain => typeof blockchain === 'string' && hasOwn(CHAINS, blockchain);

module.exports = {
    ADDRESS_REASONS,
    AddressVerificationError,
    ALGORITHMS,
    checkAddress,
    networkOfVault,
    isKnownChain,
};
