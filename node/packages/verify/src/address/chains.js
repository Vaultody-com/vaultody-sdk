'use strict';

/**
 * Every chain the helper can check, with its signing algorithm, its networks and the address formats
 * the server can issue on it.
 *
 * Chain and network names are those of the public API paths. The version bytes, Bech32 prefixes and
 * format names come from the Vaultody server's xpub utilities library; the server stores format names in
 * upper case and the API returns them in lower case. The algorithm per chain comes from the server's protocol settings: Solana uses EdDSA and every
 * other chain ECDSA.
 */

const crypto = require('node:crypto');

const base58 = require('./crypto/base58');
const bech32 = require('./crypto/bech32');
const cashaddr = require('./crypto/cashaddr');
const secp256k1 = require('./crypto/secp256k1');
const { keccak256 } = require('./crypto/keccak');
const { ripemd160 } = require('./crypto/ripemd160');
const { ALGORITHMS } = require('./derive');

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest();
const hash160 = bytes => ripemd160(sha256(bytes));

// The redeem script of P2SH-P2WPKH: OP_0, push 20 bytes, the key hash.
const p2wpkhScript = keyHash => Buffer.concat([Buffer.from([0x00, 0x14]), keyHash]);

// Each encoder takes a derived node ({ key, point }) and the network's settings.
const ENCODERS = {
    p2pkh: ({ key }, net) => base58.encodeCheck(Buffer.concat([Buffer.from(net.pubKeyHash), hash160(key)])),
    // The server's "P2SH" is P2SH wrapping P2WPKH (bitcoinjs payments.p2sh({ redeem: p2wpkh })) on every
    // chain that offers it, including those without SegWit.
    p2sh: ({ key }, net) => base58.encodeCheck(Buffer.concat([Buffer.from(net.scriptHash), hash160(p2wpkhScript(hash160(key)))])),
    p2wpkh: ({ key }, net) => bech32.segwitV0Address(net.bech32, hash160(key)),
    'p2pkh-cash': ({ key }, net) => cashaddr.encode(net.cashPrefix, cashaddr.TYPE_P2PKH, hash160(key)),
    'p2sh-cash': ({ key }, net) => cashaddr.encode(net.cashPrefix, cashaddr.TYPE_P2SH, hash160(p2wpkhScript(hash160(key)))),
    // XRP: the account ID (hash160 of the compressed key) after a 00 type byte, in XRP's Base58 alphabet.
    classic: ({ key }) => base58.encodeCheck(Buffer.concat([Buffer.from([0x00]), hash160(key)]), base58.RIPPLE_ALPHABET),
    // Ethereum and its relatives: 0x, then the last 20 bytes of Keccak-256 over the uncompressed x || y,
    // in lower case as the server returns them.
    standard: ({ point }) => `0x${keccak256(secp256k1.rawXY(point)).subarray(12).toString('hex')}`,
    // Tron: the Ethereum-style 20 bytes after a 41 byte, Base58Check.
    'tron-base58': ({ point }) => base58.encodeCheck(Buffer.concat([Buffer.from([0x41]), keccak256(secp256k1.rawXY(point)).subarray(12)])),
    // Solana: the 32-byte ed25519 public key itself, in Base58.
    'solana-base58': ({ key }) => base58.encode(key),
};

const EVM_NETWORKS = test => ({ mainnet: { main: true }, [test]: { main: false } });

function chain(algorithm, formats, networks, caseInsensitive = false) {
    return Object.freeze({
        algorithm,
        // true where addresses are hex and may be written with EIP-55 capitals (the EVM chains)
        caseInsensitive,
        // format name as returned by the API -> encoder
        formats: Object.freeze(Object.fromEntries(Object.entries(formats).map(([name, encoder]) => [name, ENCODERS[encoder]]))),
        networks: Object.freeze(Object.fromEntries(Object.entries(networks).map(([name, settings]) => [name, Object.freeze(settings)]))),
    });
}

const BITCOIN_FORMATS = { p2pkh: 'p2pkh', p2sh: 'p2sh', p2wpkh: 'p2wpkh' };
const LEGACY_FORMATS = { p2pkh: 'p2pkh', p2sh: 'p2sh' };
const EVM_FORMATS = { standard: 'standard' };

const CHAINS = Object.freeze({
    bitcoin: chain(ALGORITHMS.ECDSA, BITCOIN_FORMATS, {
        mainnet: { main: true, pubKeyHash: [0x00], scriptHash: [0x05], bech32: 'bc' },
        testnet: { main: false, pubKeyHash: [0x6f], scriptHash: [0xc4], bech32: 'tb' },
    }),
    litecoin: chain(ALGORITHMS.ECDSA, BITCOIN_FORMATS, {
        mainnet: { main: true, pubKeyHash: [0x30], scriptHash: [0x32], bech32: 'ltc' },
        testnet: { main: false, pubKeyHash: [0x6f], scriptHash: [0xc4], bech32: 'tltc' },
    }),
    dogecoin: chain(ALGORITHMS.ECDSA, LEGACY_FORMATS, {
        mainnet: { main: true, pubKeyHash: [0x1e], scriptHash: [0x16] },
        testnet: { main: false, pubKeyHash: [0x71], scriptHash: [0xc4] },
    }),
    dash: chain(ALGORITHMS.ECDSA, LEGACY_FORMATS, {
        mainnet: { main: true, pubKeyHash: [0x4c], scriptHash: [0x10] },
        testnet: { main: false, pubKeyHash: [0x8c], scriptHash: [0x13] },
    }),
    // CashAddr forms are the legacy address re-encoded; the prefix follows the network, as bchaddrjs
    // picks it from the legacy version byte.
    'bitcoin-cash': chain(ALGORITHMS.ECDSA, { ...LEGACY_FORMATS, 'p2pkh-cash': 'p2pkh-cash', 'p2sh-cash': 'p2sh-cash' }, {
        mainnet: { main: true, pubKeyHash: [0x00], scriptHash: [0x05], cashPrefix: 'bitcoincash' },
        testnet: { main: false, pubKeyHash: [0x6f], scriptHash: [0xc4], cashPrefix: 'bchtest' },
    }),
    // Transparent Zcash addresses carry a two-byte version.
    zcash: chain(ALGORITHMS.ECDSA, { p2pkh: 'p2pkh' }, {
        mainnet: { main: true, pubKeyHash: [0x1c, 0xb8] },
        testnet: { main: false, pubKeyHash: [0x1d, 0x25] },
    }),
    xrp: chain(ALGORITHMS.ECDSA, { classic: 'classic' }, { mainnet: { main: true }, testnet: { main: false } }),
    tron: chain(ALGORITHMS.ECDSA, { base58: 'tron-base58' }, { mainnet: { main: true }, nile: { main: false } }),
    solana: chain(ALGORITHMS.EDDSA, { base58: 'solana-base58' }, { mainnet: { main: true }, devnet: { main: false } }),
    ethereum: chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('sepolia'), true),
    'ethereum-classic': chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('mordor'), true),
    'binance-smart-chain': chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('testnet'), true),
    polygon: chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('amoy'), true),
    arbitrum: chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('sepolia'), true),
    optimism: chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('sepolia'), true),
    base: chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('sepolia'), true),
    avalanche: chain(ALGORITHMS.ECDSA, EVM_FORMATS, EVM_NETWORKS('fuji'), true),
});

/** The settings for a chain and network, or null when this helper does not know the pair. */
function chainNetwork(blockchain, network) {
    const settings = Object.prototype.hasOwnProperty.call(CHAINS, blockchain) ? CHAINS[blockchain] : null;
    if (!settings || !Object.prototype.hasOwnProperty.call(settings.networks, network)) {
        return null;
    }

    return { chain: settings, network: settings.networks[network] };
}

// Formats this helper refuses, per chain. Bitcoin Cash, Dogecoin and Dash have no SegWit, but the server
// library once derived their `p2sh` (and Bitcoin Cash's `p2sh-cash`) as P2SH-wrapped P2WPKH. Anyone can spend
// coins sent to such an address, so it must never be reported as genuine. The server no longer derives these
// and none exist in production.
const REFUSED_FORMATS = Object.freeze({
    'bitcoin-cash': Object.freeze(['p2sh', 'p2sh-cash']),
    dogecoin: Object.freeze(['p2sh']),
    dash: Object.freeze(['p2sh']),
});

const isRefusedFormat = (blockchain, format) => (REFUSED_FORMATS[blockchain] || []).includes(format);

module.exports = {
    REFUSED_FORMATS,
    isRefusedFormat,
    CHAINS,
    chainNetwork,
    hash160,
};
