'use strict';

// Public derivation below an extended key: BIP32 for ECDSA, Vaultody's own scheme for EdDSA.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const {
    parseExtendedPublicKey, deriveEcdsaChild, deriveEddsaChild, derivePath, MAX_INDEX,
} = require('../src/address/derive');
const secp256k1 = require('../src/address/crypto/secp256k1');
const base58 = require('../src/address/crypto/base58');
const { CHAINS } = require('../src/address/chains');
const { toBytesBE } = require('../src/address/crypto/bigint');

const ecdsa = text => parseExtendedPublicKey(text, 'ECDSA');
const eddsa = text => parseExtendedPublicKey(text, 'EDDSA');

// Rewrites an extended key's 78 bytes and re-encodes it, for the malformed-key cases.
const reencode = (text, change) => {
    const bytes = Buffer.from(base58.decodeCheck(text));
    change(bytes);

    return base58.encodeCheck(bytes);
};

describe('BIP32 test vector 1, the public derivation steps', () => {
    // BIP32, "Test vector 1" (seed 000102030405060708090a0b0c0d0e0f). Only the non-hardened steps can be
    // derived from a public key: m/0H -> m/0H/1, and m/0H/1/2H -> /2 -> /1000000000.
    const TV1 = {
        'm/0H': 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
        'm/0H/1': 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
        'm/0H/1/2H': 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
        'm/0H/1/2H/2': 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
        'm/0H/1/2H/2/1000000000': 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
    };
    const sameNode = (derived, expected) => {
        assert.deepEqual(derived.key, expected.key);
        assert.deepEqual(derived.chainCode, expected.chainCode);
    };

    it('m/0H -> m/0H/1', () => sameNode(derivePath(ecdsa(TV1['m/0H']), [1]), ecdsa(TV1['m/0H/1'])));

    it('m/0H/1/2H -> m/0H/1/2H/2 -> m/0H/1/2H/2/1000000000', () => {
        const two = derivePath(ecdsa(TV1['m/0H/1/2H']), [2]);
        sameNode(two, ecdsa(TV1['m/0H/1/2H/2']));
        sameNode(derivePath(two, [1000000000]), ecdsa(TV1['m/0H/1/2H/2/1000000000']));
    });
});

describe('ECDSA keys as Vaultody stores them', () => {
    const MASTER = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
    // Child keys the server library (the xpub utilities at the version the vault service pins) derives.
    const SERVER = [
        ['m/0/0/0', '03d1b98e4f183a60bff312ac4d9ae32a9cac73ff5dd9ed6b4244f7e1c586a42d2d'],
        ['m/1/1/1', '02104fd976d89ab932358e84e770accaa81636d74ff78bf3d62c389f4b0a4735a9'],
        ['m/7/0/2147483647', '0386ecd288d9171a30ba2fbee3eff358a5320950021d552afbf35c63a55f9fb4ee'],
    ];
    const indexesOf = path => path.split('/').slice(1).map(Number);

    it('a depth-0 xpub', () => {
        for (const [path, key] of SERVER) {
            assert.equal(derivePath(ecdsa(MASTER), indexesOf(path)).key.toString('hex'), key, path);
        }
    });

    it('a tpub: the version bytes are ignored, as the server rewrites them to xpub', () => {
        const tpub = reencode(MASTER, bytes => bytes.writeUInt32BE(0x043587cf, 0));
        assert.ok(tpub.startsWith('tpub'));
        for (const [path, key] of SERVER) {
            assert.equal(derivePath(ecdsa(tpub), indexesOf(path)).key.toString('hex'), key, path);
        }
    });

    it('a depth-1 xpub with a parent fingerprint and a hardened child number', () => {
        const m0h = 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw';
        const expected = [
            ['m/0/0/0', '0241927ca610a44197de2d0492ba921c7f59224f4fd0eab7923f39f2bd4c6f5918'],
            ['m/1/1/1', '0369fcea70e095894c18f9cee0c0975939bfe20d61e89177472cdcc6847eaf6fdd'],
            ['m/7/0/2147483647', '033aa1eb2c5662292ad3713a54d3ea89cf38410a577ace0ae4155ce082d79a084a'],
        ];
        for (const [path, key] of expected) {
            assert.equal(derivePath(ecdsa(m0h), indexesOf(path)).key.toString('hex'), key, path);
        }
        // Depth, fingerprint and child number play no part: zeroing them changes nothing.
        const zeroed = reencode(m0h, bytes => bytes.fill(0, 4, 13));
        assert.deepEqual(derivePath(ecdsa(zeroed), [0, 0, 0]).key, derivePath(ecdsa(m0h), [0, 0, 0]).key);
    });

    it('refuses a malformed key', () => {
        assert.throws(() => ecdsa('xpub-not-base58'), /Base58Check/);
        assert.throws(() => ecdsa(`${MASTER.slice(0, -1)}9`), /Base58Check/);
        assert.throws(() => ecdsa(base58.encodeCheck(Buffer.alloc(77))), /78 bytes/);
        assert.throws(() => ecdsa(reencode(MASTER, bytes => { bytes[45] = 0x00; })), /02 or 03/);
        assert.throws(() => ecdsa(reencode(MASTER, bytes => bytes.fill(0xff, 46))), /field prime/);
    });
});

describe('the invalid-child rule, as hdkey applies it', () => {
    // A parent whose private key is 1, so its public key is G and the "point at infinity" case can be built.
    const parent = { key: secp256k1.compress(secp256k1.G), point: secp256k1.G, chainCode: crypto.randomBytes(32) };
    const realHmac = (key, data) => crypto.createHmac('sha512', key).update(data).digest();
    const forcing = (atIndex, il) => (key, data) => (data.readUInt32BE(data.length - 4) === atIndex
        ? Buffer.concat([toBytesBE(il, 32), crypto.randomBytes(32)])
        : realHmac(key, data));

    it('skips to the next index when I_L is not below the curve order', () => {
        for (const il of [secp256k1.N, secp256k1.N + 1n, (1n << 256n) - 1n]) {
            const child = deriveEcdsaChild(parent, 5, forcing(5, il));
            assert.deepEqual(child, deriveEcdsaChild(parent, 6));
        }
    });

    it('skips to the next index when the child is the point at infinity', () => {
        // (n - 1) * G + G = infinity
        assert.deepEqual(deriveEcdsaChild(parent, 3, forcing(3, secp256k1.N - 1n)), deriveEcdsaChild(parent, 4));
    });

    it('accepts I_L = 0, which gives the parent key itself', () => {
        assert.deepEqual(deriveEcdsaChild(parent, 9, forcing(9, 0n)).key, parent.key);
    });

    it('fails past the last non-hardened index, as hdkey does', () => {
        assert.throws(() => deriveEcdsaChild(parent, MAX_INDEX, forcing(MAX_INDEX, secp256k1.N)), /non-hardened/);
    });
});

describe('EdDSA keys: Vaultody\'s scheme', () => {
    // Synthetic test keys: RFC 8032 TEST 1 and TEST 2 public keys with made-up chain codes, at depth 0 and
    // at depth 1 with a parent fingerprint. Expected child keys, chain codes and Solana addresses are what
    // the server library (eddsaXpubHelper.derive and SolanaUtils) returns for them.
    const D0 = 'xpub661MyMwAqRbcGdpmzahNP9BjYRTDgrzjhVAFUgwYv4FfCrFDDpQvoiwRf93e7MXL1L5Tj87hqNH3WTvkn9KjqL3jnuurE7Daz2wZuXsCbbB';
    const D1 = 'xpub69XRnZc4mqU8jdHmMSzALdxnwCYJip7VLvB9EJv2kqNBtpwrfvXZBRnM2qWSs3aotL7FZ1GrpKYHvwwJFc76cD3g5KRoEb7tPuN1NphRdTw';
    const SERVER = [
        [D0, 'm/0/0/0', 'aef3a309f6936acbfda5218439398737e7e53e7d45d47b498c2d03e36964239e', '8839f0123be47e85924a9ef92aa1fcd92f2d2943cca9a8751ced0649e9e82386', 'CmwQxecGmHKpMieaF1iP1FdbvQYpfvViKFNEyX584XoK'],
        [D0, 'm/1/0/5', '311dcde4dcbd2d1aa06c60e8a34a29914e606d2a6899fa6525882d16b3740f87', 'c8b6d4687658f454082b6b4e51494a056d49d8950838b728c2d3d8b04758dea6', '4JjLW7ccV6Mb1tvM3BLV5CTKuBkAGfSfNGvwbYCPMf5g'],
        [D0, 'm/7/1/2147483647', 'fae8360cbe965e6d91edbbea1027a66dff8cdb9bfed021758b0de7421e0c153e', '0fac658a3c6777a760a8bcabadeb8471b9667c6171ffafa63fe1b328937b97b9', 'HtSJ18dw4PaLdVWvHQZdn4gNJ8CDVv4ZQoBSJwZXxS6Z'],
        [D1, 'm/0/0/0', '8051ca3aae1494f7ac944096c98331bd74fbbad882d16f6fb32c9fa7eec918ff', '0aac4b710a2e20e84ac86a26a2dc0b5afd8f1e55b807f8f5d3065042d7c49a5d', '9duXCrrckRx8xpo55acCEtGMmB3C16nhSNKLLaGM7kMU'],
        [D1, 'm/1/0/5', '69248dca1878521cfef0d3d75e29f84b24c530a0da180e573c650f7425114074', 'bbadf4aa23ef07b6091cb06049ac0c81ea3edaf7a7bc2911d8b75091034b615c', '85S8vpZ413pe4a4pFBHEyDJUx7RTkEwu8u8mfvwJo355'],
        [D1, 'm/7/1/2147483647', 'f8c80c59451693cbc8604f5899faba086337b19a3ee86079ca195d398b865aae', '07aec85adb5c490a47cd793e713a3d5039591fd4ae9d63643628eb9d26d3e546', 'Hk92u531BQrZNd4AfWypL3GV2ziFc4cPthgLk2myu1yX'],
    ];
    for (const [xpub, path, key, chainCode, address] of SERVER) {
        it(`${xpub === D0 ? 'depth 0' : 'depth 1'} at ${path}`, () => {
            const node = derivePath(eddsa(xpub), path.split('/').slice(1).map(Number));
            assert.equal(node.key.toString('hex'), key);
            assert.equal(node.chainCode.toString('hex'), chainCode);
            assert.equal(CHAINS.solana.formats.base58(node, CHAINS.solana.networks.mainnet), address);
        });
    }

    it('writes the index little-endian and reads the HMAC big-endian', () => {
        // Rebuild one step by hand from the description, independent of deriveEddsaChild's code.
        const parent = eddsa(D0);
        const indexLE = Buffer.from([5, 0, 0, 0]);
        const hmac = prefix => crypto.createHmac('sha256', parent.chainCode).update(Buffer.concat([Buffer.from([prefix]), parent.key, indexLE])).digest();
        const child = deriveEddsaChild(parent, 5);
        assert.deepEqual(child.chainCode, hmac(0x03));
        const ed25519 = require('../src/address/crypto/ed25519');
        assert.deepEqual(child.key, ed25519.encode(ed25519.multiply(BigInt(`0x${hmac(0x02).toString('hex')}`), parent.point)));
    });

    it('refuses an index above 2^31 - 1, which the server code would wrap or refuse', () => {
        assert.throws(() => deriveEddsaChild(eddsa(D0), MAX_INDEX + 1), /hardened/);
    });

    it('refuses a key whose first key byte is not 00, or that is not on the curve', () => {
        assert.throws(() => eddsa(reencode(D0, bytes => { bytes[45] = 0x02; })), /00 followed by/);
        // y = 2 has no x on ed25519.
        assert.throws(() => eddsa(reencode(D0, bytes => { bytes.fill(0, 46); bytes[46] = 2; })), /not on the curve/);
        // An ECDSA key read as EdDSA, and the other way round.
        const tv1 = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
        assert.throws(() => eddsa(tv1), /00 followed by/);
        assert.throws(() => ecdsa(D0), /02 or 03/);
    });
});
