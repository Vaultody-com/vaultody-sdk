'use strict';

// test-vectors/address-v1.json: addresses as the vault service's own derivation code returns them (511 cases on 17
// chains, and 13 inputs the server refuses). Every case must verify exactly against its xpub, with the format as
// stored and with no format at all; a changed address must fail; no refused input may verify. The file holds
// `change` as the generator wrote it; the API field is `isChange`.

const assert = require('node:assert/strict');
const path = require('node:path');
const { describe, it } = require('node:test');

const { checkAddress, networkOfVault, AddressVerificationError } = require('../src/address');
const { parseExtendedPublicKey, derivePath } = require('../src/address/derive');
const { CHAINS, isRefusedFormat } = require('../src/address/chains');

const VECTORS = require(path.join(__dirname, '..', '..', '..', '..', 'test-vectors', 'address-v1.json'));

const typeOf = (blockchain, network) => VECTORS.chains[blockchain].networks[network].vaultType.toLowerCase();
const vaultOf = (algorithm, xpub, type) => ({ type, keys: { ECDSA: algorithm === 'ECDSA' ? xpub : null, EDDSA: algorithm === 'EDDSA' ? xpub : null } });
const paramsOf = c => ({
    blockchain: c.blockchain,
    network: c.network,
    accountIndex: c.accountIndex,
    isChange: c.change,
    addressIndex: c.addressIndex,
    addressFormat: c.addressFormat,
    address: c.address,
});

describe('test-vectors/address-v1.json', () => {
    it('is the v1 format, with cases and refused inputs', () => {
        assert.equal(VECTORS.format, 'vaultody address derivation vectors v1');
        assert.equal(VECTORS.cases.length, 511);
        assert.equal(VECTORS.rejected.length, 13);
    });

    it('lists exactly the chains, networks, algorithms and wire formats this helper knows, with the same prefixes', () => {
        assert.deepEqual(Object.keys(VECTORS.chains).sort(), Object.keys(CHAINS).sort());
        for (const [blockchain, chain] of Object.entries(VECTORS.chains)) {
            const ours = CHAINS[blockchain];
            assert.equal(ours.algorithm, chain.algorithm, blockchain);
            assert.deepEqual(Object.keys(ours.formats).sort(), [...chain.addressFormatsWire].sort(), blockchain);
            assert.deepEqual(Object.keys(ours.networks).sort(), Object.keys(chain.networks).sort(), blockchain);
            for (const [network, settings] of Object.entries(chain.networks)) {
                const mine = ours.networks[network];
                assert.equal(mine.main, settings.vaultType === 'MAIN', `${blockchain} ${network}`);
                for (const field of ['pubKeyHash', 'scriptHash']) {
                    if (mine[field] !== undefined) {
                        assert.equal(Buffer.from(mine[field]).toString('hex'), settings[field], `${blockchain} ${network} ${field}`);
                    }
                }
                if (mine.bech32 !== undefined) {
                    assert.equal(mine.bech32, settings.bech32, `${blockchain} ${network} bech32`);
                }
                // The SDK infers the network of an address from its vault's type when a response omits it.
                assert.equal(networkOfVault(blockchain, settings.vaultType.toLowerCase()), network, `${blockchain} ${network}`);
            }
        }
    });

    describe('every case verifies, with the format as stored and with no format at all', () => {
        const roots = new Map();
        for (const c of VECTORS.cases) {
            it(c.name, () => {
                const vault = vaultOf(c.algorithm, c.xpub, typeOf(c.blockchain, c.network));
                const expected = { verified: true, algorithm: c.algorithm, path: c.path, address: c.address, addressFormat: c.addressFormatWire };
                assert.deepEqual(checkAddress(vault, paramsOf(c)), expected);
                assert.deepEqual(checkAddress(vault, { ...paramsOf(c), addressFormat: undefined }), expected);
                if (!roots.has(c.xpub)) {
                    roots.set(c.xpub, parseExtendedPublicKey(c.xpub, c.algorithm));
                }
                assert.equal(derivePath(roots.get(c.xpub), [c.accountIndex, c.change ? 1 : 0, c.addressIndex]).key.toString('hex'), c.publicKey);
            });
        }
    });

    it('a changed address fails with mismatch, for one case of every chain, network and format', () => {
        const seen = new Set();
        for (const c of VECTORS.cases) {
            const group = `${c.blockchain}/${c.network}/${c.addressFormatWire}`;
            if (seen.has(group)) {
                continue;
            }
            seen.add(group);
            const last = c.address.slice(-1);
            const address = c.address.slice(0, -1) + (last === 'a' ? 'b' : 'a');
            const vault = vaultOf(c.algorithm, c.xpub, typeOf(c.blockchain, c.network));
            assert.throws(() => checkAddress(vault, { ...paramsOf(c), address }), error => error instanceof AddressVerificationError && error.reason === 'mismatch', group);
        }
    });

    it('the key of the other algorithm, or the other vault type, never verifies', () => {
        const c = VECTORS.cases.find(item => item.algorithm === 'ECDSA' && item.network === 'mainnet');
        assert.throws(() => checkAddress({ type: 'main', keys: { ECDSA: null, EDDSA: c.xpub } }, paramsOf(c)), error => error.reason === 'missing_key');
        assert.throws(() => checkAddress(vaultOf(c.algorithm, c.xpub, 'test'), paramsOf(c)), error => error.reason === 'network_mismatch');
    });

    it('an address without its derivation path is not verifiable, never verified', () => {
        const c = VECTORS.cases[0];
        const vault = vaultOf(c.algorithm, c.xpub, typeOf(c.blockchain, c.network));
        const params = { ...paramsOf(c), accountIndex: undefined };
        assert.throws(() => checkAddress(vault, params), error => error.reason === 'not_verifiable');
        assert.deepEqual(checkAddress(vault, params, { allowUnverifiable: true }), { verified: false, reason: 'not_verifiable' });
    });

    describe('no input the server refuses is reported as verified', () => {
        for (const r of VECTORS.rejected) {
            it(`${r.name} (${r.reason})`, () => {
                const sample = VECTORS.cases.find(c => c.xpubName === r.xpubName && c.blockchain === r.blockchain) || VECTORS.cases[0];
                const chain = VECTORS.chains[r.blockchain];
                const type = chain && chain.networks[r.network] ? chain.networks[r.network].vaultType.toLowerCase() : 'test';
                const params = { ...paramsOf(r), address: sample.address };
                assert.throws(() => checkAddress(vaultOf(r.algorithm, r.xpub, type), params), error => error instanceof TypeError
                    || (error instanceof AddressVerificationError && ['unsupported', 'mismatch'].includes(error.reason)));
                if (isRefusedFormat(r.blockchain, r.addressFormatWire)) {
                    assert.throws(() => checkAddress(vaultOf(r.algorithm, r.xpub, type), params), error => error.reason === 'unsupported');
                }
            });
        }
    });
});
