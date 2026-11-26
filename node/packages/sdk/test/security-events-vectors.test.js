'use strict';

// test-vectors/security-events-v1.json: the security events' names and fields, and the entries of the per-answer
// results, the same in every language. The catalogue the client builds events from is the vector's; every event
// a pipeline test sees is checked against it (test/helpers.js); and one run through the pipeline raises the
// common events and returns both kinds of results, all with exactly the vector's fields.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { SECURITY_EVENTS, AddressVerificationError, VaultKeyStoreError, MemoryVaultKeyStore } = require('../src');
const { securityEvent } = require('../src/securityEvents');
const internal = require('../src/internal');
const { setup, VAULT } = require('./helpers');
const { load } = require('./vectors');

const VECTORS = load('security-events-v1.json');
const ADDRESSES = load('address-v1.json');
const sorted = list => [...list].sort();

describe('test-vectors/security-events-v1.json', () => {
    it('the client\'s catalogue is the vector\'s: the same types, each with the same fields', () => {
        assert.deepEqual(sorted(Object.keys(SECURITY_EVENTS)), sorted(VECTORS.events.map(event => event.type)));
        for (const event of VECTORS.events) {
            assert.deepEqual(SECURITY_EVENTS[event.type], event.fields, event.type);
        }
    });

    it('an event has exactly its fields: one not given is null; a field or a type not catalogued is refused', () => {
        for (const event of VECTORS.events) {
            const built = securityEvent({ type: event.type, origin: 'https://rest.example.test' });
            assert.deepEqual(Object.keys(built), event.fields);
            assert.equal(built.type, event.type);
            assert.equal(built.origin, 'https://rest.example.test');
            assert.ok(event.fields.filter(field => !['type', 'origin'].includes(field)).every(field => built[field] === null));
            assert.ok(Object.isFrozen(built));
            assert.throws(() => securityEvent({ type: event.type, origin: 'https://rest.example.test', extra: 'x' }), TypeError);
        }
        assert.throws(() => securityEvent({ type: 'vault_key_upgraded' }), TypeError);
        assert.throws(() => securityEvent({ type: 'address_mismatch' }), TypeError);
    });

    it('through the pipeline: the events raised and the results returned have exactly the vector\'s fields', async () => {
        const c = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.addressFormatWire === 'p2wpkh');
        const other = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.address !== c.address && item.xpub !== c.xpub);
        // A release candidate that embeds the roots: unsigned answers until the gateway signs, then verified.
        const env = await setup({ signing: false, roots: 'embedded' });
        try {
            env.gw.vaults.main = [{ id: VAULT, type: 'main', name: 'Vault', mpcKeys: [{ algorithm: 'ECDSA', xpub: c.xpub }] }];
            let item = { address: c.address, label: 'deposit', accountIndex: c.accountIndex, isChange: c.change, addressIndex: c.addressIndex, addressFormat: c.addressFormatWire };
            env.gw.route('POST', /\/addresses$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item } } }));
            const generate = () => internal.request(env.client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'deposit', vaultAccountId: '6630f1c2a9e4b5d7c8e9f0e2' });

            // Unsigned: accepted (unsigned_response_accepted), the vault pinned unverified (vault_key_pinned).
            const first = await generate();
            // Signed: the latch (response_signature_latched), the pin confirmed (vault_key_verified).
            env.gw.signing = { root: 'current' };
            await generate();
            const page = await internal.request(env.client, 'listVaults', { networkType: 'main' });
            // A swapped address: address_verification_failed.
            item = { ...item, address: other.address };
            await assert.rejects(generate(), AddressVerificationError);

            const fieldsOf = new Map(VECTORS.events.map(event => [event.type, event.fields]));
            const seen = new Set(env.events.map(event => event.type));
            for (const type of ['unsigned_response_accepted', 'vault_key_pinned', 'response_signature_latched', 'vault_key_verified', 'address_verification_failed']) {
                assert.ok(seen.has(type), `no ${type} raised`);
            }
            for (const event of env.events) {
                assert.deepEqual(sorted(Object.keys(event)), sorted(fieldsOf.get(event.type)), event.type);
            }
            assert.deepEqual(env.events.find(event => event.type === 'address_verification_failed'),
                { type: 'address_verification_failed', origin: env.client.origin, operationId: 'generateDepositAddress', vaultId: VAULT, code: 'mismatch' });

            for (const check of first.meta.addressChecks) {
                assert.deepEqual(Object.keys(check), VECTORS.addressCheck.fields);
                assert.ok(VECTORS.addressCheck.status.includes(check.status));
            }
            for (const result of page.meta.vaultKeys) {
                assert.deepEqual(Object.keys(result), VECTORS.vaultKeyResult.fields);
                assert.ok(VECTORS.vaultKeyResult.status.includes(result.status) && VECTORS.vaultKeyResult.outcome.includes(result.outcome));
            }
        } finally {
            await env.close();
        }
    });

    const c = ADDRESSES.cases.find(item => item.blockchain === 'bitcoin' && item.network === 'mainnet' && item.addressFormatWire === 'p2wpkh');
    const depositItem = fields => ({ address: c.address, label: 'deposit', accountIndex: c.accountIndex, isChange: c.change, addressIndex: c.addressIndex, addressFormat: c.addressFormatWire, ...fields });
    const generate = client => internal.request(client, 'generateDepositAddress', { vaultId: VAULT, blockchain: 'bitcoin', network: 'mainnet', label: 'deposit', vaultAccountId: '6630f1c2a9e4b5d7c8e9f0e2' });

    it('address codes: an item on another network than asked is network_mismatch, on another chain mismatch', async () => {
        const codes = VECTORS.addressCodes.map(entry => entry.code);
        assert.ok(codes.includes('network_mismatch') && codes.includes('mismatch'));
        for (const [fields, code] of [[{ network: 'testnet' }, 'network_mismatch'], [{ blockchain: 'litecoin' }, 'mismatch'], [{ network: 'mainnet', blockchain: 'bitcoin' }, null]]) {
            const env = await setup();
            try {
                env.gw.vaults.main = [{ id: VAULT, type: 'main', name: 'Vault', mpcKeys: [{ algorithm: 'ECDSA', xpub: c.xpub }] }];
                env.gw.route('POST', /\/addresses$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item: depositItem(fields) } } }));
                if (code === null) {
                    assert.equal((await generate(env.client)).meta.addressChecks[0].status, 'verified');
                } else {
                    await assert.rejects(generate(env.client), error => error instanceof AddressVerificationError && error.code === code);
                    assert.equal(env.events.find(event => event.type === 'address_verification_failed').code, code);
                    assert.ok(codes.includes(code));
                }
            } finally {
                await env.close();
            }
        }
    });

    it('logging: with no hook every event is logged once as a warning, its JSON; with a hook nothing is; a hook that raises is logged', async () => {
        // [hook, events logged, 'hook raised' lines]: two events are raised (unsigned_response_accepted, vault_key_pinned).
        for (const [hook, expectLines, expectRaised] of [[undefined, true, 0], [() => {}, false, 0], [() => { throw new Error('hook down'); }, false, 2]]) {
            const env = await setup({ signing: false, client: { onSecurityEvent: hook } });
            try {
                env.gw.vaults.main = [{ id: VAULT, type: 'main', name: 'Vault', mpcKeys: [{ algorithm: 'ECDSA', xpub: c.xpub }] }];
                env.gw.route('POST', /\/addresses$/, () => ({ status: 201, body: { apiVersion: '2026-03-20', requestId: 'r', data: { item: depositItem({}) } } }));
                await generate(env.client);
                const lines = env.warnings.filter(message => message.startsWith('Vaultody security event: '));
                const raised = env.warnings.filter(message => message.startsWith('the security event hook raised on '));
                if (expectLines) {
                    const logged = lines.map(line => JSON.parse(line.slice('Vaultody security event: '.length)));
                    assert.deepEqual(logged.map(event => event.type), ['unsigned_response_accepted', 'vault_key_pinned']);
                    assert.deepEqual(Object.keys(logged[1]), SECURITY_EVENTS.vault_key_pinned);
                    assert.ok(!lines.join('\n').includes(c.xpub), 'no xpub in a log line');
                } else {
                    assert.deepEqual(lines, []);
                }
                assert.equal(raised.length, expectRaised);
            } finally {
                await env.close();
            }
        }
    });

    it('store_conflict: a pin removed by another writer between the read and the write refuses the answer', async () => {
        const inner = new MemoryVaultKeyStore();
        const store = {
            get: (...a) => inner.get(...a),
            list: (...a) => inner.list(...a),
            pinIfAbsent: async () => null,
            upgradeTrust: async () => null,
            getResponseSignatureLatch: (...a) => inner.getResponseSignatureLatch(...a),
            latchResponseSignature: (...a) => inner.latchResponseSignature(...a),
        };
        const env = await setup({ client: { vaultKeyStore: store } });
        try {
            env.gw.vaults.main = [{ id: VAULT, type: 'main', name: 'Vault', mpcKeys: [{ algorithm: 'ECDSA', xpub: c.xpub }] }];
            await assert.rejects(internal.request(env.client, 'listVaults', { networkType: 'main' }), error => error instanceof VaultKeyStoreError && error.code === 'store_conflict');
        } finally {
            await env.close();
        }
    });
});
