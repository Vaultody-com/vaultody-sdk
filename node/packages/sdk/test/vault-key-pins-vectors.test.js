'use strict';

// test-vectors/vault-key-pins-v1.json: signed and unsigned vault lists, verified with @vaultody-com/verify, and
// what they do to the vault xpub pins. A case's configured pins (pinnedVaultKeys) take the place of the stored pin
// of their vault; the pins after each step are the store's alone.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { verifyResponse, ResponseSignatureError } = require('@vaultody-com/verify');
const vaultKeys = require('../src/vaultKeys');
const { VaultKeyChangedError, AddressVerificationError } = require('../src/errors');
const { load } = require('./vectors');

const VECTORS = load('vault-key-pins-v1.json');
const RESPONSE_VECTORS = load('v1.json');

const rootPem = name => crypto.createPublicKey({ key: Buffer.from(RESPONSE_VECTORS.keys.roots[name].publicKeySpkiDerBase64, 'base64'), format: 'der', type: 'spki' })
    .export({ format: 'pem', type: 'spki' });
const sortPins = pins => [...pins].sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1));

describe('test-vectors/vault-key-pins-v1.json', () => {
    const roots = VECTORS.pinnedRoots.map(rootPem);

    for (const vector of VECTORS.cases) {
        it(vector.name, () => {
            let pins = new Map(vector.initialPins.map(pin => [pin.vaultId, pin]));
            const configured = vaultKeys.readConfiguredPins(vector.configuredPins);
            const seen = () => new Map([...pins, ...configured]);
            for (const step of vector.steps) {
                const { request, response, now, expected } = step;
                const body = Buffer.from(response.bodyBase64, 'base64');
                let verdict;
                try {
                    verdict = verifyResponse({
                        request: {
                            method: request.method,
                            url: request.query === '' ? request.path : `${request.path}?${request.query}`,
                            body: Buffer.from(request.bodyBase64, 'base64'),
                            apiSign: request.apiSign,
                            keypairSign: request.keypairSign,
                        },
                        response: { status: response.status, headers: response.headers, body },
                    }, { roots, now, requireResponseSignature: false });
                } catch (error) {
                    if (!(error instanceof ResponseSignatureError)) {
                        throw error;
                    }
                    assert.deepEqual({ error: error.reason }, expected.signature);
                    assert.deepEqual(sortPins(pins.values()), expected.pinsAfter);
                    continue;
                }
                assert.equal(verdict.verified ? 'verified' : 'absent', expected.signature);

                const vaults = vaultKeys.readVaultList(JSON.parse(body.toString('utf8')).data.items);
                const evidence = verdict.verified ? { signed: true, rootId: verdict.rootId, timestamp: verdict.timestamp, now } : { signed: false, now };
                if (expected.alarms) {
                    assert.throws(() => vaultKeys.observeVaults(seen(), vaults, evidence), error => {
                        assert.ok(error instanceof VaultKeyChangedError);
                        assert.deepEqual(error.alarms, expected.alarms);
                        for (const xpub of Object.values(RESPONSE_VECTORS.keys)) {
                            assert.ok(!error.message.includes(String(xpub)));
                        }

                        return true;
                    });
                } else {
                    const { outcomes, changes } = vaultKeys.observeVaults(seen(), vaults, evidence);
                    assert.deepEqual(outcomes, expected.outcomes);
                    pins = new Map(pins);
                    for (const pin of changes) {
                        assert.ok(!configured.has(pin.vaultId), 'a configured pin is never written');
                        pins.set(pin.vaultId, pin);
                    }
                }
                assert.deepEqual(sortPins(pins.values()), expected.pinsAfter);
            }
        });
    }

    for (const check of VECTORS.addressChecks) {
        it(`address check: ${check.name}`, () => {
            const configured = vaultKeys.readConfiguredPins([{ vaultId: 'v', type: 'main', keys: { ECDSA: 'xpub-test-only', EDDSA: null } }]).get('v');
            // pathRequired absent: requireAddressPaths off.
            const pathRequired = check.pathRequired ? vaultKeys.addressPathRequired(check.pathRequired) : false;
            const input = {
                pin: check.pin === null ? null : (check.pin === 'configured' ? configured : { status: check.pin }),
                vaultHasKeys: check.vaultHasKeys,
                pathFields: check.pathFields,
                derivation: check.derivation,
                pathRequired,
            };
            if (check.expected.error) {
                assert.throws(() => vaultKeys.addressCheckStatus(input), error => error instanceof AddressVerificationError && error.code === check.expected.error);
            } else {
                assert.equal(vaultKeys.addressCheckStatus(input), check.expected.status);
            }
        });
    }

    it('a new algorithm on a pinned vault and a type change are refused, also when the vault list names the test type', () => {
        const [first] = VECTORS.cases.find(vector => vector.name === 'first_sight_signed').steps[0].expected.pinsAfter;
        const ecdsaOnly = { ...first, keys: { ECDSA: first.keys.ECDSA, EDDSA: null } };
        const pins = new Map([[first.vaultId, ecdsaOnly]]);
        assert.throws(() => vaultKeys.observeVaults(pins, [{ vaultId: first.vaultId, type: 'main', keys: first.keys }], { signed: true, now: 1 }),
            error => error.alarms[0].reason === 'xpub_added' && error.alarms[0].pinned === null);
        assert.throws(() => vaultKeys.observeVaults(new Map([[first.vaultId, first]]), [{ vaultId: first.vaultId, type: 'test', keys: first.keys }], { signed: true, now: 1 }),
            error => error.alarms[0].reason === 'type_changed');
    });
});
