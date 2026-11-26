'use strict';

// The surface scripts/coverage.mjs reads, and the pinned API version.

const assert = require('node:assert/strict');
const path = require('node:path');
const { readFileSync } = require('node:fs');
const { describe, it } = require('node:test');

const sdk = require('@vaultody-com/sdk');
const { clientMethods, describeSurface } = require('../src/surface');

const ROOT = path.resolve(__dirname, '..', '..', '..', '..');

describe('surface', () => {
    it('pins the API version of the published contract', () => {
        const contract = JSON.parse(readFileSync(path.join(ROOT, 'contract', 'openapi.json'), 'utf8'));
        assert.equal(sdk.API_VERSION, contract.info.version);
        assert.equal(sdk.API_VERSION, '2026-03-20');
    });

    it('carries the one version number of the repository', () => {
        assert.equal(sdk.SDK_VERSION, readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim());
        assert.equal(require('@vaultody-com/verify/package.json').version, sdk.SDK_VERSION);
    });

    it('describes a client by walking it: only methods bound to an operation count', () => {
        const listVaults = async () => {};
        listVaults.operationId = 'listVaults';
        class Transactions {
            createSingleTransfer() {}
        }
        Transactions.prototype.createSingleTransfer.operationId = 'createSingleTransfer';
        const client = { vaults: { listVaults, helper() {} }, transactions: new Transactions(), version: '1' };
        assert.deepEqual(clientMethods(client), [
            { namespace: 'transactions', method: 'createSingleTransfer', operationId: 'createSingleTransfer' },
            { namespace: 'vaults', method: 'listVaults', operationId: 'listVaults' },
        ]);
    });

    it('has a client with one method per operation of the table, and the whole table', () => {
        const client = new sdk.Vaultody({ apiKey: 'surface', apiSecret: 'c3VyZmFjZQ==', passphrase: 'surface', vaultKeyStore: new sdk.MemoryVaultKeyStore() });
        const surface = describeSurface(client);
        assert.equal(surface.language, 'node');
        const contract = JSON.parse(readFileSync(path.join(ROOT, 'contract', 'overlay.json'), 'utf8'));
        assert.deepEqual(surface.operations.map(entry => entry.operationId).sort(), Object.keys(contract.operations).sort());
        assert.deepEqual(surface.clients.node.map(entry => entry.operationId).sort(), Object.keys(contract.operations).sort());
        for (const entry of surface.clients.node) {
            assert.equal(entry.method, entry.operationId);
        }
        // The dump carries each param as the contract states it; the schemas stay in the table.
        for (const entry of surface.operations) {
            for (const param of entry.params) {
                assert.deepEqual(Object.keys(param), ['name', 'in', 'required']);
            }
        }
    });

    it('takes retry class, paging and cursor field from contract/overlay.json', () => {
        const overlay = JSON.parse(readFileSync(path.join(ROOT, 'contract', 'overlay.json'), 'utf8')).operations;
        for (const entry of sdk.OPERATIONS) {
            const expected = overlay[entry.operationId];
            assert.equal(entry.retry, expected.retry, entry.operationId);
            assert.equal(entry.paging, expected.paging === 'offset' ? 'offset' : (expected.cursorField !== undefined ? 'cursor' : null), entry.operationId);
            if (expected.cursorField !== undefined) {
                assert.equal(entry.cursorField, expected.cursorField, entry.operationId);
            }
        }
    });
});
