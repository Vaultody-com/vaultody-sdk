// The coverage check itself: it must pass on the repository as it is, and fail on every kind of drift.
//   node --test scripts/

import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import { GROUP_NAMESPACES, PENDING_PARAMS, TARGETS, checkCoverage, collisionsOf, loadContract, nameIn, snakeCase } from './coverage.mjs';

const CONTRACT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'contract');
const contract = loadContract();
const ALL_IDS = contract.operations.map(op => op.operationId);
const LANGUAGES = ['node', 'python', 'php'];

const opOf = id => contract.operations.find(op => op.operationId === id);
const tableEntry = id => {
    const { operationId, method, path: opPath, params } = opOf(id);

    return { operationId, method, path: opPath, params: [...params] };
};
const method = (casing, id) => ({ namespace: nameIn(casing, GROUP_NAMESPACES[opOf(id).group]), method: nameIn(casing, id), operationId: id });

/** A surface dump with every method bound and the whole operation table, as a complete SDK writes it. */
const surface = (language, overrides = {}) => ({
    language,
    sdkVersion: '0.1.0',
    apiVersion: contract.apiVersion,
    clients: Object.fromEntries(TARGETS.filter(t => t.language === language).map(t => [t.target, ALL_IDS.map(id => method(t.casing, id))])),
    operations: ALL_IDS.map(tableEntry),
    ...overrides,
});
const surfaces = () => LANGUAGES.map(language => surface(language));
const replacing = (language, overrides) => LANGUAGES.map(l => (l === language ? surface(l, overrides) : surface(l)));
const run = (input = {}) => checkCoverage({ contract, surfaces: surfaces(), sdkVersion: '0.1.0', ...input });

describe('scripts/coverage.mjs', () => {
    it('reads 32 operations: 31 published, listApiKeySigningKeys pending and without parameters', () => {
        assert.equal(contract.operations.length, 32);
        assert.deepEqual(contract.operations.filter(op => op.pending).map(op => op.operationId), ['listApiKeySigningKeys']);
        assert.deepEqual(opOf('listApiKeySigningKeys').params, []);
        assert.deepEqual(Object.keys(PENDING_PARAMS), ['listApiKeySigningKeys']);
        assert.equal(contract.apiVersion, '2026-03-20');
        assert.deepEqual(contract.problems, []);
    });

    it('names methods per language', () => {
        assert.equal(snakeCase('listAddressesByVaultAccountId'), 'list_addresses_by_vault_account_id');
        assert.equal(nameIn('snake', 'vaultAccounts'), 'vault_accounts');
        assert.equal(nameIn('camel', 'getTransactionRequestDetails'), 'getTransactionRequestDetails');
    });

    it('passes when every client has every method', () => {
        const result = run();
        assert.deepEqual(result.problems, []);
        for (const { target } of TARGETS) {
            assert.deepEqual(result.summary[target], { implemented: 32, total: 32 });
        }
    });

    it('fails on every missing method: nothing may be missing', () => {
        const empty = language => surface(language, {
            clients: Object.fromEntries(TARGETS.filter(t => t.language === language).map(t => [t.target, []])),
            operations: [],
        });
        const result = run({ surfaces: LANGUAGES.map(empty) });
        assert.equal(result.ok, false);
        assert.equal(result.problems.length, 32 * 4);

        const node = surface('node');
        node.clients.node = node.clients.node.filter(m => m.operationId !== 'listVaults');
        assert.deepEqual(run({ surfaces: [node, surface('python'), surface('php')] }).problems, ['node has no method for listVaults']);
    });

    it('fails on a method in the wrong namespace or under the wrong name', () => {
        const python = surface('python');
        python.clients['python-sync'] = python.clients['python-sync'].map(m => (m.operationId === 'listVaults' ? { ...m, method: 'listVaults' } : m));
        assert.deepEqual(run({ surfaces: [surface('node'), python, surface('php')] }).problems,
            ['python-sync vaults.listVaults implements listVaults, which belongs at vaults.list_vaults']);
    });

    it('fails on a method that is not in its operation table', () => {
        const result = run({ surfaces: replacing('php', { operations: ALL_IDS.filter(id => id !== 'listUtxos').map(tableEntry) }) });
        assert.deepEqual(result.problems, ['php transactions.listUtxos implements listUtxos, which is not in the php operation table']);
    });

    it('fails on an extra method, a second method for one operation, and an extra table entry', () => {
        const node = surface('node');
        node.clients.node.push({ namespace: 'vaults', method: 'deleteVault', operationId: 'deleteVault' }, method('camel', 'listVaults'));
        node.operations.push({ operationId: 'deleteVault', method: 'DELETE', path: '/vaults/{vaultId}', params: [] });
        const result = run({ surfaces: [node, surface('python'), surface('php')] });
        assert.deepEqual(result.problems.sort(), [
            'node has two methods for listVaults',
            'node operation table has deleteVault, which the contract does not document',
            'node vaults.deleteVault is bound to deleteVault, which the contract does not document',
        ]);
    });

    it('fails on a wrong path, method or parameter in the operation table', () => {
        const entry = tableEntry('listUtxos');
        const wrongs = [
            { ...entry, path: '/vaults/{vaultId}/utxo' },
            { ...entry, method: 'POST' },
            { ...entry, params: entry.params.map(p => (p.name === 'vaultId' ? { ...p, in: 'query' } : p)) },
            { ...entry, params: entry.params.map(p => ({ ...p, required: !p.required })) },
            { ...entry, params: entry.params.slice(1) },
        ];
        for (const wrong of wrongs) {
            const result = run({ surfaces: replacing('node', { operations: ALL_IDS.map(id => (id === 'listUtxos' ? wrong : tableEntry(id))) }) });
            assert.equal(result.problems.length, 1, JSON.stringify(result.problems));
            assert.match(result.problems[0], /^node operation table: listUtxos /);
        }
    });

    it('fails in every language when listApiKeySigningKeys takes a parameter', () => {
        for (const language of LANGUAGES) {
            const withLimit = { ...tableEntry('listApiKeySigningKeys'), params: [{ name: 'limit', in: 'query', required: false }] };
            const result = run({ surfaces: replacing(language, { operations: ALL_IDS.map(id => (id === 'listApiKeySigningKeys' ? withLimit : tableEntry(id))) }) });
            assert.equal(result.problems.length, 1, JSON.stringify(result.problems));
            assert.match(result.problems[0], new RegExp(`^${language} operation table: listApiKeySigningKeys params `));
        }
    });

    it('fails on a pending operation without declared parameters', () => {
        const dir = mkdtempSync(path.join(tmpdir(), 'coverage-contract-'));
        try {
            cpSync(CONTRACT_DIR, dir, { recursive: true });
            writeFileSync(path.join(dir, 'pending', 'api-keys', 'rotate-api-key.yaml'),
                'operation: "POST /api-keys/current/rotate"\noperationId: rotateApiKey\ngroup: api-keys\n');
            const { problems } = loadContract(dir);
            assert.ok(problems.includes('rotateApiKey is pending: declare its parameters in PENDING_PARAMS (scripts/coverage.mjs)'), JSON.stringify(problems));
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('fails when a pinned API version or an SDK version differs', () => {
        const result = run({ surfaces: [surface('node', { apiVersion: '2025-01-01' }), surface('python', { sdkVersion: '0.2.0' }), surface('php')] });
        assert.deepEqual(result.problems, [
            'node pins x-api-version 2025-01-01; the contract is 2026-03-20',
            'python is version 0.2.0; VERSION says 0.1.0',
        ]);
    });

    it('holds Python to the PEP 440 form of a release candidate, and Node and PHP to VERSION as written', () => {
        const rc = sdkVersion => [surface('node', { sdkVersion: '0.9.0-rc.1' }), surface('python', { sdkVersion }), surface('php', { sdkVersion: '0.9.0-rc.1' })];
        assert.deepEqual(run({ surfaces: rc('0.9.0rc1'), sdkVersion: '0.9.0-rc.1' }).problems, []);
        assert.deepEqual(run({ surfaces: rc('0.9.0-rc.1'), sdkVersion: '0.9.0-rc.1' }).problems,
            ['python is version 0.9.0-rc.1; VERSION says 0.9.0-rc.1 (0.9.0rc1 in Python)']);
    });

    it('fails without a dump for every language', () => {
        const result = run({ surfaces: [surface('node'), surface('python')] });
        assert.equal(result.problems[0], 'no surface dump for php');
        assert.ok(result.problems.slice(1).every(problem => /^php has no method for /.test(problem)));
    });

    it('reports a contract parameter that collides with a body field, and fails on any contract problem', () => {
        const op = opOf('createSingleTransfer');
        assert.deepEqual(collisionsOf(op), []);
        assert.deepEqual(collisionsOf({ ...op, params: [...op.params, { name: 'vaultId', in: 'body', required: false }] }),
            ['createSingleTransfer: "vaultId" is both a path and a body parameter, so a flat params argument can\'t hold it']);
        const result = checkCoverage({ contract: { ...contract, problems: ['a contract problem'] }, surfaces: surfaces(), sdkVersion: '0.1.0' });
        assert.deepEqual(result.problems, ['a contract problem']);
    });
});
