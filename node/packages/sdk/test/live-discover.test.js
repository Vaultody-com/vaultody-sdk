'use strict';

// conformance/live/discover.js as a separate process against the mock gateway (conformance/mock-gateway), unsigned
// as a test environment answers: the vault it chooses when the API key may use only some of the test vaults
// it lists. The live run itself never runs in CI; this holds its choice of vault to the API key's scope.

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it } = require('node:test');

const { startMockGateway } = require('../../../../conformance/mock-gateway');
const { CREDENTIALS } = require('./helpers');

const DISCOVER = path.resolve(__dirname, '..', '..', '..', '..', 'conformance', 'live', 'discover.js');
const SECRETS = [CREDENTIALS.apiSecret, CREDENTIALS.passphrase];
const vaultId = n => `6630f1c2a9e4b5d7c8e9${n.toString(16).padStart(4, '0')}`;
const answer = data => ({ status: 200, body: { apiVersion: '2026-03-20', requestId: 'r', data } });
const refusal = code => ({ status: 403, body: { requestId: 'r', error: { code, message: 'no' } } });

/**
 * Runs discover.js against a mock gateway listing `count` test vaults; `refused(id)` names the code a vault's
 * vault accounts answer with, or null for a vault the API key may read. Every other list is empty.
 */
async function discover({ count, refused }) {
    const gw = await startMockGateway({
        signing: false,
        keys: { [CREDENTIALS.apiKey]: { secret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, keypairs: [] } },
    });
    gw.vaults.test = Array.from({ length: count }, (_, i) => ({ id: vaultId(i + 1), type: 'test', name: `Vault ${i + 1}` }));
    const asked = [];
    gw.route('GET', /^\/vaults\/[0-9a-f]{24}\/vault-accounts\/details$/, request => {
        const id = request.path.split('/')[2];
        asked.push(id);
        const code = refused(id);

        return code ? refusal(code) : answer({ limit: 50, hasMore: false, items: [{ vaultAccountId: `acc-${id}`, index: '0', name: 'Default' }] });
    });
    gw.route('GET', /^\/vaults\/[0-9a-f]{24}\/(vault-accounts\/[^/]+\/list-addresses|transactions)$/, () => answer({ limit: 50, hasMore: false, items: [] }));
    gw.route('GET', /^\/supported-assets$/, () => answer({ limit: 50, hasMore: false, items: [] }));
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-discover-'));
    try {
        const run = await new Promise(resolve => {
            execFile(process.execPath, [DISCOVER, out], {
                env: {
                    PATH: process.env.PATH,
                    VAULTODY_BASE_URL: gw.url,
                    VAULTODY_API_KEY: CREDENTIALS.apiKey,
                    VAULTODY_API_SECRET: CREDENTIALS.apiSecret,
                    VAULTODY_PASSPHRASE: CREDENTIALS.passphrase,
                    VAULTODY_CONFORMANCE_RPS: '1000',
                },
                encoding: 'utf8',
            }, (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr }));
        });
        for (const secret of SECRETS) {
            assert.ok(!(run.stdout + run.stderr).includes(secret), 'nothing secret is printed');
        }
        const file = path.join(out, 'fixture.json');
        const fixture = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;

        return { ...run, fixture, asked, listRequests: gw.requests.filter(r => r.path === '/vaults/test').length };
    } finally {
        fs.rmSync(out, { recursive: true, force: true });
        await gw.close();
    }
}

describe('conformance/live/discover.js: the vault it runs against', () => {
    it('skips a first vault the API key may not use and takes the second, in the API\'s order', async () => {
        const run = await discover({ count: 3, refused: id => (id === vaultId(1) ? 'api_key_not_allowed_for_wallet' : null) });
        assert.equal(run.code, 0, run.stderr);
        assert.equal(run.fixture.vaultId, vaultId(2));
        assert.equal(run.fixture.vaultAccountId, `acc-${vaultId(2)}`);
        assert.deepEqual(run.asked, [vaultId(1), vaultId(2)]);
        assert.match(run.stderr, /skipped 1 test vault\(s\) the API key may not use \(api_key_not_allowed_for_wallet\)/);
    });

    it('pages through the vault list when no vault of the first page can be read', async () => {
        const run = await discover({ count: 52, refused: id => (id === vaultId(52) ? null : 'api_key_not_allowed_for_wallet') });
        assert.equal(run.code, 0, run.stderr);
        assert.equal(run.fixture.vaultId, vaultId(52));
        assert.equal(run.listRequests, 2);
        assert.equal(run.asked.length, 52);
    });

    it('fails with a clear message when the API key may read none of the vaults it lists', async () => {
        const run = await discover({ count: 2, refused: () => 'api_key_not_allowed_for_wallet' });
        assert.equal(run.code, 1);
        assert.equal(run.fixture, null);
        assert.match(run.stderr, /discover failed: Error: the API key may read none of the 2 test vaults it lists \(each answered api_key_not_allowed_for_wallet\)/);
    });

    it('stops at any other refusal instead of trying the next vault', async () => {
        const run = await discover({ count: 2, refused: id => (id === vaultId(1) ? 'endpoint_not_allowed_for_api_key' : null) });
        assert.equal(run.code, 1);
        assert.equal(run.fixture, null);
        assert.deepEqual(run.asked, [vaultId(1)]);
        assert.match(run.stderr, /discover failed: PermissionDeniedError endpoint_not_allowed_for_api_key/);
    });
});
