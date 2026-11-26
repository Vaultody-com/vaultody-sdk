'use strict';

// `vaultody vault-keys accept` against the mock gateway (conformance/mock-gateway): the vault lists come signed by
// the TEST-ONLY current root, or unsigned, and the pin file is a real file in a temporary directory. The command
// shows the pinned and the new fingerprints, re-pins only with --yes, and an SDK client then accepts the vault.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { describe, it } = require('node:test');

const { main } = require('../bin/vaultody');
const { Vaultody, VaultKeyChangedError } = require('../src');
const { FileVaultKeyStore } = require('../src/vaultKeyStore');
const { xpubHash } = require('../src/vaultKeys');
const { startMockGateway, fakeClock, rootPem } = require('../../../../conformance/mock-gateway');
const { CREDENTIALS, T0, VAULT } = require('./helpers');
const { load } = require('./vectors');

const ADDRESSES = load('address-v1.json');
const [ECDSA_OLD, ECDSA_NEW] = [...new Set(ADDRESSES.xpubs.filter(item => item.algorithm === 'ECDSA').map(item => item.xpub))];
const EDDSA = ADDRESSES.xpubs.find(item => item.algorithm === 'EDDSA').xpub;
const XPUBS = [ECDSA_OLD, ECDSA_NEW, EDDSA];
const ENV = Object.freeze({ VAULTODY_API_KEY: CREDENTIALS.apiKey, VAULTODY_API_SECRET: CREDENTIALS.apiSecret, VAULTODY_PASSPHRASE: CREDENTIALS.passphrase });
const SECRETS = Object.values(ENV);

/** The --expect value of a vault's type and keys, as the run without --yes prints it. */
const expectOf = ({ ECDSA = null, EDDSA: eddsa = null }, type = 'main') => `type=${type},ECDSA=${ECDSA ? xpubHash(ECDSA) : '-'},EDDSA=${eddsa ? xpubHash(eddsa) : '-'}`;

const pinOf = ({ ECDSA = null, EDDSA: eddsa = null }, { type = 'main', status = 'verified' } = {}) => ({
    vaultId: VAULT,
    type,
    keys: { ECDSA, EDDSA: eddsa },
    status,
    firstSeenAt: 1794200000,
    verifiedAt: status === 'verified' ? 1794200000 : null,
    verification: status === 'verified' ? { rootId: 'test-root', timestamp: 1794200000 } : null,
});
const listed = ({ ECDSA = null, EDDSA: eddsa = null }, type = 'main') => ({
    id: VAULT,
    type,
    name: 'Vault',
    mpcKeys: [...(ECDSA ? [{ algorithm: 'ECDSA', xpub: ECDSA }] : []), ...(eddsa ? [{ algorithm: 'EDDSA', xpub: eddsa }] : [])],
});

/** A mock gateway listing `vaults`, and a pin file holding `pinned` for its origin. */
async function scenario({ pinned = null, vaults = {}, signing = { root: 'current' }, latched = false } = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-accept-'));
    const file = path.join(dir, 'vault-keys.json');
    const rootFile = path.join(dir, 'root.pem');
    fs.writeFileSync(rootFile, rootPem('current'));
    const clock = fakeClock(T0);
    const gw = await startMockGateway({
        clock,
        signing,
        keys: { [CREDENTIALS.apiKey]: { secret: CREDENTIALS.apiSecret, passphrase: CREDENTIALS.passphrase, keypairs: [] } },
    });
    gw.vaults.main = vaults.main || [];
    gw.vaults.test = vaults.test || [];
    const origin = new URL(gw.url).origin;
    const store = new FileVaultKeyStore({ file });
    if (pinned) {
        await store.pinIfAbsent(origin, pinned);
    }
    if (latched) {
        await store.latchResponseSignature(origin, { latchedAt: 1794200000, rootId: 'test-root' });
    }

    const run = async (args, { env = ENV } = {}) => {
        const stdout = [];
        const stderr = [];
        const code = await main(['vault-keys', 'accept', '--root', gw.url, '--file', file, ...args], {
            env, stdout: text => stdout.push(text), stderr: text => stderr.push(text), now: T0 / 1000, sleep: async () => {},
        });
        const out = { code, stdout: stdout.join(''), stderr: stderr.join('') };
        for (const secret of [...SECRETS, ...XPUBS]) {
            assert.ok(!out.stdout.includes(secret) && !out.stderr.includes(secret), 'nothing secret, and no xpub, is printed');
        }

        return out;
    };
    const client = () => new Vaultody({
        ...CREDENTIALS,
        baseUrl: gw.url,
        roots: [rootPem('current')],
        vaultKeysFile: file,
        logger: { warn() {} },
        onSecurityEvent() {},
        unsupported: { clock },
    });

    return { gw, store, origin, file, rootFile, run, client, close: () => gw.close() };
}

describe('vaultody vault-keys accept', () => {
    it('shows the pinned and the new fingerprints, and changes nothing without --yes; prints the --expect that accepts them', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] } });
        try {
            const out = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile]);
            assert.equal(out.code, 1);
            assert.match(out.stdout, new RegExp(`ECDSA +${xpubHash(ECDSA_OLD)} +${xpubHash(ECDSA_NEW)} +changed`));
            assert.match(out.stdout, /type +main +main\n/);
            assert.match(out.stdout, /signed and verified/);
            assert.match(out.stderr, /nothing was changed[\s\S]*--yes/);
            assert.ok(out.stderr.includes(`\n  --yes --expect ${expectOf({ ECDSA: ECDSA_NEW })}\n`), out.stderr);
            assert.deepEqual(await env.store.get(env.origin, VAULT), pinOf({ ECDSA: ECDSA_OLD }));
        } finally {
            await env.close();
        }
    });

    it('with --yes re-pins from a signed list, records why, and the SDK accepts the vault again', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] } });
        try {
            await assert.rejects(env.client().vaults.listVaults({ networkType: 'main' }), error => error instanceof VaultKeyChangedError);

            const out = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--yes', '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(out.code, 0, out.stderr);
            // The comparison comes before the replace.
            assert.match(out.stdout, new RegExp(`ECDSA +${xpubHash(ECDSA_OLD)} +${xpubHash(ECDSA_NEW)} +changed[\\s\\S]*Re-pinned vault .* as verified\\.\\n$`));
            const pin = await env.store.get(env.origin, VAULT);
            assert.deepEqual(pin.keys, { ECDSA: ECDSA_NEW, EDDSA: null });
            assert.equal(pin.status, 'verified');
            const audit = JSON.parse(fs.readFileSync(env.file, 'utf8')).origins[env.origin].audit;
            assert.equal(audit.length, 1);
            assert.equal(audit[0].vaultId, VAULT);
            assert.equal(audit[0].reason, `re-pinned with vaultody vault-keys accept: ECDSA ${xpubHash(ECDSA_OLD)} -> ${xpubHash(ECDSA_NEW)}`);

            const page = await env.client().vaults.listVaults({ networkType: 'main' });
            assert.deepEqual(page.meta.vaultKeys, [{ vaultId: VAULT, status: 'verified', outcome: 'unchanged' }]);
        } finally {
            await env.close();
        }
    });

    it('a key added to the vault and a type change: both shown, and re-pinned together', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { test: [listed({ ECDSA: ECDSA_OLD, EDDSA }, 'test')] } });
        try {
            const out = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--yes', '--expect', expectOf({ ECDSA: ECDSA_OLD, EDDSA }, 'test')]);
            assert.equal(out.code, 0, out.stderr);
            assert.match(out.stdout, /type +main +test +changed/);
            assert.match(out.stdout, new RegExp(`ECDSA +${xpubHash(ECDSA_OLD)} +${xpubHash(ECDSA_OLD)}\n`));
            assert.match(out.stdout, new RegExp(`EDDSA +- +${xpubHash(EDDSA)} +added`));
            const pin = await env.store.get(env.origin, VAULT);
            assert.equal(pin.type, 'test');
            assert.deepEqual(pin.keys, { ECDSA: ECDSA_OLD, EDDSA });
        } finally {
            await env.close();
        }
    });

    it('an unsigned list exits 4 unless --allow-unsigned, and then the new pin is unverified', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] }, signing: false });
        try {
            const refused = await env.run(['--vault-id', VAULT, '--yes', '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(refused.code, 4);
            assert.match(refused.stderr, /not signed.*\n.*Nothing was changed/);
            assert.equal((await env.store.get(env.origin, VAULT)).keys.ECDSA, ECDSA_OLD);

            const accepted = await env.run(['--vault-id', VAULT, '--allow-unsigned', '--yes', '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(accepted.code, 0, accepted.stderr);
            assert.match(accepted.stdout, /not signed: the new pin is unverified/);
            const pin = await env.store.get(env.origin, VAULT);
            assert.equal(pin.keys.ECDSA, ECDSA_NEW);
            assert.equal(pin.status, 'unverified');
        } finally {
            await env.close();
        }
    });

    it('a pin file that has seen a signed answer from this API never takes an unsigned one', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] }, signing: false, latched: true });
        try {
            const out = await env.run(['--vault-id', VAULT, '--allow-unsigned', '--yes', '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(out.code, 4);
            assert.match(out.stderr, /--allow-unsigned is ignored/);
            assert.equal((await env.store.get(env.origin, VAULT)).keys.ECDSA, ECDSA_OLD);
        } finally {
            await env.close();
        }
    });

    it('nothing to accept: no pin, a vault not listed, a vault without keys, or a pin that already matches', async () => {
        const none = await scenario({ vaults: { main: [listed({ ECDSA: ECDSA_NEW })] } });
        try {
            const out = await none.run(['--vault-id', VAULT, '--response-root-key', none.rootFile, '--yes', '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(out.code, 1);
            assert.match(out.stderr, /has no pin for vault/);
        } finally {
            await none.close();
        }

        const gone = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }) });
        try {
            const out = await gone.run(['--vault-id', VAULT, '--response-root-key', gone.rootFile, '--yes', '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(out.code, 1);
            assert.match(out.stderr, /in neither GET \/vaults\/main nor GET \/vaults\/test/);
        } finally {
            await gone.close();
        }

        const keyless = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({})] } });
        try {
            const out = await keyless.run(['--vault-id', VAULT, '--response-root-key', keyless.rootFile, '--yes', '--expect', expectOf({})]);
            assert.equal(out.code, 1);
            assert.match(out.stderr, /without MPC keys/);
            assert.equal((await keyless.store.get(keyless.origin, VAULT)).keys.ECDSA, ECDSA_OLD);
        } finally {
            await keyless.close();
        }

        const same = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_OLD })] } });
        try {
            const out = await same.run(['--vault-id', VAULT, '--response-root-key', same.rootFile]);
            assert.equal(out.code, 0);
            assert.match(out.stdout, /already matches/);
            assert.equal(JSON.parse(fs.readFileSync(same.file, 'utf8')).origins[same.origin].audit.length, 0);
        } finally {
            await same.close();
        }
    });

    it('--expect that differs from what the API shows: refused, the file untouched', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] } });
        try {
            const before = fs.readFileSync(env.file, 'utf8');
            for (const expect of [expectOf({ ECDSA: ECDSA_OLD }), expectOf({ ECDSA: ECDSA_NEW, EDDSA }), expectOf({ ECDSA: ECDSA_NEW }, 'test')]) {
                const out = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--yes', '--expect', expect]);
                assert.equal(out.code, 1, expect);
                assert.ok(out.stderr.includes(`the API shows ${expectOf({ ECDSA: ECDSA_NEW })}, not the --expect ${expect}; nothing was changed`), out.stderr);
                assert.equal(fs.readFileSync(env.file, 'utf8'), before);
            }
        } finally {
            await env.close();
        }
    });

    it('the answer changes between the run that shows it and the run with --yes: refused', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] } });
        try {
            const shown = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile]);
            const line = shown.stderr.match(/--yes --expect (\S+)/)[1];
            assert.equal(line, expectOf({ ECDSA: ECDSA_NEW }));
            env.gw.vaults.main = [listed({ ECDSA: ECDSA_NEW, EDDSA })];
            const out = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--yes', '--expect', line]);
            assert.equal(out.code, 1);
            assert.match(out.stderr, /nothing was changed/);
            assert.deepEqual(await env.store.get(env.origin, VAULT), pinOf({ ECDSA: ECDSA_OLD }));
        } finally {
            await env.close();
        }
    });

    it('--yes without --expect, --expect without --yes, and a malformed --expect are usage errors, before anything is sent', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] } });
        try {
            const noExpect = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--yes']);
            assert.equal(noExpect.code, 2);
            assert.match(noExpect.stderr, /--yes needs --expect type=<main\|test>,ECDSA=<fingerprint\|->,EDDSA=<fingerprint\|->/);
            const noYes = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(noYes.code, 2);
            assert.match(noYes.stderr, /--expect goes with --yes/);
            for (const bad of ['ECDSA=-,EDDSA=-', `type=main,ECDSA=${xpubHash(ECDSA_NEW)}`, `type=MAIN,ECDSA=-,EDDSA=-`, `type=main,ECDSA=${xpubHash(ECDSA_NEW).toUpperCase()},EDDSA=-`,
                'type=main,ECDSA=-,EDDSA=-,ECDSA=-', 'type=main,ECDSA=-,EDDSA=-,SCHNORR=-', 'type=main,ECDSA,EDDSA=-']) {
                const out = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--yes', '--expect', bad]);
                assert.equal(out.code, 2, bad);
                assert.match(out.stderr, /--expect must be type=<main\|test>/, bad);
            }
            assert.equal(env.gw.requests.length, 0);
            assert.deepEqual(await env.store.get(env.origin, VAULT), pinOf({ ECDSA: ECDSA_OLD }));
        } finally {
            await env.close();
        }
    });

    it('response-signing root keys and an unsigned list: exit 4, nothing read or changed', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }), vaults: { main: [listed({ ECDSA: ECDSA_NEW })] }, signing: false });
        try {
            const out = await env.run(['--vault-id', VAULT, '--response-root-key', env.rootFile, '--yes', '--expect', expectOf({ ECDSA: ECDSA_NEW })]);
            assert.equal(out.code, 4, out.stderr);
            assert.match(out.stderr, /not signed.*\n.*refused before it is read\. Nothing was changed/);
            assert.equal((await env.store.get(env.origin, VAULT)).keys.ECDSA, ECDSA_OLD);
        } finally {
            await env.close();
        }
    });

    it('usage errors: no --vault-id, credentials missing from the environment, an unreadable pin file', async () => {
        const env = await scenario({ pinned: pinOf({ ECDSA: ECDSA_OLD }) });
        try {
            const noVault = await env.run([]);
            assert.equal(noVault.code, 2);
            assert.match(noVault.stderr, /--vault-id is required/);
            assert.match(noVault.stderr, /vaultody vault-keys accept --help/);

            const noCredentials = await env.run(['--vault-id', VAULT], { env: {} });
            assert.equal(noCredentials.code, 2);
            assert.match(noCredentials.stderr, /VAULTODY_API_KEY/);

            fs.writeFileSync(env.file, 'not json', { mode: 0o600 });
            const broken = await env.run(['--vault-id', VAULT]);
            assert.equal(broken.code, 2);
            assert.match(broken.stderr, /pin file can't be used \(not_json\)/);
        } finally {
            await env.close();
        }
    });

    it('is listed in the help', async () => {
        const stdout = [];
        assert.equal(await main(['--help'], { stdout: text => stdout.push(text), stderr: () => {} }), 0);
        assert.match(stdout.join(''), /vault-keys accept/);
        const help = [];
        assert.equal(await main(['vault-keys', 'accept', '--help'], { stdout: text => help.push(text), stderr: () => {} }), 0);
        assert.match(help.join(''), /--yes +replace the pin/);
        assert.match(help.join(''), /--expect +the type and fingerprints/);
    });
});
