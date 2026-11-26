'use strict';

/**
 * Finds the values the cases need in the API key's own data, through the Node SDK (reads only), and writes
 * them as the fixture: node discover.js <out-dir>. Ids and addresses only, never a secret.
 *
 * The choices are stable from run to run: the first test vault the API key can read (in the API's order; an
 * API key limited to some vaults still lists all of its client's, and the others answer
 * api_key_not_allowed_for_wallet, so they are skipped), its vault account with the lowest index, addresses in
 * the order the API lists them (leaving out the ones earlier runs made, labelled sdk-conformance-*), and the
 * first unspent UTXO of the chosen asset. A value the data doesn't have stays out, and the cases that need it
 * are skipped.
 */

const path = require('node:path');

const { ROOT, settings, writeJson, short } = require('./lib');
const { Vaultody, PermissionDeniedError } = require(path.join(ROOT, 'node', 'packages', 'sdk'));

const RUN_LABEL = /^sdk-conformance/;
// The answer to a vault outside the API key's vaults: that vault is skipped. Any other error ends the run.
const NOT_THE_KEYS_VAULT = 'api_key_not_allowed_for_wallet';

/**
 * The first test vault, in the API's order, whose vault accounts the API key can read, and those accounts,
 * paging through the vault list as far as it takes: { vault, accounts, listed, skipped }, vault null when none.
 */
async function firstReadableTestVault(client) {
    let listed = 0;
    let skipped = 0;
    const first = await client.vaults.listVaults({ networkType: 'test', limit: 50 });
    for await (const vault of first.autoPaging()) {
        listed += 1;
        try {
            const accounts = (await client.vaultAccounts.listVaultAccounts({ vaultId: vault.id, limit: 50 })).items;

            return { vault, accounts, listed, skipped };
        } catch (error) {
            if (!(error instanceof PermissionDeniedError && error.code === NOT_THE_KEYS_VAULT)) {
                throw error;
            }
            skipped += 1;
        }
    }

    return { vault: null, accounts: [], listed, skipped };
}

async function main() {
    const out = process.argv[2];
    if (!out) {
        throw new Error('usage: node discover.js <out-dir>');
    }
    const s = settings();
    const warnings = [];
    const client = new Vaultody({
        apiKey: s.apiKey,
        apiSecret: s.apiSecret,
        passphrase: s.passphrase,
        baseUrl: s.baseUrl,
        vaultKeysFile: path.join(out, 'pins-discover.json'),
        logger: { warn: message => warnings.push(message) },
        // The same rate as the clients' cases (VAULTODY_CONFORMANCE_RPS), else the SDK's default.
        ...(s.rps === undefined ? {} : { maxRequestsPerSecond: s.rps }),
    });
    const fixture = { discoveredAt: new Date().toISOString(), origin: s.origin };
    const note = (name, value) => {
        if (value !== undefined && value !== null && value !== '') {
            fixture[name] = value;
        }
    };

    const { vault, accounts, listed, skipped } = await firstReadableTestVault(client);
    if (!vault) {
        throw new Error(listed === 0
            ? 'the API key sees no test vault: nothing to run against'
            : `the API key may read none of the ${listed} test vaults it lists (each answered ${NOT_THE_KEYS_VAULT}): nothing to run against`);
    }
    if (skipped > 0) {
        process.stderr.write(`discover: skipped ${skipped} test vault(s) the API key may not use (${NOT_THE_KEYS_VAULT})\n`);
    }
    note('vaultId', vault.id);

    const account = [...accounts].sort((a, b) => Number(a.index) - Number(b.index))[0];
    if (!account) {
        throw new Error('the test vault has no vault account');
    }
    note('vaultAccountId', account.vaultAccountId);

    const addresses = async blockchain => (await client.assetsAddresses.listAddressesByVaultAccountId({
        vaultId: vault.id, vaultAccountId: account.vaultAccountId, blockchain, limit: 50,
    })).items.filter(a => !RUN_LABEL.test(a.label || ''));

    const eth = await addresses('ethereum');
    note('ethAddress', eth[0] && eth[0].address);
    note('ethAddress2', eth[1] && eth[1].address);

    const btc = await addresses('bitcoin');
    // An address that already holds an asset: adding that asset to it again is the API's no-write answer.
    const held = btc.find(a => Array.isArray(a.balances) && a.balances.some(b => b && b.assetId));
    if (held) {
        note('btcHeldAddress', held.address);
        note('btcAssetId', held.balances.find(b => b && b.assetId).assetId);
    }
    note('btcAddress', btc[0] && btc[0].address);
    note('btcAddress2', btc.find(a => a.address !== (btc[0] && btc[0].address)) && btc.find(a => a.address !== btc[0].address).address);

    const tron = await addresses('tron');
    note('tronAddress', tron[0] && tron[0].address);
    const xrp = await addresses('xrp');
    note('xrpAddress', xrp[0] && xrp[0].address);

    const ethAssets = (await client.assetsAddresses.listSupportedAssets({ networkType: 'test', blockchain: 'ethereum', assetUnit: 'ETH', limit: 50 })).items;
    const ethAsset = ethAssets.find(a => a.network === 'sepolia') || ethAssets[0];
    note('ethAssetId', ethAsset && ethAsset.assetId);

    if (fixture.btcAssetId) {
        // An unspent UTXO when there is one; else any of the asset's (the dry run then says the sender is not
        // valid, which still exercises the call). assetId is always sent: some environments answer 500 without it.
        const unspent = (await client.transactions.listUtxos({ vaultId: vault.id, assetId: fixture.btcAssetId, isSpent: false, limit: 5 })).items;
        const any = unspent.length ? unspent : (await client.transactions.listUtxos({ vaultId: vault.id, assetId: fixture.btcAssetId, limit: 5 })).items;
        note('utxoId', any[0] && any[0].utxoId);
        if (any[0]) {
            fixture.utxoSpent = any[0].isSpent === true;
        }
    }

    const transactions = (await client.vaults.listTransactionsByVault({ vaultId: vault.id, limit: 1 })).items;
    if (transactions[0]) {
        note('txId', transactions[0].transactionId);
        note('txBlockchain', transactions[0].blockchain);
    }

    note('transactionRequestId', process.env.VAULTODY_CONFORMANCE_TRANSACTION_REQUEST_ID);

    writeJson(path.join(out, 'fixture.json'), fixture);
    const shown = Object.fromEntries(Object.entries(fixture).map(([k, v]) => [k, short(v)]));
    process.stderr.write(`discover: ${JSON.stringify(shown)}\n`);
}

main().catch(error => {
    process.stderr.write(`discover failed: ${error.name}${error.code ? ` ${error.code}` : ''}: ${String(error.message).slice(0, 300)}\n`);
    process.exit(1);
});
