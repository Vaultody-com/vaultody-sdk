'use strict';

// The check every API method runs on its params before anything is sent (src/params.js): required fields,
// types, documented values, unknown fields at any depth, and errors that name the field but never its value.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { ParameterError, operationById } = require('../src');
const { validateParams } = require('../src/params');

const TRANSFER = Object.freeze({
    vaultId: 'v', amount: '0.1', assetId: 'a', fromAddress: 'f', toAddress: 't', note: 'n', vaultAccountId: 'va',
});
const UTXO = Object.freeze({
    vaultId: 'v', assetId: 'a', feePriority: 'standard', note: 'n',
    recipients: [{ address: 'r', amount: '1' }], senders: [{ utxoId: 'u' }],
});

const check = (operationId, params) => validateParams(operationById(operationId), params);
const refused = (operationId, params, code, param) => assert.throws(() => check(operationId, params), error => {
    assert.ok(error instanceof ParameterError, String(error));
    assert.equal(error.code, code, error.message);
    assert.equal(error.param, param);

    return true;
});

describe('params against the API reference', () => {
    it('accepts the documented fields, with optional ones left out or undefined', () => {
        check('createSingleTransfer', TRANSFER);
        check('createSingleTransfer', { ...TRANSFER, gross: false, feePriority: 'fast', feeInput: { total: '0.001' }, maxFee: undefined });
        check('createUtxoTransfer', { ...UTXO, changeData: { vaultAccountId: 'va' } });
        check('listUtxos', { vaultId: 'v', isSpent: true, limit: 50 });
        check('listSupportedAssets', {});
        check('listApiKeySigningKeys', {});
    });

    it('refuses a missing required field, at the top and nested', () => {
        refused('createSingleTransfer', { ...TRANSFER, amount: undefined }, 'missing_param', 'amount');
        refused('createSingleTransfer', (({ vaultId, ...rest }) => rest)(TRANSFER), 'missing_param', 'vaultId');
        refused('createUtxoTransfer', { ...UTXO, recipients: [{ address: 'r', amount: '1' }, { address: 'r2' }] }, 'missing_param', 'recipients[1].amount');
        refused('createBatchTransactionRequest', { vaultId: 'v', fromAddress: 'f', note: 'n', recipients: [], feePayer: { address: 'x' } }, 'missing_param', 'feePayer.assetId');
    });

    it('refuses a field the operation does not have, at any depth', () => {
        refused('createSingleTransfer', { ...TRANSFER, amont: '1' }, 'unknown_param', 'amont');
        refused('createSingleTransfer', { ...TRANSFER, feeInput: { total: '1', tip: '2' } }, 'unknown_param', 'feeInput.tip');
        refused('createUtxoTransfer', { ...UTXO, senders: [{ utxoId: 'u', index: 0 }] }, 'unknown_param', 'senders[0].index');
        refused('listApiKeySigningKeys', { limit: 2 }, 'unknown_param', 'limit');
        refused('listApiKeySigningKeys', { offset: 0 }, 'unknown_param', 'offset');
        // context and the API version are never params: context is a call option, the version is pinned.
        refused('getTransactionRequestDetails', { transactionRequestId: 't', context: 'c' }, 'unknown_param', 'context');
    });

    it('refuses a value of the wrong type, never converting it', () => {
        refused('createSingleTransfer', { ...TRANSFER, amount: 0.1 }, 'invalid_param', 'amount');
        refused('createSingleTransfer', { ...TRANSFER, gross: 'true' }, 'invalid_param', 'gross');
        refused('createSingleTransfer', { ...TRANSFER, feeInput: 'fast' }, 'invalid_param', 'feeInput');
        refused('createSingleTransfer', { ...TRANSFER, feeInput: { acknowledgeHighFee: 1 } }, 'invalid_param', 'feeInput.acknowledgeHighFee');
        refused('createUtxoTransfer', { ...UTXO, recipients: { address: 'r', amount: '1' } }, 'invalid_param', 'recipients');
        refused('createUtxoTransfer', { ...UTXO, recipients: [null] }, 'invalid_param', 'recipients[0]');
        refused('createUtxoTransfer', { ...UTXO, recipients: [{ address: 'r', amount: 1 }] }, 'invalid_param', 'recipients[0].amount');
        refused('listUtxos', { vaultId: 'v', isSpent: 'false' }, 'invalid_param', 'isSpent');
        refused('encodeXrpAddress', { network: 'testnet', classicAddress: 'r', addressTag: 123 }, 'invalid_param', 'addressTag');
        refused('getTransactionRequestDetails', { transactionRequestId: 7 }, 'invalid_param', 'transactionRequestId');
    });

    it('refuses null: no field is nullable', () => {
        refused('createSingleTransfer', { ...TRANSFER, maxFee: null }, 'invalid_param', 'maxFee');
        refused('createSingleTransfer', { ...TRANSFER, amount: null }, 'invalid_param', 'amount');
    });

    it('page sizes: whole numbers from 1 to the documented maximum', () => {
        for (const limit of [1, 50]) {
            check('listVaults', { networkType: 'main', limit });
        }
        for (const limit of [0, -1, 51, 1.5, '10', Number.NaN, 2 ** 60]) {
            refused('listVaults', { networkType: 'main', limit }, 'invalid_param', 'limit');
        }
    });

    it('documented values only, exactly as written', () => {
        refused('listVaults', { networkType: 'MAIN' }, 'invalid_param', 'networkType');
        refused('createSingleTransfer', { ...TRANSFER, feePriority: 'medium' }, 'invalid_param', 'feePriority');
        refused('generateDepositAddress', { vaultId: 'v', blockchain: 'bitcoin', network: 'regtest', label: 'l', vaultAccountId: 'a' }, 'invalid_param', 'network');
        refused('tronResourceOverview', { vaultId: 'v', blockchain: 'ethereum', network: 'nile', address: 'a' }, 'invalid_param', 'blockchain');
        // Each operation's own list: multiple transfers say minimize-dust, the fee estimate minimize_dust.
        const multiple = { vaultId: 'v', assetId: 'a', feePriority: 'slow', note: 'n', recipients: [], vaultAccountId: 'va' };
        check('createMultipleTransfer', { ...multiple, prepareStrategy: 'minimize-dust' });
        refused('createMultipleTransfer', { ...multiple, prepareStrategy: 'minimize_dust' }, 'invalid_param', 'prepareStrategy');
        check('estimateTransactionFeeByAssetId', { vaultId: 'v', transactionType: 'multiple', vaultAccountId: 'va', prepareStrategy: 'minimize_dust' });
        // No list where the document gives none (the UTXO transfers' feePriority).
        check('createUtxoTransfer', { ...UTXO, feePriority: 'anything' });
    });

    it('params must be a plain object', () => {
        for (const params of [null, [], 'x', new Map(), new (class Params {})()]) {
            assert.throws(() => check('listSupportedAssets', params), error => error instanceof ParameterError && error.code === 'invalid_params');
        }
        check('listSupportedAssets', Object.create(null));
    });

    it('names the field and the operation, never the value', () => {
        const secretish = 'do-not-echo-this-value';
        for (const params of [{ ...TRANSFER, amount: { secretish } }, { ...TRANSFER, feePriority: secretish }, { ...TRANSFER, [secretish.slice(0, 5)]: secretish }]) {
            assert.throws(() => check('createSingleTransfer', params), error => {
                assert.match(error.message, /^createSingleTransfer: /);
                assert.ok(!error.message.includes(secretish), error.message);

                return true;
            });
        }
    });
});
