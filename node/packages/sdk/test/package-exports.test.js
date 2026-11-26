'use strict';

// Every name the package exports, imported both ways an application does: require() and ESM `import { X }`. Node
// reads a CommonJS module's names for ESM from the shape of its `module.exports = { ... }`; a spread or an
// `a: b.c` hides the rest, and only a real import shows it (cjs-module-lexer). The root's names are listed here by
// hand, so adding or dropping one is a decision; every entry point in package.json "exports" is checked.

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { describe, it } = require('node:test');

const manifest = require('../package.json');

const ROOT_NAMES = [
    // the client
    'Vaultody', 'API_VERSION', 'SDK_VERSION', 'OPERATIONS', 'operationById', 'RESPONSE_SIGNATURE_MODES', 'SECURITY_EVENTS',
    // every error class, and reading an answer into a result or one
    'VaultodyError', 'ApiError', 'AuthenticationError', 'RequestSigningError', 'PermissionDeniedError', 'NotFoundError',
    'InvalidRequestError', 'ConflictError', 'DuplicateTransferError', 'RateLimitError', 'ServerError',
    'RequestOutcomeUnknownError', 'TransportError', 'ParameterError', 'PaginationError', 'VaultKeyChangedError',
    'AddressVerificationError', 'ResponseVerificationError', 'ConfigurationError', 'WebhookSignatureError',
    'WebhookPayloadError', 'VaultKeyStoreError', 'errorClassFor', 'readEnvelope',
    // retries, paging, request targets
    'RETRY', 'decideRetry', 'paginate', 'Page', 'Pager', 'classifyTransportError', 'buildRequestTarget', 'percentEncode',
    // vault xpub pins, address checks and the stores
    'PIN_STATUS', 'ADDRESS_CHECK_STATUS', 'readVaultList', 'observeVaults', 'addressCheckStatus', 'xpubHash',
    'MemoryVaultKeyStore', 'FileVaultKeyStore', 'defaultVaultKeysFile',
    // signers
    'pemSigner', 'fileSigner', 'awsKmsSigner', 'gcpKmsSigner', 'vaultTransitSigner',
    // webhooks
    'verifyWebhook', 'WEBHOOK_EVENTS',
];

const PACKAGE_DIR = path.join(__dirname, '..');
const ENTRY_POINTS = Object.keys(manifest.exports)
    .filter(subpath => !subpath.endsWith('.json'))
    .map(subpath => (subpath === '.' ? manifest.name : `${manifest.name}/${subpath.slice(2)}`));

describe(`${manifest.name}: every export by require() and by ESM import`, () => {
    it('the root exports exactly its public names', () => {
        assert.deepEqual(Object.keys(require(manifest.name)).sort(), [...ROOT_NAMES].sort());
    });

    for (const specifier of ENTRY_POINTS) {
        it(`${specifier}: each CommonJS export is an ESM named export with the same value`, async () => {
            const cjs = require(specifier);
            const esm = await import(specifier);
            const names = Object.keys(cjs);
            assert.ok(names.length > 0);
            for (const name of names) {
                assert.ok(Object.prototype.hasOwnProperty.call(esm, name), `import { ${name} } from '${specifier}' finds nothing`);
                assert.equal(esm[name], cjs[name], name);
            }
            assert.equal(esm.default, cjs);
        });

        it(`${specifier}: import { ...every name } links in an ES module`, () => {
            const names = Object.keys(require(specifier));
            const source = [
                `import { ${names.join(', ')} } from '${specifier}';`,
                `import { createRequire } from 'node:module';`,
                `const cjs = createRequire(${JSON.stringify(path.join(PACKAGE_DIR, 'package.json'))})('${specifier}');`,
                `const differ = Object.entries({ ${names.join(', ')} }).filter(([name, value]) => cjs[name] !== value);`,
                `if (differ.length > 0) { throw new Error('not the CommonJS value: ' + differ.map(([name]) => name).join(', ')); }`,
            ].join('\n');
            execFileSync(process.execPath, ['--input-type=module', '-e', source], { cwd: PACKAGE_DIR, stdio: ['ignore', 'pipe', 'pipe'] });
        });
    }
});
