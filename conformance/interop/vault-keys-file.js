'use strict';

/**
 * The Node helper of conformance/interop/run.mjs: one JSON command on stdin, one JSON answer on stdout, through
 * the Node SDK's own file store (protocol in run.mjs).
 */

const path = require('node:path');

const { FileVaultKeyStore, VaultKeyStoreError } = require(path.join(__dirname, '..', '..', 'node', 'packages', 'sdk', 'src'));

const byVaultId = pins => [...pins].sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1));

async function run(request) {
    const store = new FileVaultKeyStore({ file: request.file });
    if (request.op === 'write') {
        for (const step of request.steps) {
            if (step.pin) {
                await store.pinIfAbsent(step.pin.origin, step.pin.pin);
            } else if (step.latch) {
                await store.latchResponseSignature(step.latch.origin, step.latch.latch);
            } else {
                throw new Error('a step is { pin } or { latch }');
            }
        }

        return { ok: true };
    }
    if (request.op === 'read') {
        const origins = {};
        for (const origin of request.origins) {
            origins[origin] = { responseSignature: await store.getResponseSignatureLatch(origin), pins: byVaultId(await store.list(origin)) };
        }

        return { ok: true, origins };
    }
    throw new Error(`unknown op ${request.op}`);
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
    run(JSON.parse(input)).then(answer => {
        process.stdout.write(JSON.stringify(answer));
    }, error => {
        if (error instanceof VaultKeyStoreError) {
            process.stdout.write(JSON.stringify({ ok: false, error: error.code }));
            return;
        }
        process.stderr.write(`${error.stack || error}\n`);
        process.exitCode = 1;
    });
});
