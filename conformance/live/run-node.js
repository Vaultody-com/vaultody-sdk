'use strict';

/**
 * The live conformance cases through the Node SDK: node run-node.js <out-dir>. Reads cases.json and
 * <out-dir>/fixture.json, writes <out-dir>/results-node.json. It records what happened; report.js judges every
 * language by the same rules. Nothing secret is written or printed.
 */

const fs = require('node:fs');
const path = require('node:path');

const { ROOT, CASES, settings, wrongPassphrase, testRootPem, resolveParams, SEED_ORIGINS, seedPinFile, pinFileFacts, summarizeRead, short, isObject, writeJson } = require('./lib');
const sdk = require(path.join(ROOT, 'node', 'packages', 'sdk'));

const { Vaultody, ApiError, FileVaultKeyStore, MemoryVaultKeyStore, VaultKeyStoreError } = sdk;
const CLIENT = 'node';
const CONTEXT = 'sdk-conformance';
const MAX_PAGE = 50;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/** fetch, recording each request: method, path, nonce, status (and the limit a 429 names). */
function countingFetch(log) {
    return async (url, init) => {
        const target = new URL(url);
        const record = { method: init.method, path: target.pathname, nonce: init.headers['x-api-nonce'], at: Date.now() };
        log.push(record);
        try {
            const response = await fetch(url, init);
            record.status = response.status;
            if (response.status === 429) {
                try {
                    const body = await response.clone().json();
                    record.limit = body && body.error && body.error.details;
                } catch (e) {
                    // an unreadable body is the SDK's to report
                }
            }
            return response;
        } catch (error) {
            record.error = (error.cause && error.cause.code) || error.name;
            throw error;
        }
    };
}

function errorOf(error) {
    return {
        class: error && error.constructor ? error.constructor.name : typeof error,
        apiError: error instanceof ApiError,
        status: error && error.status !== undefined ? error.status : null,
        code: error && error.code !== undefined ? error.code : null,
        reason: error && error.reason !== undefined ? error.reason : null,
        message: String(error && error.message).slice(0, 200),
    };
}

function envelopeOf(meta) {
    return {
        requestId: typeof meta.requestId === 'string' && meta.requestId !== '',
        apiVersion: meta.apiVersion,
        context: meta.context === CONTEXT,
        replayed: meta.replayed === true,
        signature: meta.signature,
    };
}

function countStatuses(checks) {
    const out = {};
    for (const check of checks || []) {
        out[check.status] = (out[check.status] || 0) + 1;
    }
    return out;
}

function fieldOf(item, spec, expected) {
    if (!spec.field) {
        return undefined;
    }
    const value = isObject(item) ? item[spec.field] : undefined;
    const out = { name: spec.field, present: value !== undefined && value !== null };
    if (spec.equals !== undefined) {
        out.equalsExpected = value === expected;
    }
    return out;
}

async function main() {
    const out = process.argv[2];
    if (!out) {
        throw new Error('usage: node run-node.js <out-dir>');
    }
    const s = settings();
    const fixture = JSON.parse(fs.readFileSync(path.join(out, 'fixture.json'), 'utf8'));
    const runId = process.env.VAULTODY_CONFORMANCE_RUN_ID || String(Date.now());
    const log = [];
    const events = [];
    const warnings = new Set();
    const pinFile = path.join(out, `pins-${CLIENT}.json`);
    seedPinFile(pinFile);
    const make = (overrides = {}) => new Vaultody({
        apiKey: s.apiKey,
        apiSecret: s.apiSecret,
        passphrase: overrides.passphrase || s.passphrase,
        baseUrl: s.baseUrl,
        // A client given response-signing roots gets its own in-memory store: the run's pin file is never touched by it.
        ...(overrides.roots ? { roots: overrides.roots, vaultKeyStore: new MemoryVaultKeyStore() } : { vaultKeysFile: pinFile }),
        maxRequestsPerSecond: overrides.maxRequestsPerSecond === undefined ? s.rps : overrides.maxRequestsPerSecond,
        onSecurityEvent: event => events.push({
            type: event.type, vaultId: short(event.vaultId), outcome: event.outcome, status: event.status, reason: event.reason, code: event.code, operationId: event.operationId,
            // The unsigned notice must carry exactly these fields in every language.
            ...(event.type === 'unsigned_response_accepted' ? { fields: Object.keys(event).sort(), originIsRun: event.origin === s.origin } : {}),
        }),
        logger: { warn: message => warnings.add(String(message).slice(0, 200)) },
        unsupported: { fetch: countingFetch(log) },
    });
    const client = make();
    const items = {};
    const ctx = { fixture, results: items, client: CLIENT, run: runId };
    const resolve = params => resolveParams(params, ctx);
    const method = (c, group, op) => c[group][op].bind(c[group]);

    async function runCase(spec) {
        const result = { id: spec.id, group: spec.group, op: spec.op, class: spec.class, kind: spec.kind };
        const resolved = resolve(spec.params);
        if (resolved.missing) {
            return { ...result, skipped: `no ${resolved.missing}` };
        }
        const params = resolved.params;
        const expected = spec.equals === undefined ? undefined : resolve({ v: spec.equals }).params.v;
        const before = log.length;
        try {
            if (spec.kind === 'item') {
                const answer = await method(client, spec.group, spec.op)(params, { context: CONTEXT });
                result.outcome = 'ok';
                result.envelope = envelopeOf(answer.meta);
                result.typed = `item:${Array.isArray(answer.item) ? 'array' : typeof answer.item}`;
                result.field = fieldOf(answer.item, spec, expected);
                if (answer.meta.addressChecks) {
                    result.addressChecks = countStatuses(answer.meta.addressChecks);
                }
                items[spec.id] = answer.item;
            } else {
                const paging = spec.paging || {};
                const first = await method(client, spec.group, spec.op)(paging.limit ? { ...params, limit: paging.limit } : params, { context: CONTEXT });
                const pages = [first];
                let page = first;
                while (pages.length < (paging.maxPages || 1) && page.hasMore) {
                    page = await page.nextPage();
                    if (!page) {
                        break;
                    }
                    pages.push(page);
                }
                const all = pages.flatMap(p => p.items);
                const ids = all.map(item => (isObject(item) ? item[paging.idField] : undefined));
                result.outcome = 'ok';
                result.envelope = envelopeOf(first.meta);
                result.typed = `${first.constructor.name}[${all.length ? typeof all[0] : 'empty'}]`;
                result.paging = {
                    limit: paging.limit || null,
                    pages: pages.length,
                    items: all.length,
                    hasMoreAfter: Boolean(page && page.hasMore),
                    duplicates: ids.length - new Set(ids).size,
                    missingIds: ids.filter(id => typeof id !== 'string' || id === '').length,
                };
                const checks = pages.flatMap(p => p.meta.addressChecks || []);
                if (pages.some(p => p.meta.addressChecks)) {
                    result.addressChecks = countStatuses(checks);
                }
                if (spec.vaultKeys || pages.some(p => p.meta.vaultKeys)) {
                    // The per-vault pin results of every page fetched: { vaultId, status, outcome }.
                    result.vaultKeys = pages.every(p => Array.isArray(p.meta.vaultKeys))
                        ? pages.flatMap(p => p.meta.vaultKeys.map(v => ({ vaultId: short(v.vaultId), status: v.status, outcome: v.outcome })))
                        : null;
                }
                if (paging.everyItem) {
                    const iterated = [];
                    const firstSmall = await method(client, spec.group, spec.op)({ ...params, limit: paging.limit }, { context: CONTEXT });
                    const pager = firstSmall.autoPaging({ maxItems: MAX_PAGE });
                    for await (const item of pager) {
                        iterated.push(item[paging.idField]);
                    }
                    const single = await method(client, spec.group, spec.op)({ ...params, limit: MAX_PAGE }, { context: CONTEXT });
                    const singleIds = single.items.map(item => item[paging.idField]);
                    result.everyItem = {
                        iterator: iterated.length,
                        singlePage: singleIds.length,
                        singleHasMore: single.hasMore,
                        stop: pager.stop,
                        equal: JSON.stringify(iterated) === JSON.stringify(singleIds),
                    };
                }
                items[spec.id] = all[0];
            }
        } catch (error) {
            result.outcome = 'error';
            result.error = errorOf(error);
        }
        result.requests = log.length - before;
        result.statuses = log.slice(before).map(r => r.status || r.error);
        const limits = log.slice(before).filter(r => r.limit).map(r => r.limit);
        if (limits.length) {
            result.limits = limits;
        }
        return result;
    }

    async function runNegative(spec) {
        const result = { id: spec.id, group: spec.group, op: spec.op, class: spec.class, check: spec.check };
        if (spec.check === 'burst') {
            return runBurst(spec, result);
        }
        let target = client;
        if (spec.check === 'wrongPassphrase') {
            target = make({ passphrase: wrongPassphrase(s.passphrase) });
        } else if (spec.check === 'rootsOnUnsignedOrigin') {
            target = make({ roots: [testRootPem()] });
        }
        const before = log.length;
        try {
            const answer = await method(target, spec.group, spec.op)(spec.params);
            result.outcome = 'ok';
            result.typed = answer && answer.constructor ? answer.constructor.name : typeof answer;
        } catch (error) {
            result.outcome = 'error';
            result.error = errorOf(error);
        }
        result.requests = log.length - before;
        result.statuses = log.slice(before).map(r => r.status || r.error);
        return result;
    }

    async function runBurst(spec, result) {
        const size = s.burst;
        if (!(size > 0)) {
            return { ...result, skipped: 'VAULTODY_CONFORMANCE_BURST is 0' };
        }
        const read = resolve(spec.read.params);
        const write = resolve(spec.write.params);
        const count = resolve(spec.count.params);
        if (read.missing || write.missing || count.missing) {
            return { ...result, skipped: `no ${read.missing || write.missing || count.missing}` };
        }
        await sleep(1500); // start on a fresh second of the gateway's counters
        const fast = make({ maxRequestsPerSecond: 1000 });
        const before = log.length;
        const started = Date.now();
        let dispatched = 0;
        const reads = [];
        const worker = async () => {
            while (dispatched < size) {
                dispatched += 1;
                try {
                    await method(fast, spec.read.group, spec.read.op)(read.params);
                    reads.push('ok');
                } catch (error) {
                    reads.push(`${error.constructor.name}:${error.code}`);
                }
            }
        };
        const writePromise = (async () => {
            while (dispatched < size) {
                await sleep(2);
            }
            try {
                const answer = await method(fast, spec.write.group, spec.write.op)(write.params);
                return { outcome: 'ok', addressChecks: countStatuses(answer.meta.addressChecks) };
            } catch (error) {
                return { outcome: 'error', error: errorOf(error) };
            }
        })();
        await Promise.all([worker(), worker(), worker(), worker()]);
        const writeResult = await writePromise;
        const window = log.slice(before);
        const writeAttempts = window.filter(r => r.method === 'POST');
        const readAttempts = window.filter(r => r.method === 'GET');
        result.burst = {
            size,
            workers: 4,
            ms: Date.now() - started,
            readsOk: reads.filter(r => r === 'ok').length,
            readErrors: reads.filter(r => r !== 'ok'),
            readAttempts: readAttempts.length,
            read429: readAttempts.filter(r => r.status === 429).length,
            limits: [...new Set(window.filter(r => r.limit).map(r => JSON.stringify(r.limit)))].map(x => JSON.parse(x)),
            write: {
                ...writeResult,
                attempts: writeAttempts.length,
                statuses: writeAttempts.map(r => r.status || r.error),
                distinctNonces: new Set(writeAttempts.map(r => r.nonce)).size,
            },
        };
        await sleep(1500);
        const wanted = write.params.label;
        let labelled = 0;
        const firstCount = await method(client, spec.count.group, spec.count.op)({ ...count.params, limit: MAX_PAGE });
        for await (const address of firstCount.autoPaging({ maxItems: 1000 })) {
            if (address.label === wanted) {
                labelled += 1;
            }
        }
        result.burst.write.addressesWithLabel = labelled;
        result.outcome = 'ok';
        result.requests = log.length - before;
        return result;
    }

    const results = [];
    // VAULTODY_CONFORMANCE_CASES: run only these case ids (comma-separated), for example to repeat a few.
    const only = process.env.VAULTODY_CONFORMANCE_CASES ? new Set(process.env.VAULTODY_CONFORMANCE_CASES.split(',')) : null;
    for (const spec of CASES.cases.filter(c => !only || only.has(c.id))) {
        const result = spec.class === 'negative' ? await runNegative(spec) : await runCase(spec);
        results.push(result);
        process.stderr.write(`${CLIENT} ${spec.id}: ${result.skipped ? `skip (${result.skipped})` : result.outcome}${result.error ? ` ${result.error.class} ${result.error.code || ''} ${result.error.status || ''}` : ''}\n`);
    }

    // The pin file as this SDK's own store reads it after the run: the seed's origins and the run's.
    let read;
    try {
        const store = new FileVaultKeyStore({ file: pinFile });
        const origins = {};
        for (const origin of [...SEED_ORIGINS, s.origin]) {
            origins[origin] = { responseSignature: await store.getResponseSignatureLatch(origin), pins: (await store.list(origin)).sort((a, b) => (a.vaultId < b.vaultId ? -1 : 1)) };
        }
        read = { ok: true, origins: summarizeRead(origins) };
    } catch (error) {
        read = { ok: false, error: error instanceof VaultKeyStoreError ? error.code : error.name };
    }

    writeJson(path.join(out, `results-${CLIENT}.json`), {
        client: CLIENT,
        runtime: `node ${process.versions.node}`,
        sdkVersion: sdk.SDK_VERSION,
        apiVersion: sdk.API_VERSION,
        origin: s.origin,
        runId,
        finishedAt: new Date().toISOString(),
        requests: log.length,
        cases: results,
        pins: { ...pinFileFacts(pinFile), read },
        securityEvents: events,
        warnings: [...warnings],
    });
}

main().catch(error => {
    process.stderr.write(`run-node failed: ${error.name}${error.code ? ` ${error.code}` : ''}: ${String(error.message).slice(0, 300)}\n`);
    process.exit(1);
});
