'use strict';

/**
 * Judges every client's results by the same rules and writes the table: node report.js <out-dir> > report.md
 * (also <out-dir>/summary.json). PASS, FAIL, SKIP (a fixture value the data doesn't have, or a check that
 * couldn't be provoked) per case and client; then what each case saw, the pins, and what is not run live.
 */

const fs = require('node:fs');
const path = require('node:path');

const { CASES, writeJson } = require('./lib');

const CLIENTS = ['node', 'python-sync', 'python-async', 'php'];
const ADDRESS_STATUSES = new Set(['verified', 'unverified', 'not_verifiable']);
const VAULT_OUTCOMES = new Set(['pinned', 'unchanged', 'upgraded', 'not_verifiable']);
const UNSIGNED_FIELDS = JSON.stringify(['operationId', 'origin', 'type']);
const SIGNATURES = new Set(['verified', 'absent']);

const typed4xx = error => Boolean(error && error.apiError && error.class !== 'ApiError' && error.status >= 400 && error.status < 500);
const errorText = error => `${error.class}${error.code ? ` ${error.code}` : ''}${error.reason ? ` ${error.reason}` : ''}${error.status ? ` ${error.status}` : ''}`;
const counts = map => Object.entries(map || {}).map(([k, v]) => `${v} ${k}`).join(', ');

function judgeBurst(result) {
    const b = result.burst;
    if (!b) {
        return { verdict: 'FAIL', note: 'no burst result' };
    }
    const write = b.write || {};
    const facts = `${b.size} reads, ${b.read429}×429, ${b.readsOk}/${b.size} ok; write ${write.attempts} attempt(s) ${(write.statuses || []).join('/')}, ${write.addressesWithLabel} address(es)`;
    const writeOnce = write.outcome === 'ok' && write.addressesWithLabel === 1 && write.distinctNonces === 1;
    if (b.read429 === 0) {
        return { verdict: 'SKIP', note: `no 429 provoked (${facts})` };
    }
    return { verdict: b.readsOk === b.size && writeOnce ? 'PASS' : 'FAIL', note: facts };
}

function judge(result, spec) {
    if (!result) {
        return { verdict: '–', note: 'not in this run' };
    }
    if (result.skipped) {
        return { verdict: 'SKIP', note: result.skipped };
    }
    const error = result.error;
    if (spec.class === 'negative') {
        if (spec.check === 'burst') {
            return judgeBurst(result);
        }
        const want = spec.expectError;
        const ok = result.outcome === 'error' && error.class === want.class
            && (want.code === undefined || error.code === want.code)
            && (want.reason === undefined || error.reason === want.reason)
            && (want.status === undefined || error.status === want.status)
            && (want.requests === undefined || result.requests === want.requests);
        return { verdict: ok ? 'PASS' : 'FAIL', note: `${result.outcome === 'error' ? errorText(error) : 'no error'}, ${result.requests} sent` };
    }
    if (spec.expectError) {
        return { verdict: result.outcome === 'error' && typed4xx(error) ? 'PASS' : 'FAIL', note: result.outcome === 'error' ? errorText(error) : 'answered 2xx' };
    }
    if (result.outcome === 'error') {
        if (spec.acceptTyped4xx && typed4xx(error)) {
            return { verdict: 'PASS', note: `typed ${errorText(error)}` };
        }
        return { verdict: 'FAIL', note: `${errorText(error)} after ${result.requests} attempt(s)` };
    }

    const problems = [];
    const env = result.envelope || {};
    if (!env.requestId) {
        problems.push('no requestId');
    }
    if (env.apiVersion !== CASES.apiVersion) {
        problems.push(`apiVersion ${env.apiVersion}`);
    }
    if (!SIGNATURES.has(env.signature)) {
        problems.push(`signature ${env.signature}`);
    }
    if (result.field && !result.field.present) {
        problems.push(`no ${result.field.name}`);
    }
    if (result.field && result.field.equalsExpected === false) {
        problems.push(`${result.field.name} differs`);
    }
    const notes = [];
    if (result.paging) {
        if (result.paging.duplicates) {
            problems.push(`${result.paging.duplicates} duplicate(s)`);
        }
        if (result.paging.missingIds) {
            problems.push(`${result.paging.missingIds} item(s) without ${spec.paging.idField}`);
        }
        notes.push(`${result.paging.pages} page(s), ${result.paging.items} item(s)`);
    }
    if (result.everyItem) {
        if (!result.everyItem.equal) {
            problems.push(`iterator ${result.everyItem.iterator} ≠ single page ${result.everyItem.singlePage}`);
        } else {
            notes.push(`all ${result.everyItem.iterator} by iterator`);
        }
    }
    if (result.addressChecks) {
        const unknown = Object.keys(result.addressChecks).filter(k => !ADDRESS_STATUSES.has(k));
        if (unknown.length) {
            problems.push(`address status ${unknown.join(', ')}`);
        }
        notes.push(counts(result.addressChecks) || 'no addresses');
    }
    if (spec.vaultKeys) {
        // The per-vault pin results, the same in every language: { vaultId, status, outcome } per vault.
        const vaults = result.vaultKeys;
        if (!Array.isArray(vaults)) {
            problems.push('no per-vault pin results');
        } else {
            const bad = vaults.filter(v => !ADDRESS_STATUSES.has(v.status) || !VAULT_OUTCOMES.has(v.outcome)
                || (v.outcome === 'not_verifiable') !== (v.status === 'not_verifiable'));
            if (bad.length) {
                problems.push(`per-vault result ${JSON.stringify(bad[0])}`);
            }
            if (result.paging && vaults.length !== result.paging.items) {
                problems.push(`${vaults.length} per-vault results for ${result.paging.items} vaults`);
            }
            notes.push(`vaults ${counts(Object.fromEntries(Object.entries(vaults.reduce((acc, v) => {
                const key = `${v.status}/${v.outcome}`;
                acc[key] = (acc[key] || 0) + 1;
                return acc;
            }, {}))))}`);
        }
    }
    if (result.field && result.field.equalsExpected === true) {
        notes.push(`${result.field.name} as expected`);
    }
    const retried = (result.statuses || []).filter(s => s !== 200).length;
    if (retried) {
        const quota = (result.limits || []).map(l => `${l.requests}/${l.seconds}s`);
        notes.push(`retried after ${(result.statuses || []).filter(s => s !== 200).join('/')}${quota.length ? ` (quota ${[...new Set(quota)].join(', ')})` : ''}`);
    }

    return problems.length ? { verdict: 'FAIL', note: problems.join('; ') } : { verdict: 'PASS', note: notes.join('; ') };
}

function main() {
    const out = process.argv[2];
    if (!out) {
        throw new Error('usage: node report.js <out-dir>');
    }
    const runs = {};
    for (const client of CLIENTS) {
        const file = path.join(out, `results-${client}.json`);
        if (fs.existsSync(file)) {
            runs[client] = JSON.parse(fs.readFileSync(file, 'utf8'));
        }
    }
    const present = CLIENTS.filter(c => runs[c]);
    const fixtureFile = path.join(out, 'fixture.json');
    const fixture = fs.existsSync(fixtureFile) ? JSON.parse(fs.readFileSync(fixtureFile, 'utf8')) : {};
    const lines = [];
    const summary = { origin: fixture.origin, clients: {}, cases: [] };
    const tally = Object.fromEntries(present.map(c => [c, { PASS: 0, FAIL: 0, SKIP: 0 }]));

    lines.push('# SDK live conformance', '');
    lines.push(`- API: \`${fixture.origin || '?'}\`, \`x-api-version: ${CASES.apiVersion}\``);
    for (const client of present) {
        const run = runs[client];
        lines.push(`- ${client}: ${run.runtime}, SDK ${run.sdkVersion || '?'}, run \`${run.runId}\`, ${run.requests} requests, finished ${run.finishedAt}`);
        summary.clients[client] = { runtime: run.runtime, sdkVersion: run.sdkVersion, requests: run.requests, runId: run.runId };
    }
    const signatures = new Set(present.flatMap(c => runs[c].cases.filter(r => r.envelope).map(r => r.envelope.signature)));
    lines.push(`- Response signatures seen: ${[...signatures].join(', ') || 'none'} (\`absent\`: unsigned, accepted in \`when-present\` mode)`, '');

    lines.push(`| Case | Class | ${present.join(' | ')} |`, `|---|---|${present.map(() => '---|').join('')}`);
    for (const spec of CASES.cases) {
        const row = [`\`${spec.id}\``, spec.class];
        const entry = { id: spec.id, op: spec.op, class: spec.class, clients: {} };
        for (const client of present) {
            const result = runs[client].cases.find(r => r.id === spec.id);
            const verdict = judge(result, spec);
            if (tally[client][verdict.verdict] !== undefined) {
                tally[client][verdict.verdict] += 1;
            }
            entry.clients[client] = verdict;
            row.push(`**${verdict.verdict}**${verdict.note ? ` ${verdict.note}` : ''}`);
        }
        summary.cases.push(entry);
        lines.push(`| ${row.join(' | ')} |`);
    }
    lines.push(`| **Total** | | ${present.map(c => `${tally[c].PASS} pass, ${tally[c].FAIL} fail, ${tally[c].SKIP} skip`).join(' | ')} |`, '');
    summary.tally = tally;

    lines.push('## Typed results and requests', '');
    lines.push(`| Case | ${present.join(' | ')} |`, `|---|${present.map(() => '---|').join('')}`);
    for (const spec of CASES.cases.filter(s => s.class !== 'negative')) {
        const cells = present.map(client => {
            const r = runs[client].cases.find(x => x.id === spec.id);
            return r && !r.skipped ? `${r.typed || (r.error ? r.error.class : '')} (${r.requests})` : '–';
        });
        lines.push(`| \`${spec.id}\` | ${cells.join(' | ')} |`);
    }
    lines.push('');

    // The pin file, the per-vault pin results and the unsigned notice, side by side: one behaviour in every
    // language (docs/vault-keys-file.md). A row agrees when every client's value is the same.
    lines.push('## Pin file, per-vault results and the unsigned notice', '');
    lines.push('Every client starts from the same seeded pin file (the vectors\' canonical `two_origins`: pins and a latch under '
        + 'two other origins, nothing under the origin of the run) and reads it with its own store.', '');
    lines.push(`| | ${present.join(' | ')} | Agree |`, `|---|${present.map(() => '---|').join('')}---|`);
    const agreementRows = [];
    const row = (label, cellOf, keyOf) => {
        const cells = present.map(client => cellOf(runs[client]));
        const keys = present.map(client => JSON.stringify(keyOf(runs[client])));
        const agree = keys.length > 0 && new Set(keys).size === 1;
        agreementRows.push({ label, agree });
        lines.push(`| ${label} | ${cells.join(' | ')} | **${agree ? 'yes' : 'NO'}** |`);
    };
    const pinsOf = run => run.pins || {};
    row('Pin file after the run', run => {
        const p = pinsOf(run);
        return p.exists ? `mode ${p.mode}, ${p.unchangedSinceSeed ? 'the seed, unchanged' : 'rewritten'}, sha256 \`${String(p.sha256).slice(0, 12)}\`` : 'none';
    }, run => {
        const p = pinsOf(run);
        return { exists: p.exists, mode: p.mode, sha256: p.sha256 };
    });
    for (const [origin] of Object.entries((present[0] && pinsOf(runs[present[0]]).read && pinsOf(runs[present[0]]).read.origins) || {})) {
        row(`Read back: \`${origin}\``, run => {
            const read = pinsOf(run).read;
            if (!read || !read.ok) {
                return `refused (${read ? read.error : 'not read'})`;
            }
            const entry = read.origins[origin];
            if (!entry) {
                return 'not read';
            }
            const vaults = entry.vaults.map(v => `${v.vaultId} ${v.type} ${v.status} [${v.algorithms.join('+')}]`);
            return `latch ${entry.latch || 'none'}; ${vaults.length ? vaults.join(', ') : 'no pin'}`;
        }, run => {
            const read = pinsOf(run).read;
            return read && read.ok ? read.origins[origin] : read;
        });
    }
    for (const spec of CASES.cases.filter(s => s.vaultKeys)) {
        const of = run => (run.cases.find(r => r.id === spec.id) || {}).vaultKeys;
        row(`\`${spec.id}\` per vault`, run => {
            const v = of(run);
            return Array.isArray(v) ? (v.length ? v.map(x => `${x.vaultId} ${x.status}/${x.outcome}`).join(', ') : 'no vault') : 'none';
        }, of);
    }
    const unsigned = run => (run.securityEvents || []).filter(e => e.type === 'unsigned_response_accepted');
    row('`unsigned_response_accepted`', run => {
        const events = unsigned(run);
        const fields = [...new Set(events.map(e => JSON.stringify(e.fields)))];
        return `${events.length}× (${events.map(e => e.operationId).join(', ')}); fields ${fields.length === 1 && fields[0] === UNSIGNED_FIELDS ? 'type, origin, operationId' : fields.join(' / ')}`
            + `${events.every(e => e.originIsRun) ? '' : '; ORIGIN DIFFERS'}`;
    }, run => unsigned(run).map(e => ({ operationId: e.operationId, fields: e.fields, originIsRun: e.originIsRun })));
    row('Its warning', run => {
        const n = (run.warnings || []).filter(w => /not signed/.test(w)).length;
        return n ? `${n} distinct` : 'none';
    }, run => (run.warnings || []).filter(w => /not signed/.test(w)).length > 0);
    row('Other security events', run => {
        const other = (run.securityEvents || []).filter(e => e.type !== 'unsigned_response_accepted');
        return other.length ? other.map(e => e.type).join(', ') : 'none';
    }, run => (run.securityEvents || []).filter(e => e.type !== 'unsigned_response_accepted').map(e => e.type));
    lines.push('');
    summary.agreement = agreementRows;

    lines.push('## Not run live', '');
    lines.push('| Operation | Why | Covered offline by |', '|---|---|---|');
    for (const item of CASES.notRun) {
        lines.push(`| \`${item.group}.${item.op}\` | ${item.why} | ${item.mock} |`);
    }
    lines.push('');

    process.stdout.write(`${lines.join('\n')}\n`);
    writeJson(path.join(out, 'summary.json'), summary);
}

main();
