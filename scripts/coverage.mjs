#!/usr/bin/env node
/**
 * Checks that every SDK has exactly one method for every documented operation of the pinned API version,
 * and nothing else.
 *
 *   node scripts/coverage.mjs --surface node.json --surface python.json --surface php.json
 *
 * The expected set is every operation in contract/openapi.json (the published OpenAPI document, copied as
 * contract/source.json records) plus contract/pending/ (documented, not published on production yet). The actual set comes from
 * each SDK's own surface dump (node/packages/sdk/scripts/surface.js, python -m vaultody_sdk._surface,
 * php/bin/surface.php): the methods its clients really expose, found by reflection, and the operation
 * table the transport builds requests from.
 *
 * It fails on a method that is missing, extra, in the wrong namespace or under the wrong name; on an
 * operation table entry with the wrong HTTP method, path or parameters (a pending operation's parameters
 * are declared in PENDING_PARAMS); on a pinned x-api-version or an SDK version that differs from the
 * contract and VERSION; and on a contract that no longer matches the copies recorded in
 * contract/source.json or contract/overlay.json. Every client has every method: nothing may be missing.
 *
 * No dependencies; Node 22 or later.
 */

import { createHash } from 'node:crypto';
import { appendFileSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parseVersion, toPep440 } from './version.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Each SDK client checked, the language that dumps it, and how that language names things. */
export const TARGETS = Object.freeze([
    { target: 'node', language: 'node', casing: 'camel' },
    { target: 'python-sync', language: 'python', casing: 'snake' },
    { target: 'python-async', language: 'python', casing: 'snake' },
    { target: 'php', language: 'php', casing: 'camel' },
]);

/** The docs group of an operation (its first tag) and the client namespace its method lives in. */
export const GROUP_NAMESPACES = Object.freeze({
    vaults: 'vaults',
    'vault-accounts': 'vaultAccounts',
    'assets-addresses': 'assetsAddresses',
    transactions: 'transactions',
    'api-keys': 'apiKeys',
});

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
// Set on the client or per call, never a method parameter: x-api-version is pinned per release, and
// `context` is a call option (decision: a flat params argument plus options).
const NOT_PARAMS = new Set(['x-api-version', 'context']);

export const snakeCase = name => name.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
export const nameIn = (casing, name) => (casing === 'snake' ? snakeCase(name) : name);

/**
 * The parameters of each pending operation. A pending docs file names none (they come from the route
 * contract once the operation is published), so they are declared here from the file's text; a pending
 * operation without an entry fails, and every SDK's operation table must match the entry.
 */
export const PENDING_PARAMS = Object.freeze({
    // "The list covers the API key in `x-api-key`, so the request takes no parameters."
    listApiKeySigningKeys: Object.freeze([]),
});

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const readJson = file => JSON.parse(readFileSync(file, 'utf8'));
const byName = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The top-level scalar keys of a pending docs file. Only `operation`, `operationId` and `group` are read,
 * all plain `key: value` lines, so no YAML parser is needed.
 */
function readPendingFile(text, file) {
    const value = key => {
        const match = text.match(new RegExp(`^${key}:\\s*(.+?)\\s*$`, 'm'));
        if (!match) {
            throw new Error(`${file}: no top-level "${key}:"`);
        }

        return match[1].replace(/^"(.*)"$/, '$1');
    };
    const [method, operationPath] = value('operation').split(/\s+/);
    const operationId = value('operationId');

    const params = Object.hasOwn(PENDING_PARAMS, operationId) ? [...PENDING_PARAMS[operationId]] : null;

    return { operationId, group: value('group'), method, path: operationPath, params, pending: true };
}

function walkFiles(dir) {
    return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
        const full = path.join(dir, entry.name);

        return entry.isDirectory() ? walkFiles(full) : [full];
    });
}

/**
 * A flat params argument works only while no path or query parameter shares a name with a body field.
 *
 * @param {{ operationId: string, params: Array<{ name: string, in: string }> }} op
 * @returns {string[]} one problem per name used in two places
 */
export function collisionsOf(op) {
    const problems = [];
    const located = new Map();
    for (const param of op.params) {
        if (located.has(param.name) && located.get(param.name) !== param.in) {
            problems.push(`${op.operationId}: "${param.name}" is both a ${located.get(param.name)} and a ${param.in} parameter, so a flat params argument can't hold it`);
        }
        located.set(param.name, param.in);
    }

    return problems;
}

/**
 * The expected operations: every operation of the OpenAPI document plus the pending ones.
 *
 * @returns {{ apiVersion: string, operations: Array<Object>, problems: string[] }}
 */
export function loadContract(contractDir = path.join(ROOT, 'contract')) {
    const problems = [];
    const source = readJson(path.join(contractDir, 'source.json'));
    for (const [file, record] of Object.entries(source.files)) {
        const actual = sha256(readFileSync(path.join(contractDir, file)));
        if (actual !== record.sha256) {
            problems.push(`contract/${file} differs from the copy recorded in contract/source.json (sha256 ${actual}, recorded ${record.sha256})`);
        }
    }

    const openapi = readJson(path.join(contractDir, 'openapi.json'));
    const published = readJson(path.join(contractDir, 'published.json'));
    const sharedParams = (openapi.components && openapi.components.parameters) || {};
    const resolve = param => (param.$ref ? sharedParams[param.$ref.split('/').pop()] : param);

    const operations = [];
    for (const [operationPath, item] of Object.entries(openapi.paths)) {
        for (const method of HTTP_METHODS) {
            const op = item[method];
            if (!op) {
                continue;
            }
            const params = (op.parameters || []).map(resolve)
                .filter(param => param.in !== 'header' && !NOT_PARAMS.has(param.name))
                .map(param => ({ name: param.name, in: param.in, required: param.required === true }));
            const body = op.requestBody && op.requestBody.content && op.requestBody.content['application/json'];
            const itemSchema = body && body.schema && body.schema.properties && body.schema.properties.data
                && body.schema.properties.data.properties && body.schema.properties.data.properties.item;
            if (itemSchema) {
                const required = new Set(itemSchema.required || []);
                for (const name of Object.keys(itemSchema.properties || {})) {
                    params.push({ name, in: 'body', required: required.has(name) });
                }
            }
            operations.push({
                operationId: op.operationId,
                group: (op.tags || [])[0],
                method: method.toUpperCase(),
                path: operationPath,
                params: params.sort((a, b) => byName(a.name, b.name)),
                pending: false,
            });
        }
    }

    const pendingDir = path.join(contractDir, 'pending');
    for (const file of walkFiles(pendingDir).filter(name => name.endsWith('.yaml')).sort()) {
        operations.push(readPendingFile(readFileSync(file, 'utf8'), path.relative(ROOT, file)));
    }

    const seen = new Set();
    for (const op of operations) {
        if (!op.operationId) {
            problems.push(`${op.method} ${op.path} has no operationId`);
        } else if (seen.has(op.operationId)) {
            problems.push(`operationId ${op.operationId} appears twice`);
        }
        seen.add(op.operationId);
        if (!GROUP_NAMESPACES[op.group]) {
            problems.push(`${op.operationId} is in docs group "${op.group}", which has no SDK namespace`);
        }
        if (!op.params) {
            problems.push(`${op.operationId} is pending: declare its parameters in PENDING_PARAMS (scripts/coverage.mjs)`);
            op.params = [];
        }
        problems.push(...collisionsOf(op));
    }

    if (published.apiVersion !== openapi.info.version) {
        problems.push(`contract/published.json apiVersion ${published.apiVersion} differs from openapi.json info.version ${openapi.info.version}`);
    }

    const overlay = readJson(path.join(contractDir, 'overlay.json'));
    for (const op of operations) {
        if (!overlay.operations[op.operationId]) {
            problems.push(`contract/overlay.json has no entry for ${op.operationId}`);
        }
    }
    for (const operationId of Object.keys(overlay.operations)) {
        if (!seen.has(operationId)) {
            problems.push(`contract/overlay.json names ${operationId}, which the contract does not document`);
        }
    }
    for (const operationId of Object.keys(PENDING_PARAMS)) {
        if (!operations.some(op => op.pending && op.operationId === operationId)) {
            problems.push(`PENDING_PARAMS names ${operationId}, which is not in contract/pending/`);
        }
    }

    return {
        apiVersion: openapi.info.version,
        tag: published.tag,
        operations: operations.sort((a, b) => byName(a.operationId, b.operationId)),
        problems,
    };
}

const sameParams = (a, b) => JSON.stringify([...a].sort((x, y) => byName(x.name, y.name)))
    === JSON.stringify([...b].sort((x, y) => byName(x.name, y.name)));

/**
 * Compares the SDK surfaces with the contract.
 *
 * @param {{ contract: Object, surfaces: Object[], sdkVersion: string }} input
 * @returns {{ ok: boolean, problems: string[], rows: Object[], summary: Object }}
 */
export function checkCoverage({ contract, surfaces, sdkVersion }) {
    const problems = [...contract.problems];
    const expected = new Map(contract.operations.map(op => [op.operationId, op]));
    const status = new Map(contract.operations.map(op => [op.operationId, {}]));
    const summary = {};

    const surfaceOf = new Map();
    for (const surface of surfaces) {
        if (surfaceOf.has(surface.language)) {
            problems.push(`two surface dumps for ${surface.language}`);
        }
        surfaceOf.set(surface.language, surface);
    }

    for (const language of new Set(TARGETS.map(t => t.language))) {
        const surface = surfaceOf.get(language);
        if (!surface) {
            problems.push(`no surface dump for ${language}`);
            continue;
        }
        if (surface.apiVersion !== contract.apiVersion) {
            problems.push(`${language} pins x-api-version ${surface.apiVersion}; the contract is ${contract.apiVersion}`);
        }
        // Python spells a release candidate the PEP 440 way (scripts/version.mjs): 0.9.0-rc.1 is 0.9.0rc1.
        const expectedVersion = language === 'python' && parseVersion(sdkVersion) ? toPep440(sdkVersion) : sdkVersion;
        if (surface.sdkVersion !== expectedVersion) {
            problems.push(`${language} is version ${surface.sdkVersion}; VERSION says ${sdkVersion}${expectedVersion === sdkVersion ? '' : ` (${expectedVersion} in Python)`}`);
        }
        for (const entry of surface.operations || []) {
            const op = expected.get(entry.operationId);
            if (!op) {
                problems.push(`${language} operation table has ${entry.operationId}, which the contract does not document`);
                continue;
            }
            if (entry.method !== op.method || entry.path !== op.path) {
                problems.push(`${language} operation table: ${entry.operationId} is ${entry.method} ${entry.path}; the contract says ${op.method} ${op.path}`);
            }
            if (!sameParams(entry.params || [], op.params)) {
                problems.push(`${language} operation table: ${entry.operationId} params ${JSON.stringify(entry.params)} differ from the contract's ${JSON.stringify(op.params)}`);
            }
        }
    }

    for (const { target, language, casing } of TARGETS) {
        const surface = surfaceOf.get(language);
        const methods = (surface && surface.clients && surface.clients[target]) || [];
        const tableIds = new Set(((surface && surface.operations) || []).map(entry => entry.operationId));
        const bound = new Set();
        for (const method of methods) {
            const op = expected.get(method.operationId);
            const label = `${target} ${method.namespace}.${method.method}`;
            if (!op) {
                problems.push(`${label} is bound to ${method.operationId}, which the contract does not document`);
                continue;
            }
            if (bound.has(op.operationId)) {
                problems.push(`${target} has two methods for ${op.operationId}`);
            }
            bound.add(op.operationId);
            const namespace = nameIn(casing, GROUP_NAMESPACES[op.group]);
            const name = nameIn(casing, op.operationId);
            if (method.namespace !== namespace || method.method !== name) {
                problems.push(`${label} implements ${op.operationId}, which belongs at ${namespace}.${name}`);
            }
            if (!tableIds.has(op.operationId)) {
                problems.push(`${label} implements ${op.operationId}, which is not in the ${language} operation table`);
            }
        }

        let implemented = 0;
        for (const op of contract.operations) {
            if (bound.has(op.operationId)) {
                implemented += 1;
                status.get(op.operationId)[target] = 'ok';
            } else {
                status.get(op.operationId)[target] = 'missing';
                problems.push(`${target} has no method for ${op.operationId}`);
            }
        }
        summary[target] = { implemented, total: contract.operations.length };
    }

    const rows = contract.operations.map(op => ({ operationId: op.operationId, group: op.group, pending: op.pending, ...status.get(op.operationId) }));

    return { ok: problems.length === 0, problems, rows, summary };
}

const MARK = { ok: 'yes', missing: 'MISSING' };

export function renderMarkdown(contract, result) {
    const lines = [
        `### SDK coverage: API ${contract.apiVersion} (${contract.tag}), ${contract.operations.length} operations`,
        '',
        `| operation | group | ${TARGETS.map(t => t.target).join(' | ')} |`,
        `|---|---|${TARGETS.map(() => '---').join('|')}|`,
        ...result.rows.map(row => `| ${row.operationId}${row.pending ? ' (pending)' : ''} | ${row.group} | ${TARGETS.map(t => MARK[row[t.target]]).join(' | ')} |`),
        '',
        ...TARGETS.map(({ target }) => {
            const s = result.summary[target];

            return `- **${target}:** ${s.implemented} of ${s.total} implemented`;
        }),
    ];
    if (result.problems.length > 0) {
        lines.push('', '**Problems:**', ...result.problems.map(problem => `- ${problem}`));
    }

    return `${lines.join('\n')}\n`;
}

function main(argv) {
    const surfaces = [];
    for (let i = 0; i < argv.length; i += 1) {
        if (argv[i] === '--surface') {
            surfaces.push(readJson(argv[i + 1]));
            i += 1;
        } else {
            throw new Error(`unknown argument ${argv[i]}`);
        }
    }

    const contract = loadContract();
    const sdkVersion = readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim();
    const result = checkCoverage({ contract, surfaces, sdkVersion });

    const markdown = renderMarkdown(contract, result);
    process.stdout.write(markdown);
    if (process.env.GITHUB_STEP_SUMMARY) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
    }
    process.stdout.write(result.ok ? '\ncoverage: ok\n' : `\ncoverage: FAILED, ${result.problems.length} problem(s)\n`);

    return result.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    process.exitCode = main(process.argv.slice(2));
}
