'use strict';

// The hand-written parts of the surface against the published OpenAPI document (contract/openapi.json) and the
// pending operation (contract/pending/):
//  - every param schema in the operation table (what the API methods check values against): type, enum,
//    maximum, nested fields and their required flags;
//  - every model (the *Params and *Result typedefs in src/api/): the same field names at every depth, the same
//    types, required exactly where the document says (response fields: never, the document marks none).
// scripts/coverage.mjs checks the methods, paths and parameter places; this checks the rest.

const assert = require('node:assert/strict');
const path = require('node:path');
const { readFileSync, readdirSync } = require('node:fs');
const { describe, it } = require('node:test');

const { OPERATIONS } = require('../src/operations');

const ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const OPENAPI = JSON.parse(readFileSync(path.join(ROOT, 'contract', 'openapi.json'), 'utf8'));
const PENDING_FILE = path.join(ROOT, 'contract', 'pending', 'api-keys', 'list-api-key-signing-keys.yaml');
const PENDING = readFileSync(PENDING_FILE, 'utf8');
const API_DIR = path.resolve(__dirname, '..', 'src', 'api');

const capitalised = name => name[0].toUpperCase() + name.slice(1);

/** operationId → { op, params: { name: schema }, required: Set, result: schema of one item } from the document. */
function documented() {
    const out = new Map();
    for (const item of Object.values(OPENAPI.paths)) {
        for (const method of ['get', 'post', 'put']) {
            const op = item[method];
            if (!op) {
                continue;
            }
            const params = {};
            const required = new Set();
            for (const param of op.parameters || []) {
                if (param.$ref) {
                    continue;
                }
                params[param.name] = param.schema;
                if (param.required) {
                    required.add(param.name);
                }
            }
            const body = op.requestBody && op.requestBody.content['application/json'].schema.properties.data.properties.item;
            if (body) {
                Object.assign(params, body.properties);
                (body.required || []).forEach(name => required.add(name));
            }
            const success = op.responses['200'] || op.responses['201'];
            const data = success.content['application/json'].schema.properties.data;
            const result = data.properties.items ? data.properties.items.items : data.properties.item;
            out.set(op.operationId, { op, params, required, result, list: Boolean(data.properties.items) });
        }
    }

    return out;
}

const DOCUMENTED = documented();

/** The response fields of the pending operation: the `fields:` map of its docs file, typed by their examples. */
function pendingResult() {
    const block = PENDING.slice(PENDING.indexOf('\nfields:\n') + '\nfields:\n'.length).split('\n');
    const properties = {};
    for (const line of block) {
        const match = /^ {2}"([A-Za-z0-9]+)": \{.*example: (.+) \}$/.exec(line);
        if (!match) {
            break;
        }
        properties[match[1]] = { type: /^[0-9]+$/.test(match[2]) ? 'integer' : 'string' };
    }

    return { type: 'object', properties };
}

// ---- the operation table ----

const sorted = values => [...values].sort();

/** The document's schema reduced to what the table holds. */
function reduce(schema) {
    const out = { type: schema.type };
    if (schema.enum) {
        out.enum = sorted(schema.enum);
    }
    if (schema.maximum !== undefined) {
        out.maximum = schema.maximum;
    }
    if (schema.type === 'object') {
        out.properties = Object.fromEntries(Object.entries(schema.properties || {}).map(([name, value]) => [name, reduce(value)]));
        out.required = sorted(schema.required || []);
    }
    if (schema.type === 'array') {
        out.items = reduce(schema.items);
    }

    return out;
}

/** The table's schema, with the one addition it makes (a page size of at least 1) checked and set aside. */
function reduceTable(schema, name) {
    const { minimum, ...rest } = schema;
    if (minimum !== undefined) {
        assert.equal(name, 'limit', `only limit has a minimum the document does not state, not ${name}`);
        assert.equal(minimum, 1);
    }

    return reduce(rest);
}

describe('the operation table against the document', () => {
    for (const entry of OPERATIONS) {
        it(entry.operationId, () => {
            if (entry.operationId === 'listApiKeySigningKeys') {
                // The pending docs file names no parameter and says the request takes none.
                assert.doesNotMatch(PENDING, /^(parameters|params|query):/m);
                assert.match(PENDING, /the request takes no parameters/);
                assert.deepEqual(entry.params, []);

                return;
            }
            const doc = DOCUMENTED.get(entry.operationId);
            assert.ok(doc, 'documented');
            assert.deepEqual(entry.params.map(param => param.name).sort(), Object.keys(doc.params).sort());
            for (const param of entry.params) {
                assert.ok(param.schema, `${param.name} has a schema`);
                assert.equal(param.required, doc.required.has(param.name), `${param.name} required`);
                assert.deepEqual(reduceTable(param.schema, param.name), reduce(doc.params[param.name]), param.name);
            }
        });
    }
});

// ---- the models ----

/** Reads the text inside balanced braces starting at text[start] === '{'. */
function braced(text, start) {
    let depth = 0;
    for (let i = start; i < text.length; i += 1) {
        if (text[i] === '{') {
            depth += 1;
        } else if (text[i] === '}') {
            depth -= 1;
            if (depth === 0) {
                return { inner: text.slice(start + 1, i), end: i + 1 };
            }
        }
    }
    throw new Error(`unbalanced braces at ${start}`);
}

/** Every @typedef in src/api/: name → { type, properties: [{ name, type, optional }] }. */
function readTypedefs() {
    const typedefs = new Map();
    for (const file of readdirSync(API_DIR).filter(name => name.endsWith('.js'))) {
        const text = readFileSync(path.join(API_DIR, file), 'utf8');
        for (const comment of text.match(/\/\*\*[\s\S]*?\*\//g) || []) {
            const at = comment.indexOf('@typedef {');
            if (at === -1) {
                continue;
            }
            const type = braced(comment, at + '@typedef '.length);
            const name = /^\s*([A-Za-z0-9_]+)/.exec(comment.slice(type.end))[1];
            const properties = [];
            let from = type.end;
            for (;;) {
                const next = comment.indexOf('@property {', from);
                if (next === -1) {
                    break;
                }
                const propType = braced(comment, next + '@property '.length);
                const match = /^\s*(\[?)([A-Za-z0-9_]+)\]?/.exec(comment.slice(propType.end));
                properties.push({ name: match[2], type: propType.inner.trim(), optional: match[1] === '[' });
                from = propType.end;
            }
            const alias = /^import\('\.\/common'\)\.([A-Za-z0-9_]+)$/.exec(type.inner.trim());
            if (alias && alias[1] === name) {
                // A group file's local name for a type of common.js.
                continue;
            }
            assert.ok(!typedefs.has(name), `typedef ${name} is defined twice (${file})`);
            typedefs.set(name, { type: type.inner.trim(), properties, file });
        }
    }

    return typedefs;
}

const TYPEDEFS = readTypedefs();

/** Compares a model type with a document schema; returns the problems found, each with its field path. */
function compare(type, schema, where, { request }) {
    const problems = [];
    const literalUnion = text => (/^'[^']*'(\|'[^']*')*$/.test(text) ? text.split('|').map(part => part.slice(1, -1)) : null);
    let resolved = type.replace(/^import\('\.\/common'\)\./, '');
    const typedef = TYPEDEFS.get(resolved);
    if (typedef && typedef.type !== 'Object') {
        resolved = typedef.type;
    }
    const array = /^Array<(.+)>$/.exec(resolved);
    switch (schema.type) {
    case 'string': {
        const values = literalUnion(resolved);
        if (schema.enum) {
            if (!values || JSON.stringify(sorted(values)) !== JSON.stringify(sorted(schema.enum))) {
                problems.push(`${where}: ${type}, the document says one of ${schema.enum.join(', ')}`);
            }
        } else if (resolved !== 'string') {
            problems.push(`${where}: ${type}, the document says string`);
        }
        break;
    }
    case 'integer':
        if (resolved !== 'number') {
            problems.push(`${where}: ${type}, the document says integer`);
        }
        break;
    case 'boolean':
        if (resolved !== 'boolean') {
            problems.push(`${where}: ${type}, the document says boolean`);
        }
        break;
    case 'array':
        if (!array) {
            problems.push(`${where}: ${type}, the document says array`);
        } else {
            problems.push(...compare(array[1], schema.items, `${where}[]`, { request }));
        }
        break;
    case 'object':
        if (!typedef || typedef.type !== 'Object') {
            problems.push(`${where}: ${type} is not an object typedef`);
        } else {
            problems.push(...compareObject(typedef, schema, where, { request }));
        }
        break;
    default:
        problems.push(`${where}: the document's type ${schema.type} has no model rule`);
    }

    return problems;
}

function compareObject(typedef, schema, where, { request, required = new Set(schema.required || []) }) {
    const problems = [];
    const documentedFields = schema.properties || {};
    const modelled = new Map(typedef.properties.map(property => [property.name, property]));
    for (const name of Object.keys(documentedFields)) {
        if (!modelled.has(name)) {
            problems.push(`${where}.${name}: documented, missing from the model`);
        }
    }
    for (const property of typedef.properties) {
        const field = `${where}.${property.name}`;
        if (!Object.prototype.hasOwnProperty.call(documentedFields, property.name)) {
            problems.push(`${field}: in the model, not in the document`);
            continue;
        }
        const shouldBeOptional = request ? !required.has(property.name) : true;
        if (property.optional !== shouldBeOptional) {
            problems.push(`${field}: ${property.optional ? 'optional' : 'required'} in the model, ${shouldBeOptional ? 'optional' : 'required'} in the document`);
        }
        problems.push(...compare(property.type, documentedFields[property.name], field, { request }));
    }

    return problems;
}

describe('the models against the document', () => {
    for (const entry of OPERATIONS) {
        const { operationId } = entry;
        it(operationId, () => {
            const Op = capitalised(operationId);
            const params = TYPEDEFS.get(`${Op}Params`);
            const result = TYPEDEFS.get(`${Op}Result`);
            assert.ok(params, `${Op}Params is modelled`);
            assert.ok(result, `${Op}Result is modelled`);
            let problems;
            if (operationId === 'listApiKeySigningKeys') {
                problems = [
                    ...compareObject(params, { type: 'object', properties: {} }, `${Op}Params`, { request: true }),
                    ...compareObject(result, pendingResult(), `${Op}Result`, { request: false }),
                ];
                assert.equal(Object.keys(pendingResult().properties).length, 5);
            } else {
                const doc = DOCUMENTED.get(operationId);
                problems = [
                    ...compareObject(params, { type: 'object', properties: doc.params }, `${Op}Params`, { request: true, required: doc.required }),
                    ...compareObject(result, doc.result, `${Op}Result`, { request: false }),
                ];
            }
            assert.deepEqual(problems, []);
        });
    }

    it('every method names its own models', () => {
        let methods = 0;
        for (const file of readdirSync(API_DIR).filter(name => name.endsWith('.js') && name !== 'common.js' && name !== 'index.js')) {
            const text = readFileSync(path.join(API_DIR, file), 'utf8');
            for (const match of text.matchAll(/@param \{([A-Za-z]+)Params\} \[?params\]?[\s\S]*?@returns \{([^\n]+)\}\n\s+\*\/\n\s+([A-Za-z]+)\(params, options\)/g)) {
                const [, paramsOf, returns, method] = match;
                const Op = capitalised(method);
                assert.equal(paramsOf, Op, `${method} takes ${paramsOf}Params`);
                const entry = OPERATIONS.find(candidate => candidate.operationId === method);
                assert.equal(returns, entry.paging
                    ? `import('./common').PageRequest<${Op}Result>`
                    : `Promise<import('./common').ItemResponse<${Op}Result>>`, method);
                methods += 1;
            }
        }
        assert.equal(methods, OPERATIONS.length);
    });

    it('the comparison catches drift', () => {
        const doc = DOCUMENTED.get('createSingleTransfer');
        const model = TYPEDEFS.get('CreateSingleTransferParams');
        const without = { ...model, properties: model.properties.filter(property => property.name !== 'note') };
        assert.deepEqual(compareObject(without, { properties: doc.params }, 'P', { request: true, required: doc.required }), ['P.note: documented, missing from the model']);
        const optional = { ...model, properties: model.properties.map(property => (property.name === 'amount' ? { ...property, optional: true } : property)) };
        assert.deepEqual(compareObject(optional, { properties: doc.params }, 'P', { request: true, required: doc.required }), ['P.amount: optional in the model, required in the document']);
        const wrongEnum = { ...model, properties: model.properties.map(property => (property.name === 'feePriority' ? { ...property, type: "'slow'|'fast'" } : property)) };
        assert.equal(compareObject(wrongEnum, { properties: doc.params }, 'P', { request: true, required: doc.required }).length, 1);
        const extra = { ...model, properties: [...model.properties, { name: 'memo', type: 'string', optional: true }] };
        assert.deepEqual(compareObject(extra, { properties: doc.params }, 'P', { request: true, required: doc.required }), ['P.memo: in the model, not in the document']);
    });
});
