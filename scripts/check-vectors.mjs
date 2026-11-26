#!/usr/bin/env node
/**
 * Every shared vector set has a runner in Node, in Python and in PHP, and is listed in the README.
 *
 *   node scripts/check-vectors.mjs
 *
 * A runner counts when a test file of that language names the vector file. PENDING lists the runners a
 * set may still lack, per language, while its module is being ported; it must shrink to zero, and a
 * listed runner that now exists also fails, so the list never goes stale.
 */

import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// The runners a set may still lack, per language: { 'set.json': ['node' | 'python' | 'php', ...] }. Empty:
// every set runs in all three languages.
const PENDING = {};

const filesUnder = (dir, match) => readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter(entry => entry.isFile() && match.test(entry.name) && !path.join(entry.parentPath, entry.name).includes('node_modules'))
    .map(entry => path.join(entry.parentPath, entry.name));
const read = files => files.map(file => readFileSync(file, 'utf8')).join('\n');

const sets = readdirSync(path.join(ROOT, 'test-vectors')).filter(name => name.endsWith('.json')).sort();
const node = read(filesUnder(path.join(ROOT, 'node', 'packages'), /\.test\.js$/));
const python = read(filesUnder(path.join(ROOT, 'python'), /^test_.*\.py$/));
const php = read(filesUnder(path.join(ROOT, 'php', 'tests'), /\.php$/));
const readme = readFileSync(path.join(ROOT, 'README.md'), 'utf8');

const runners = { node, python, php };
const names = { node: 'Node', python: 'Python', php: 'PHP' };

const problems = [];
for (const set of Object.keys(PENDING)) {
    if (!sets.includes(set)) {
        problems.push(`${set}: listed in PENDING, but there is no such vector set`);
    }
}
for (const set of sets) {
    for (const [language, tests] of Object.entries(runners)) {
        const pending = (PENDING[set] || []).includes(language);
        if (!tests.includes(set) && !pending) {
            problems.push(`${set}: no ${names[language]} test names it`);
        }
        if (tests.includes(set) && pending) {
            problems.push(`${set}: a ${names[language]} test names it now; remove it from PENDING`);
        }
    }
    if (!readme.includes(`\`${set}\``)) {
        problems.push(`${set}: not listed in README.md`);
    }
}

process.stdout.write(`${sets.length} vector sets: ${sets.join(', ')}\n`);
if (problems.length > 0) {
    process.stdout.write(`${problems.map(problem => `- ${problem}`).join('\n')}\nvectors: FAILED\n`);
    process.exitCode = 1;
} else {
    const pending = Object.entries(PENDING).map(([set, languages]) => `${set} (${languages.map(language => names[language]).join(', ')})`);
    process.stdout.write(`vectors: every set has a Node, a Python and a PHP runner and is in the README${pending.length > 0 ? `; still pending: ${pending.join('; ')}` : ''}\n`);
}
