#!/usr/bin/env node
/**
 * What must hold before a version is released. The release workflow runs it first and stops on any
 * problem; the release-dry-run job runs it with --report on every push.
 *
 *   node scripts/release/guard.mjs --version 0.9.0-rc.1 --ref refs/tags/v0.9.0-rc.1 --sha <commit> \
 *       --repository Vaultody-com/vaultody-sdk --visibility public [--root-fingerprint <hex>]
 *   node scripts/release/guard.mjs --report
 *
 * Always (a problem fails --report too):
 *   - VERSION is X.Y.Z or X.Y.Z-rc.N, and every package says the same (scripts/version.mjs);
 *   - each embedded response-signing root slot is empty or a P-256 key whose fingerprint matches;
 *     the three languages embed the same keys; no slot holds a test-only root;
 *   - the build defaults (the response-signature mode when none is given, whether address paths are public)
 *     are valid and the same in the three languages.
 * Every release, a release candidate too:
 *   - the run: the version asked for is VERSION; the run is on the tag vVERSION, an annotated tag
 *     SSH-signed by a key in .github/release-signers as it is on main, on a commit that is on main;
 *     the repository is public (npm provenance and GitHub attestations need it);
 *   - the packages: a LICENSE in the repository and in every package, and a licence in every manifest;
 *     no "private": true or "Private :: Do Not Upload" left; the npm "repository" is this repository
 *     (trusted publishing refuses anything else); a CHANGELOG.md section for the version.
 * A stable release (no -rc.N) also needs:
 *   - the current root embedded, and --root-fingerprint (the fingerprint published to clients) equal
 *     to it;
 *   - no pending operation left in contract/pending/ (the coverage check covers the rest);
 *   - the build defaults of a stable release: responses must be signed by default ('required', not
 *     'when-present'), and address paths are public (generateDepositAddress requires them).
 *
 * No dependencies; Node 22 or later, python3 (to read the Python roots) and git.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { checkVersions, parseVersion, toPep440 } from '../version.mjs';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export const LANGUAGES = Object.freeze(['node', 'python', 'php']);
export const SLOTS = Object.freeze(['current', 'next']);

/**
 * Fingerprints of roots that are not production roots but do not appear in the repository's test
 * material either (a test environment's root, say). The test-only roots of the vectors and tests are found
 * by scanning those files, so they need no entry here.
 */
export const NON_PRODUCTION_ROOTS = Object.freeze([]);

/** Where the test material lives: a root whose key or fingerprint appears here is a test root. */
const TEST_MATERIAL = ['test-vectors', 'conformance', 'node/packages/verify/test', 'node/packages/sdk/test',
    'python/vaultody-verify/tests', 'python/vaultody-sdk/tests', 'php/tests'];

/** The directories that become packages, each of which must carry the LICENSE. */
export const PACKAGE_DIRS = Object.freeze(['node/packages/verify', 'node/packages/sdk', 'python/vaultody-verify',
    'python/vaultody-sdk', 'php']);
const NPM_PACKAGES = ['node/packages/verify', 'node/packages/sdk'];
const PYTHON_PACKAGES = ['python/vaultody-verify', 'python/vaultody-sdk'];

// A P-256 SubjectPublicKeyInfo with a named curve and an uncompressed point: this 27-byte header and the
// 64-byte point (the only layout the packages accept; see rootKeys.js).
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex');
const P256_SPKI_BYTES = P256_SPKI_PREFIX.length + 64;
const FINGERPRINT = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------------------------------
// The embedded roots, as each language holds them

/** Node: the module itself. */
function readNodeRoots(root) {
    const file = path.join(root, 'node/packages/verify/src/roots.js');
    const roots = createRequire(import.meta.url)(file);

    return Object.fromEntries(SLOTS.map(slot => [slot, { pem: roots[slot]?.pem, fingerprint: roots[slot]?.fingerprint }]));
}

// Python: the four module constants, read with Python's own parser and without importing the module.
const PYTHON_READER = `
import ast, json, sys
names = ("CURRENT_ROOT_PEM", "CURRENT_ROOT_FINGERPRINT", "NEXT_ROOT_PEM", "NEXT_ROOT_FINGERPRINT")
found = {}
for node in ast.parse(open(sys.argv[1], encoding="utf-8").read()).body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and getattr(node.targets[0], "id", None) in names:
        name = node.targets[0].id
        if name in found:
            sys.exit(name + " is assigned twice")
        value = ast.literal_eval(node.value)
        found[name] = value.decode("ascii") if isinstance(value, bytes) else value
missing = [name for name in names if name not in found]
if missing:
    sys.exit("not found: " + ", ".join(missing))
print(json.dumps(found))
`;

function readPythonRoots(root, python = 'python3') {
    const file = path.join(root, 'python/vaultody-verify/vaultody_verify/roots.py');
    const found = JSON.parse(execFileSync(python, ['-I', '-c', PYTHON_READER, file], { encoding: 'utf8' }));

    return {
        current: { pem: found.CURRENT_ROOT_PEM, fingerprint: found.CURRENT_ROOT_FINGERPRINT },
        next: { pem: found.NEXT_ROOT_PEM, fingerprint: found.NEXT_ROOT_FINGERPRINT },
    };
}

// PHP: the two class constants, each written as ['pem' => '...', 'fingerprint' => '...'] with single-quoted
// strings (where only \\ and \' are escapes), so they can be read exactly without running PHP.
const PHP_STRING = String.raw`'((?:[^'\\]|\\.)*)'`;
const PHP_SLOT = name => new RegExp(String.raw`public const ${name} = \[\s*'pem' => ${PHP_STRING},\s*'fingerprint' => ${PHP_STRING},?\s*\];`, 'g');
const phpUnquote = text => text.replace(/\\([\\'])/g, '$1');

function readPhpRoots(root) {
    const file = 'php/src/Verify/EmbeddedRoots.php';
    const text = readFileSync(path.join(root, file), 'utf8');

    return Object.fromEntries(SLOTS.map(slot => {
        const matches = [...text.matchAll(PHP_SLOT(slot.toUpperCase()))];
        if (matches.length !== 1) {
            throw new Error(`${file}: ${slot.toUpperCase()} must be ['pem' => '...', 'fingerprint' => '...'] with single-quoted strings`);
        }

        return [slot, { pem: phpUnquote(matches[0][1]), fingerprint: phpUnquote(matches[0][2]) }];
    }));
}

/** The embedded roots of every language: { node: { current: { pem, fingerprint }, next }, python, php }. */
export function readEmbeddedRoots(root = ROOT, { python } = {}) {
    return { node: readNodeRoots(root), python: readPythonRoots(root, python), php: readPhpRoots(root) };
}

/**
 * One slot as a key: null when empty; otherwise the SPKI DER (base64) and its fingerprint, or the reason
 * it is not a valid root.
 */
export function readSlot({ pem, fingerprint } = {}) {
    const blank = value => value === undefined || value === null || value === '';
    if (blank(pem) && blank(fingerprint)) {
        return null;
    }
    if (blank(pem) || blank(fingerprint)) {
        return { error: 'the PEM and its fingerprint must be set together' };
    }
    if (typeof pem !== 'string' || typeof fingerprint !== 'string' || !FINGERPRINT.test(fingerprint)) {
        return { error: 'the fingerprint must be 64 lowercase hex characters' };
    }
    const labels = [...pem.matchAll(/-----BEGIN ([^-]*)-----/g)].map(match => match[1]);
    const body = pem.match(/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/);
    if (labels.length !== 1 || labels[0] !== 'PUBLIC KEY' || !body) {
        return { error: 'the PEM must hold exactly one "PUBLIC KEY" block' };
    }
    const der = Buffer.from(body[1].replace(/\s+/g, ''), 'base64');
    if (der.length !== P256_SPKI_BYTES || !der.subarray(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) {
        return { error: 'the key must be P-256 in standard SPKI form (named curve, uncompressed point)' };
    }
    try {
        createPublicKey({ key: der, format: 'der', type: 'spki' });
    } catch (error) {
        return { error: `the key does not load: ${error.message}` };
    }
    const computed = createHash('sha256').update(der).digest('hex');
    if (computed !== fingerprint) {
        return { error: `the fingerprint ${fingerprint} does not match the key, whose fingerprint is ${computed}` };
    }

    return { der: der.toString('base64'), fingerprint };
}

/** Every file of the test material, as one string with whitespace and \n escapes removed. */
export function readTestMaterial(root = ROOT) {
    const parts = [];
    for (const dir of TEST_MATERIAL) {
        const full = path.join(root, dir);
        if (!existsSync(full)) {
            continue;
        }
        for (const entry of readdirSync(full, { withFileTypes: true, recursive: true })) {
            const file = path.join(entry.parentPath, entry.name);
            if (entry.isFile() && !file.includes('node_modules') && !file.includes('__pycache__')) {
                parts.push(readFileSync(file, 'utf8'));
            }
        }
    }

    return parts.join('\n').replace(/\\n|\s+/g, '');
}

/**
 * The checks on the embedded roots.
 *
 * @param {Object} roots from readEmbeddedRoots
 * @param {{ testMaterial: string, nonProduction?: string[] }} options
 * @returns {{ problems: string[], slots: { current: Object|null, next: Object|null } }} the problems, and each
 *          slot as the languages agree on it (null when empty or when they do not agree)
 */
export function checkRoots(roots, { testMaterial, nonProduction = NON_PRODUCTION_ROOTS }) {
    const problems = [];
    const slots = {};
    for (const slot of SLOTS) {
        const read = Object.fromEntries(LANGUAGES.map(language => [language, readSlot(roots[language]?.[slot])]));
        for (const language of LANGUAGES) {
            if (read[language]?.error) {
                problems.push(`${language} ${slot} root: ${read[language].error}`);
            }
        }
        const keys = new Set(LANGUAGES.map(language => (read[language] ? `${read[language].der}/${read[language].fingerprint}` : 'empty')));
        if (keys.size > 1) {
            problems.push(`the ${slot} root differs between the languages: ${LANGUAGES.map(language => `${language} ${read[language] ? read[language].fingerprint || 'invalid' : 'empty'}`).join(', ')}`);
            slots[slot] = null;
            continue;
        }
        const key = read.node && !read.node.error ? read.node : null;
        slots[slot] = key;
        if (key && (testMaterial.includes(key.fingerprint) || testMaterial.includes(key.der))) {
            problems.push(`the ${slot} root ${key.fingerprint} is a test-only root (it is in the test vectors or tests)`);
        } else if (key && nonProduction.includes(key.fingerprint)) {
            problems.push(`the ${slot} root ${key.fingerprint} is listed as not a production root (NON_PRODUCTION_ROOTS)`);
        }
    }

    return { problems, slots };
}

// ---------------------------------------------------------------------------------------------------
// The build defaults a stable release changes

/** Each default, the values it may take, and the value a stable release must ship. */
export const DEFAULTS = Object.freeze({
    DEFAULT_RESPONSE_SIGNATURE: Object.freeze({ allowed: Object.freeze(['when-present', 'required']), stable: 'required',
        why: 'a stable release refuses unsigned responses by default' }),
    ADDRESS_PATHS_PUBLIC: Object.freeze({ allowed: Object.freeze([false, true]), stable: true,
        why: 'a stable release ships after the address derivation paths are public, and requires them on generateDepositAddress' }),
});
const DEFAULT_NAMES = Object.keys(DEFAULTS);

/** Node: a module with no dependency. */
function readNodeDefaults(root) {
    const defaults = createRequire(import.meta.url)(path.join(root, 'node/packages/sdk/src/defaults.js'));

    return Object.fromEntries(DEFAULT_NAMES.map(name => [name, defaults[name]]));
}

// Python: the module constants, read with Python's own parser and without importing the module.
const PYTHON_DEFAULTS_READER = `
import ast, json, sys
names = ("DEFAULT_RESPONSE_SIGNATURE", "ADDRESS_PATHS_PUBLIC")
found = {}
for node in ast.parse(open(sys.argv[1], encoding="utf-8").read()).body:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) == 1 and getattr(targets[0], "id", None) in names:
            name = targets[0].id
            if name in found:
                sys.exit(name + " is assigned twice")
            found[name] = ast.literal_eval(node.value)
missing = [name for name in names if name not in found]
if missing:
    sys.exit("not found: " + ", ".join(missing))
print(json.dumps(found))
`;

function readPythonDefaults(root, python = 'python3') {
    const file = path.join(root, 'python/vaultody-sdk/vaultody_sdk/_defaults.py');

    return JSON.parse(execFileSync(python, ['-I', '-c', PYTHON_DEFAULTS_READER, file], { encoding: 'utf8' }));
}

// PHP: two class constants of Transport, each on one line: a single-quoted string, or true / false.
const PHP_DEFAULTS = {
    DEFAULT_RESPONSE_SIGNATURE: { pattern: /public const DEFAULT_RESPONSE_SIGNATURE = '([a-z-]*)';/g, read: text => text },
    ADDRESS_PATHS_PUBLIC: { pattern: /public const ADDRESS_PATHS_PUBLIC = (true|false);/g, read: text => text === 'true' },
};

function readPhpDefaults(root) {
    const file = 'php/src/Transport/Transport.php';
    const text = readFileSync(path.join(root, file), 'utf8');

    return Object.fromEntries(DEFAULT_NAMES.map(name => {
        const matches = [...text.matchAll(PHP_DEFAULTS[name].pattern)];
        if (matches.length !== 1) {
            throw new Error(`${file}: ${name} must be declared exactly once, as public const ${name} = <value>;`);
        }

        return [name, PHP_DEFAULTS[name].read(matches[0][1])];
    }));
}

/** The build defaults of every language: { node: { DEFAULT_RESPONSE_SIGNATURE, ADDRESS_PATHS_PUBLIC }, python, php }. */
export function readDefaults(root = ROOT, { python } = {}) {
    return { node: readNodeDefaults(root), python: readPythonDefaults(root, python), php: readPhpDefaults(root) };
}

/**
 * The checks on every commit: each default is one of its values, and the three languages agree.
 *
 * @returns {{ problems: string[], values: Object }} values: each default as the languages agree on it (undefined
 *          where they do not, or where it is not valid)
 */
export function checkDefaults(defaults) {
    const problems = [];
    const values = {};
    for (const name of DEFAULT_NAMES) {
        const seen = LANGUAGES.map(language => defaults[language]?.[name]);
        LANGUAGES.forEach((language, index) => {
            if (!DEFAULTS[name].allowed.includes(seen[index])) {
                problems.push(`${language} ${name} is ${JSON.stringify(seen[index])}, not one of ${DEFAULTS[name].allowed.map(value => JSON.stringify(value)).join(', ')}`);
            }
        });
        if (new Set(seen.map(value => JSON.stringify(value))).size > 1) {
            problems.push(`${name} differs between the languages: ${LANGUAGES.map((language, index) => `${language} ${JSON.stringify(seen[index])}`).join(', ')}`);
            values[name] = undefined;
        } else {
            values[name] = DEFAULTS[name].allowed.includes(seen[0]) ? seen[0] : undefined;
        }
    }

    return { problems, values };
}

/** What a stable release needs of the defaults: each at its stable value. */
export function checkStableDefaults(values) {
    return DEFAULT_NAMES.filter(name => values[name] !== DEFAULTS[name].stable)
        .map(name => `${name} is ${values[name] === undefined ? 'not agreed between the languages' : JSON.stringify(values[name])}: ${DEFAULTS[name].why}, so it must be ${JSON.stringify(DEFAULTS[name].stable)} in every language`);
}

// ---------------------------------------------------------------------------------------------------
// The packages

const readJson = file => JSON.parse(readFileSync(file, 'utf8'));
const sameRepository = (url, repository) => typeof url === 'string'
    && url.replace(/^git\+/, '').replace(/\.git$/, '').toLowerCase() === `https://github.com/${repository}`.toLowerCase();

/** What every published version needs from the packages themselves. */
export function checkPackages(root, { version, repository }) {
    const problems = [];

    const licence = path.join(root, 'LICENSE');
    if (!existsSync(licence)) {
        problems.push('no LICENSE: the repository and every package ship the Apache-2.0 licence');
    } else {
        const text = readFileSync(licence);
        for (const dir of PACKAGE_DIRS) {
            const copy = path.join(root, dir, 'LICENSE');
            if (!existsSync(copy) || !readFileSync(copy).equals(text)) {
                problems.push(`${dir}/LICENSE is missing or differs from LICENSE (each package ships its own copy)`);
            }
        }
    }
    for (const dir of NPM_PACKAGES) {
        const manifest = readJson(path.join(root, dir, 'package.json'));
        if (!manifest.license || manifest.license === 'UNLICENSED') {
            problems.push(`${dir}/package.json: license is ${manifest.license || 'not set'}`);
        }
        if (manifest.private === true) {
            problems.push(`${dir}/package.json: still "private": true`);
        }
        if (repository && !sameRepository(manifest.repository?.url, repository)) {
            problems.push(`${dir}/package.json: repository is ${manifest.repository?.url || 'not set'}, not ${repository} (npm trusted publishing refuses that)`);
        }
    }
    for (const dir of PYTHON_PACKAGES) {
        const text = readFileSync(path.join(root, dir, 'pyproject.toml'), 'utf8');
        if (!/^license = "[^"]+"$/m.test(text)) {
            problems.push(`${dir}/pyproject.toml: no license = "<SPDX expression>"`);
        }
        if (text.includes('Private :: Do Not Upload')) {
            problems.push(`${dir}/pyproject.toml: still "Private :: Do Not Upload"`);
        }
    }
    const composer = readJson(path.join(root, 'php/composer.json'));
    if (!composer.license || composer.license === 'proprietary') {
        problems.push(`php/composer.json: license is ${composer.license || 'not set'}`);
    }

    const changelog = path.join(root, 'CHANGELOG.md');
    const escaped = version.replace(/[.*+?^$()|[\]{}\\]/g, '\\$&');
    const heading = new RegExp(`^## \\[?${escaped}\\]?(\\s|$)`, 'm');
    if (!existsSync(changelog) || !heading.test(readFileSync(changelog, 'utf8'))) {
        problems.push(`CHANGELOG.md has no "## ${version}" section (the release notes)`);
    }

    return problems;
}

/**
 * What a stable release needs on top: the production root, named by the run, and nothing pending. A
 * report cannot know the fingerprint the run will be given, so it leaves that out.
 */
export function checkStable(root, { slots, rootFingerprint, report = false }) {
    const problems = [];
    if (!slots.current) {
        problems.push('no current root embedded: a stable release needs the production root key and its fingerprint in every language');
    } else if (!rootFingerprint && !report) {
        problems.push('no --root-fingerprint: a stable release names the production root fingerprint published to clients');
    }
    const pending = path.join(root, 'contract/pending');
    const files = existsSync(pending) ? readdirSync(pending, { recursive: true, withFileTypes: true }).filter(entry => entry.isFile()) : [];
    if (files.length > 0) {
        problems.push(`contract/pending/ still has ${files.map(entry => entry.name).join(', ')}: a stable release covers only operations published on production`);
    }

    return problems;
}

/** The fingerprint typed into the run must be the embedded current root (stable releases always give one). */
export function checkRootFingerprint({ slots, rootFingerprint }) {
    if (!rootFingerprint) {
        return [];
    }
    if (!slots.current) {
        return [`--root-fingerprint ${rootFingerprint} given, but no current root is embedded`];
    }

    return rootFingerprint === slots.current.fingerprint ? [] : [`--root-fingerprint ${rootFingerprint} is not the embedded current root ${slots.current.fingerprint}`];
}

// ---------------------------------------------------------------------------------------------------
// The run: the tag, its signature, main

const git = (cwd, args, options = {}) => spawnSync('git', args, { cwd, encoding: 'utf8', ...options });

/**
 * The tag the run is on: annotated, SSH-signed by a key in .github/release-signers as `mainRef` has it,
 * pointing at `sha`, and on `mainRef`.
 */
export function checkTag(cwd, { version, sha, mainRef = 'origin/main' }) {
    const tag = `v${version}`;
    const problems = [];
    const type = git(cwd, ['cat-file', '-t', `refs/tags/${tag}`]).stdout.trim();
    if (type !== 'tag') {
        return [type === 'commit' ? `${tag} is a lightweight tag: a release tag is annotated and signed (git tag -s)` : `there is no tag ${tag}`];
    }
    const commit = git(cwd, ['rev-parse', `refs/tags/${tag}^{commit}`]).stdout.trim();
    if (commit !== sha) {
        problems.push(`${tag} points at ${commit}, but the run is on ${sha}`);
    }
    if (git(cwd, ['merge-base', '--is-ancestor', commit, mainRef]).status !== 0) {
        problems.push(`${tag} (${commit}) is not on ${mainRef}`);
    }
    const signers = git(cwd, ['show', `${mainRef}:.github/release-signers`]);
    const entries = signers.status === 0 ? signers.stdout.split('\n').filter(text => text.trim() !== '' && !text.trim().startsWith('#')) : [];
    if (entries.length === 0) {
        problems.push(`no release signer in .github/release-signers on ${mainRef}: nobody may release yet`);

        return problems;
    }
    if (!git(cwd, ['cat-file', 'tag', `refs/tags/${tag}`]).stdout.includes('-----BEGIN SSH SIGNATURE-----')) {
        problems.push(`${tag} has no SSH signature (git tag -s with gpg.format=ssh)`);

        return problems;
    }
    const dir = mkdtempSync(path.join(tmpdir(), 'vaultody-signers-'));
    try {
        const file = path.join(dir, 'allowed_signers');
        writeFileSync(file, `${entries.join('\n')}\n`);
        const verified = git(cwd, ['-c', `gpg.ssh.allowedSignersFile=${file}`, 'verify-tag', tag]);
        if (verified.status !== 0) {
            problems.push(`${tag}: the signature is not from a release signer on ${mainRef}: ${(verified.stderr || verified.stdout).trim().split('\n').join(' ')}`);
        }
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }

    return problems;
}

/** The run itself: the version asked for, the ref, the repository's visibility, the tag. */
export function checkRun(root, { inputVersion, version, ref, sha, visibility, mainRef }) {
    const problems = [];
    if (inputVersion !== version) {
        problems.push(`the run asks for ${JSON.stringify(inputVersion)}, but VERSION is ${version}`);
    }
    if (visibility !== 'public') {
        problems.push(`the repository is ${visibility || 'of unknown visibility'}: npm provenance and GitHub attestations need a public repository. Nothing is published without provenance; make the repository public first`);
    }
    if (ref !== `refs/tags/v${version}`) {
        problems.push(`the run is on ${ref}: a release runs on its signed tag refs/tags/v${version} ("Use workflow from: Tags")`);
    } else {
        problems.push(...checkTag(root, { version, sha, mainRef }));
    }

    return problems;
}

// ---------------------------------------------------------------------------------------------------

/**
 * Every check, grouped by when it applies.
 *
 * @returns {{ version: string, isStable: boolean, slots: Object, defaults: Object, always: string[], release: string[], stable: string[], run: string[] }}
 *          the problems: `always` on every commit, `release` for every release, `stable` for a stable one,
 *          `run` of the workflow run (none in a report)
 */
export function guard(root, { report, inputVersion, ref, sha, repository, visibility, rootFingerprint, mainRef, python }) {
    const versions = checkVersions(root);
    const version = versions.version;
    const parsed = parseVersion(version);
    const roots = checkRoots(readEmbeddedRoots(root, { python }), { testMaterial: readTestMaterial(root) });
    const defaults = checkDefaults(readDefaults(root, { python }));
    const always = [...versions.problems, ...roots.problems, ...defaults.problems];

    return {
        version,
        isStable: parsed ? parsed.stable : false,
        slots: roots.slots,
        defaults: defaults.values,
        always,
        release: [...checkPackages(root, { version, repository }), ...checkRootFingerprint({ slots: roots.slots, rootFingerprint })],
        stable: [...checkStable(root, { slots: roots.slots, rootFingerprint, report }), ...checkStableDefaults(defaults.values)],
        run: report ? [] : checkRun(root, { inputVersion, version, ref, sha, visibility, mainRef }),
    };
}

const list = problems => problems.map(problem => `- ${problem}`).join('\n');
const slotLine = (slots, slot) => (slots[slot] ? `\`${slots[slot].fingerprint}\`` : 'empty');
const defaultLine = (defaults, name) => (defaults[name] === undefined ? 'not agreed' : `\`${defaults[name]}\``);

function render(result, report) {
    const lines = [
        `### Release guard: ${result.version} (${result.isStable ? 'stable' : 'release candidate'})${report ? ', report' : ''}`,
        '',
        `- Embedded roots: current ${slotLine(result.slots, 'current')}, next ${slotLine(result.slots, 'next')}`,
        `- Defaults: response signature ${defaultLine(result.defaults, 'DEFAULT_RESPONSE_SIGNATURE')}, address paths public ${defaultLine(result.defaults, 'ADDRESS_PATHS_PUBLIC')}`,
    ];
    if (result.always.length > 0) {
        lines.push('', '**Wrong on every commit:**', list(result.always));
    }
    if (report) {
        lines.push('', result.release.length > 0
            ? `**A release of this commit would be refused** (a release candidate too):\n${list(result.release)}`
            : 'A release candidate of this commit would pass these checks (the tag, the signature and the repository are checked by the run).');
        lines.push('', result.stable.length > 0 ? `**A stable release would also need:**\n${list(result.stable)}` : 'A stable release would also pass.');
    } else {
        const refused = [...result.run, ...result.release, ...(result.isStable ? result.stable : [])];
        if (refused.length > 0) {
            lines.push('', '**Refused:**', list(refused));
        }
    }

    return `${lines.join('\n')}\n`;
}

function main(argv) {
    const options = { report: false, mainRef: 'origin/main' };
    const names = { '--version': 'inputVersion', '--ref': 'ref', '--sha': 'sha', '--repository': 'repository', '--visibility': 'visibility',
        '--root-fingerprint': 'rootFingerprint', '--main-ref': 'mainRef', '--python': 'python' };
    for (let i = 0; i < argv.length; i += 1) {
        if (argv[i] === '--report') {
            options.report = true;
        } else if (names[argv[i]] && i + 1 < argv.length) {
            options[names[argv[i]]] = argv[i + 1];
            i += 1;
        } else {
            throw new Error(`unknown argument ${argv[i]}`);
        }
    }
    if (options.report) {
        options.repository = options.repository || process.env.GITHUB_REPOSITORY;
    }
    // An empty input from the workflow means none was given.
    options.rootFingerprint = options.rootFingerprint || undefined;

    const result = guard(ROOT, options);
    const markdown = render(result, options.report);
    process.stdout.write(markdown);
    if (process.env.GITHUB_STEP_SUMMARY) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
    }

    const refused = options.report ? result.always : [...result.always, ...result.run, ...result.release, ...(result.isStable ? result.stable : [])];
    if (refused.length > 0) {
        process.stdout.write(`\nrelease guard: REFUSED, ${refused.length} problem(s)\n`);

        return 1;
    }
    if (!options.report && process.env.GITHUB_OUTPUT) {
        appendFileSync(process.env.GITHUB_OUTPUT, [
            `version=${result.version}`,
            `pep440=${toPep440(result.version)}`,
            `prerelease=${!result.isStable}`,
            `dist-tag=${result.isStable ? 'latest' : 'next'}`,
        ].map(entry => `${entry}\n`).join(''));
    }
    process.stdout.write(`\nrelease guard: ok${options.report ? ' (report)' : ''}\n`);

    return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    try {
        process.exitCode = main(process.argv.slice(2));
    } catch (error) {
        process.stderr.write(`release guard: ${error.message}\n`);
        process.exitCode = 1;
    }
}
