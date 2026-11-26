#!/usr/bin/env node
/**
 * One version number for every package: VERSION drives all three languages.
 *
 *   node scripts/version.mjs check              # every package says what VERSION says
 *   node scripts/version.mjs set 0.9.0-rc.1     # writes VERSION and every place below
 *   node scripts/version.mjs print [--pep440]   # VERSION, or its Python form
 *
 * A version is X.Y.Z (a stable release) or X.Y.Z-rc.N (a release candidate); nothing else is released.
 * Node and PHP carry it as written. Python carries its PEP 440 form (0.9.0-rc.1 is 0.9.0rc1), which is
 * what PyPI, pip and the file names show anyway, so __version__ and the installed metadata agree.
 *
 * No dependencies; Node 22 or later.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-rc\.([1-9]\d*))?$/;

/**
 * Reads a version string. Returns null for anything that is not X.Y.Z or X.Y.Z-rc.N (N from 1).
 *
 * @param {string} version
 * @returns {{ version: string, major: number, minor: number, patch: number, rc: number|null, stable: boolean }|null}
 */
export function parseVersion(version) {
    const match = typeof version === 'string' ? version.match(VERSION_PATTERN) : null;
    if (!match) {
        return null;
    }
    const rc = match[4] === undefined ? null : Number(match[4]);

    return { version, major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), rc, stable: rc === null };
}

/** The PEP 440 form of a version: 0.9.0-rc.1 → 0.9.0rc1; a stable version is unchanged. */
export function toPep440(version) {
    const parsed = parseVersion(version);
    if (!parsed) {
        throw new Error(`${JSON.stringify(version)} is not a release version (X.Y.Z or X.Y.Z-rc.N)`);
    }

    return `${parsed.major}.${parsed.minor}.${parsed.patch}${parsed.rc === null ? '' : `rc${parsed.rc}`}`;
}

/** A JSON file, kept in the layout npm writes (two spaces, a newline at the end). */
const json = (file, keys) => ({
    file,
    what: keys.join('.'),
    form: 'semver',
    read(text) {
        let value = JSON.parse(text);
        for (const key of keys) {
            value = value === undefined || value === null ? undefined : value[key];
        }

        return value;
    },
    write(text, version) {
        const document = JSON.parse(text);
        if (`${JSON.stringify(document, null, 2)}\n` !== text) {
            throw new Error(`${file} is not in the layout npm writes; not rewriting it`);
        }
        let parent = document;
        for (const key of keys.slice(0, -1)) {
            parent = parent[key];
        }
        parent[keys[keys.length - 1]] = version;

        return `${JSON.stringify(document, null, 2)}\n`;
    },
});

/** A version inside a text file: the one line the pattern matches, with the version as its second group. */
const line = (file, what, form, pattern) => ({
    file,
    what,
    form,
    read(text) {
        const matches = [...text.matchAll(new RegExp(pattern.source, 'gm'))];

        return matches.length === 1 ? matches[0][2] : undefined;
    },
    write(text, version) {
        const matches = [...text.matchAll(new RegExp(pattern.source, 'gm'))];
        if (matches.length !== 1) {
            throw new Error(`${file}: expected one ${what}, found ${matches.length}`);
        }

        return text.replace(new RegExp(pattern.source, 'm'), (_, before, _old, after) => `${before}${version}${after}`);
    },
});

/**
 * Every place a package states its version or the version of its sibling. `form` says which spelling
 * the place holds: 'semver' (VERSION as written) or 'pep440' (Python).
 */
export const PLACES = Object.freeze([
    json('node/packages/verify/package.json', ['version']),
    json('node/packages/sdk/package.json', ['version']),
    json('node/packages/sdk/package.json', ['dependencies', '@vaultody/verify']),
    json('node/package-lock.json', ['packages', 'packages/verify', 'version']),
    json('node/package-lock.json', ['packages', 'packages/sdk', 'version']),
    json('node/package-lock.json', ['packages', 'packages/sdk', 'dependencies', '@vaultody/verify']),
    line('python/vaultody-verify/pyproject.toml', 'version', 'pep440', /^(version = ")([^"]*)(")$/),
    line('python/vaultody-verify/vaultody_verify/__init__.py', '__version__', 'pep440', /^(__version__ = ")([^"]*)(")$/),
    line('python/vaultody-sdk/pyproject.toml', 'version', 'pep440', /^(version = ")([^"]*)(")$/),
    line('python/vaultody-sdk/pyproject.toml', 'the vaultody-verify pin', 'pep440', /^(dependencies = \[.*"vaultody-verify==)([^"]*)(".*)$/),
    line('python/vaultody-sdk/vaultody_sdk/_version.py', '__version__', 'pep440', /^(__version__ = ")([^"]*)(")$/),
    line('php/src/Version.php', 'SDK_VERSION', 'semver', /^(\s*public const SDK_VERSION = ')([^']*)(';)$/),
]);

const expectedIn = (form, version) => (form === 'pep440' ? toPep440(version) : version);

/** VERSION as written, without the newline. */
export const readVersion = (root = ROOT) => readFileSync(path.join(root, 'VERSION'), 'utf8').trim();

/**
 * Compares every place with VERSION.
 *
 * @returns {{ ok: boolean, version: string, problems: string[], places: Array<{ file: string, what: string, value: string|undefined, expected: string|undefined }> }}
 */
export function checkVersions(root = ROOT) {
    const version = readVersion(root);
    const problems = [];
    if (!parseVersion(version)) {
        problems.push(`VERSION is ${JSON.stringify(version)}: a release version is X.Y.Z or X.Y.Z-rc.N`);
    }
    const places = PLACES.map(place => {
        const value = place.read(readFileSync(path.join(root, place.file), 'utf8'));
        const expected = parseVersion(version) ? expectedIn(place.form, version) : undefined;
        if (value === undefined) {
            problems.push(`${place.file}: no ${place.what} found`);
        } else if (expected !== undefined && value !== expected) {
            problems.push(`${place.file}: ${place.what} is ${value}; VERSION ${version} means ${expected}`);
        }

        return { file: place.file, what: place.what, value, expected };
    });

    return { ok: problems.length === 0, version, problems, places };
}

/** Writes `version` to VERSION and every place, then checks the result. */
export function setVersion(version, root = ROOT) {
    if (!parseVersion(version)) {
        throw new Error(`${JSON.stringify(version)} is not a release version (X.Y.Z or X.Y.Z-rc.N)`);
    }
    // Every file is rewritten in memory first, so a place that cannot be written leaves nothing half done.
    const texts = new Map();
    for (const place of PLACES) {
        const file = path.join(root, place.file);
        const text = texts.has(file) ? texts.get(file) : readFileSync(file, 'utf8');
        texts.set(file, place.write(text, expectedIn(place.form, version)));
    }
    texts.set(path.join(root, 'VERSION'), `${version}\n`);
    for (const [file, text] of texts) {
        writeFileSync(file, text);
    }

    return checkVersions(root);
}

function main(argv) {
    const [command, ...rest] = argv;
    if (command === 'print') {
        const version = readVersion();
        process.stdout.write(`${rest.includes('--pep440') ? toPep440(version) : version}\n`);

        return 0;
    }
    if (command !== 'check' && command !== 'set') {
        process.stderr.write('usage: node scripts/version.mjs check | set <X.Y.Z or X.Y.Z-rc.N> | print [--pep440]\n');

        return 2;
    }
    const result = command === 'set' ? setVersion(rest[0]) : checkVersions();
    for (const place of result.places) {
        process.stdout.write(`${place.value === place.expected ? 'ok  ' : 'DIFF'} ${place.file} (${place.what}): ${place.value}\n`);
    }
    if (!result.ok) {
        process.stdout.write(`${result.problems.map(problem => `- ${problem}`).join('\n')}\nversion: FAILED\n`);

        return 1;
    }
    process.stdout.write(`version: every package is ${result.version}${parseVersion(result.version).stable ? '' : ` (Python ${toPep440(result.version)})`}\n`);

    return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    try {
        process.exitCode = main(process.argv.slice(2));
    } catch (error) {
        process.stderr.write(`version: ${error.message}\n`);
        process.exitCode = 1;
    }
}
