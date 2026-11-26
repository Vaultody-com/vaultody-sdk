#!/usr/bin/env node
/**
 * Checks what each package built by pack.sh ships.
 *
 *   node scripts/release/check-packages.mjs <out> [--release] [--extract <dir>]
 *
 * For every package (the two npm tarballs, the two wheels and two sdists, the PHP zip):
 *   - exactly the files expected, named for the version in VERSION, and nothing else in <out>;
 *   - only the paths its kind may hold (sources, README, manifest, LICENSE, the build metadata), and its
 *     source files exactly the ones git tracks in its source directory (no module missing, none extra);
 *   - no tests, test vectors, key files, private keys, secrets of the test vectors or test-only root keys;
 *   - the version (and the sibling it pins) as VERSION says, in each language's spelling;
 *   - the README.
 * What only the first release changes is a TODO in a dry run and a failure with --release: the private
 * markers ("private": true, "Private :: Do Not Upload"); a missing LICENSE file or licence in the metadata
 * is reported the same way.
 *
 * --extract keeps the unpacked packages in <dir> (scripts/secret-scan.sh --dir scans them); otherwise
 * they are unpacked into a temporary directory and removed. Needs node 22+, tar, unzip and git.
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { checkVersions, toPep440 } from '../version.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Paths no package may hold, whatever its kind allows. */
const FORBIDDEN = [
    [/(^|\/)(tests?|__tests__|test-vectors|conformance)(\/|$)/, 'a test directory'],
    [/(^|\/)(test_[^/]*\.py|conftest\.py|[^/]*\.test\.[cm]?js|[^/]*Test\.php)$/, 'a test file'],
    [/\.(pem|key|p12|pfx|crt|der|env)$/i, 'a key, certificate or environment file'],
    [/(^|\/)(\.git|\.github|node_modules|vendor|\.venv|__pycache__)(\/|$)/, 'a VCS, CI or dependency directory'],
];
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{40,}-----END/;
const TEXT = /\.(js|py|php|json|md|txt|toml|cfg|in|typed)$|(^|\/)(METADATA|WHEEL|RECORD|PKG-INFO|LICENSE)$/;

const tracked = dir => execFileSync('git', ['ls-files', '-z', '--', dir], { cwd: ROOT, encoding: 'utf8' })
    .split('\0').filter(Boolean).map(file => path.posix.relative(dir, file));

/**
 * The packages pack.sh builds for `version`: where each lies in <out>, how to list it, which paths it may
 * hold, and which of them must equal the tracked source files.
 */
export function expectedPackages(version) {
    const pep = toPep440(version);
    const npm = (name, dir, extra) => ({
        name: `@vaultody-com/${name}`, registry: 'npm', file: `npm/vaultody-com-${name}-${version}.tgz`, prefix: 'package/',
        allowed: new RegExp(`^(package\\.json|README\\.md|LICENSE|src/[\\w/.-]+\\.js${extra})$`),
        required: ['package.json', 'README.md'],
        sources: { inPackage: 'src/', inRepository: `${dir}/src` },
    });
    const python = (name, module) => [
        {
            name, registry: 'PyPI', file: `pypi/${name}/${module}-${pep}-py3-none-any.whl`, prefix: '',
            allowed: new RegExp(`^(${module}/[\\w/]+\\.py|${module}/py\\.typed|${module}-${pep.replace(/\./g, '\\.')}\\.dist-info/(METADATA|WHEEL|RECORD|top_level\\.txt|licenses/LICENSE))$`),
            required: [`${module}/__init__.py`, `${module}-${pep}.dist-info/METADATA`, `${module}-${pep}.dist-info/RECORD`],
            sources: { inPackage: `${module}/`, inRepository: `python/${name}/${module}` },
        },
        {
            name, registry: 'PyPI', file: `pypi/${name}/${module}-${pep}.tar.gz`, prefix: `${module}-${pep}/`,
            allowed: new RegExp(`^(PKG-INFO|README\\.md|pyproject\\.toml|setup\\.cfg|MANIFEST\\.in|LICENSE|${module}/[\\w/]+\\.py|${module}/py\\.typed|${module}\\.egg-info/(PKG-INFO|SOURCES\\.txt|dependency_links\\.txt|requires\\.txt|top_level\\.txt))$`),
            required: ['PKG-INFO', 'README.md', 'pyproject.toml'],
            sources: { inPackage: `${module}/`, inRepository: `python/${name}/${module}` },
        },
    ];

    return [
        npm('verify', 'node/packages/verify', ''),
        // the vaultody command line (npx @vaultody-com/sdk keys ...)
        npm('sdk', 'node/packages/sdk', '|bin/vaultody\\.js'),
        ...python('vaultody-verify', 'vaultody_verify'),
        ...python('vaultody-sdk', 'vaultody_sdk'),
        {
            name: 'vaultody/sdk', registry: 'Packagist', file: `packagist/vaultody-sdk-${version}.zip`, prefix: '',
            allowed: /^(composer\.json|README\.md|LICENSE|src\/[\w/]+\.php)$/,
            required: ['composer.json', 'README.md', 'src/autoload.php'],
            sources: { inPackage: 'src/', inRepository: 'php/src' },
        },
    ];
}

/**
 * What of the test vectors must never be in a package: every secret (private keys, seeds, API secrets,
 * passphrases), and the test-only roots' public keys and fingerprints (a package that trusted one would
 * accept responses signed with a private key everyone has).
 */
export function testSecrets(root = ROOT) {
    const secrets = new Set();
    const walk = value => {
        if (Array.isArray(value)) {
            value.forEach(walk);
        } else if (value && typeof value === 'object') {
            const testRoot = typeof value.label === 'string' && value.label.startsWith('TEST-ONLY root');
            for (const [key, inner] of Object.entries(value)) {
                const keep = /private|secret|seed|passphrase|password/i.test(key) || (testRoot && /publicKey|rootId/.test(key));
                for (const text of keep ? [inner].flat() : []) {
                    if (typeof text === 'string') {
                        secrets.add(normalise(text));
                    }
                }
                walk(inner);
            }
        }
    };
    const dir = path.join(root, 'test-vectors');
    for (const file of readdirSync(dir).filter(name => name.endsWith('.json'))) {
        walk(JSON.parse(readFileSync(path.join(dir, file), 'utf8')));
    }

    return [...secrets].filter(secret => secret.length >= 16);
}

/** Text without PEM armour, whitespace or \n escapes, so a key is found however it is wrapped. */
const normalise = text => text.replace(/-----(BEGIN|END) [A-Z0-9 ]+-----/g, '').replace(/\\n|\s+/g, '');

function list(archive) {
    const entries = archive.endsWith('.zip') || archive.endsWith('.whl')
        ? execFileSync('unzip', ['-Z1', archive], { encoding: 'utf8' })
        : execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' });

    return entries.split('\n').filter(entry => entry !== '' && !entry.endsWith('/'));
}

function extract(archive, into) {
    mkdirSync(into, { recursive: true });
    if (archive.endsWith('.zip') || archive.endsWith('.whl')) {
        execFileSync('unzip', ['-q', '-o', archive, '-d', into]);
    } else {
        execFileSync('tar', ['-xzf', archive, '-C', into]);
    }
}

const metadataField = (text, field) => [...text.matchAll(new RegExp(`^${field}: (.*)$`, 'gm'))].map(match => match[1].trim());

/**
 * Checks one unpacked package. Returns problems (always wrong), todos (wrong only for a release) and a
 * summary row.
 */
function checkPackage(pkg, { archive, dir, version, secrets }) {
    const problems = [];
    const todos = [];
    const pep = toPep440(version);
    const entries = list(archive);
    const inside = [];
    for (const entry of entries) {
        if (!entry.startsWith(pkg.prefix)) {
            problems.push(`${entry}: outside ${pkg.prefix}`);
            continue;
        }
        inside.push(entry.slice(pkg.prefix.length));
    }
    const has = new Set(inside);

    for (const file of inside) {
        const forbidden = FORBIDDEN.find(([pattern]) => pattern.test(file));
        if (forbidden) {
            problems.push(`${file}: ${forbidden[1]}`);
        } else if (!pkg.allowed.test(file)) {
            problems.push(`${file}: not a file this package ships`);
        }
    }
    for (const file of pkg.required) {
        if (!has.has(file)) {
            problems.push(`no ${file}`);
        }
    }

    // The package's source files are exactly the ones git tracks in its source directory.
    const shipped = inside.filter(file => file.startsWith(pkg.sources.inPackage) && !file.endsWith('.typed')).map(file => file.slice(pkg.sources.inPackage.length)).sort();
    const sources = tracked(pkg.sources.inRepository).filter(file => !file.endsWith('.typed')).sort();
    for (const file of sources.filter(file => !shipped.includes(file))) {
        problems.push(`${pkg.sources.inRepository}/${file} is not in the package`);
    }
    for (const file of shipped.filter(file => !sources.includes(file))) {
        problems.push(`${pkg.sources.inPackage}${file} is not a tracked source file`);
    }

    const root = path.join(dir, pkg.prefix);
    const read = file => readFileSync(path.join(root, file), 'utf8');
    for (const file of inside.filter(name => TEXT.test(name))) {
        const text = read(file);
        if (PRIVATE_KEY_BLOCK.test(text.replace(/\\n/g, '\n'))) {
            problems.push(`${file}: holds a private key`);
        }
        const flat = normalise(text);
        if (secrets.some(secret => flat.includes(secret))) {
            problems.push(`${file}: holds a secret or a test-only root key of the test vectors`);
        }
    }

    // The version, the licence and the private markers, as each registry reads them.
    let licence = has.has('LICENSE');
    if (pkg.registry === 'npm') {
        const manifest = JSON.parse(read('package.json'));
        if (manifest.version !== version) {
            problems.push(`package.json version is ${manifest.version}, not ${version}`);
        }
        if (manifest.dependencies && '@vaultody-com/verify' in manifest.dependencies && manifest.dependencies['@vaultody-com/verify'] !== version) {
            problems.push(`depends on @vaultody-com/verify ${manifest.dependencies['@vaultody-com/verify']}, not ${version}`);
        }
        for (const target of [manifest.main, ...Object.values(manifest.exports || {}), ...Object.values(manifest.bin || {})].filter(Boolean)) {
            if (!has.has(path.posix.normalize(target))) {
                problems.push(`package.json names ${target}, which is not in the package`);
            }
        }
        if (manifest.private === true) {
            todos.push('"private": true');
        }
        if (!manifest.license || manifest.license === 'UNLICENSED') {
            todos.push(`license ${manifest.license || 'not set'}`);
        }
    } else if (pkg.registry === 'PyPI') {
        const metadataFile = pkg.file.endsWith('.whl') ? inside.find(file => file.endsWith('.dist-info/METADATA')) : 'PKG-INFO';
        const metadata = read(metadataFile);
        if (metadataField(metadata, 'Version')[0] !== pep) {
            problems.push(`${metadataFile}: Version ${metadataField(metadata, 'Version')[0]}, not ${pep}`);
        }
        const pins = metadataField(metadata, 'Requires-Dist').filter(requirement => requirement.startsWith('vaultody-verify'));
        if (pins.some(requirement => requirement !== `vaultody-verify==${pep}`)) {
            problems.push(`${metadataFile}: requires ${pins.join(', ')}, not vaultody-verify==${pep}`);
        }
        if (metadataField(metadata, 'Classifier').includes('Private :: Do Not Upload')) {
            todos.push('"Private :: Do Not Upload"');
        }
        if (metadataField(metadata, 'License-Expression').length === 0) {
            todos.push('no License-Expression');
        }
        licence = has.has('LICENSE') || inside.some(file => /\.dist-info\/licenses\/LICENSE$/.test(file));
    } else {
        const manifest = JSON.parse(read('composer.json'));
        if (manifest.name !== 'vaultody/sdk') {
            problems.push(`composer.json name is ${manifest.name}`);
        }
        if ('version' in manifest) {
            problems.push('composer.json has a version: Packagist takes it from the tag');
        }
        const sdkVersion = read('src/Version.php').match(/SDK_VERSION = '([^']*)'/)?.[1];
        if (sdkVersion !== version) {
            problems.push(`src/Version.php SDK_VERSION is ${sdkVersion}, not ${version}`);
        }
        if (!manifest.license || manifest.license === 'proprietary') {
            todos.push(`license ${manifest.license || 'not set'}`);
        }
    }
    if (!licence) {
        todos.push('no LICENSE');
    }

    return { problems, todos, row: { name: pkg.name, registry: pkg.registry, file: pkg.file, bytes: statSync(archive).size, files: inside.length } };
}

/**
 * Checks every package in `out`.
 *
 * @returns {{ problems: string[], todos: string[], rows: Object[] }}
 */
export function checkPackages(out, { extractTo, root = ROOT } = {}) {
    const versions = checkVersions(root);
    const problems = versions.problems.map(problem => `VERSION: ${problem}`);
    const todos = [];
    const rows = [];
    if (!versions.ok) {
        return { problems, todos, rows };
    }
    const { version } = versions;
    const packages = expectedPackages(version);

    const present = readdirSync(out, { recursive: true, withFileTypes: true })
        .filter(entry => entry.isFile())
        .map(entry => path.relative(out, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'));
    for (const file of present.filter(name => !packages.some(pkg => pkg.file === name))) {
        problems.push(`${file}: not a package of ${version}`);
    }

    const secrets = testSecrets(root);
    const unpacked = extractTo || mkdtempSync(path.join(tmpdir(), 'vaultody-packages-'));
    try {
        for (const pkg of packages) {
            if (!existsSync(path.join(out, pkg.file))) {
                problems.push(`${pkg.file}: missing`);
                continue;
            }
            const archive = path.join(out, pkg.file);
            const dir = path.join(unpacked, pkg.file);
            extract(archive, dir);
            const result = checkPackage(pkg, { archive, dir, version, secrets });
            problems.push(...result.problems.map(problem => `${pkg.file}: ${problem}`));
            todos.push(...result.todos.map(todo => `${pkg.file}: ${todo}`));
            rows.push(result.row);
        }
    } finally {
        if (!extractTo) {
            rmSync(unpacked, { recursive: true, force: true });
        }
    }

    return { problems, todos, rows };
}

function render(result, release) {
    const lines = [
        `### Packages${release ? '' : ' (dry run)'}`,
        '',
        '| package | registry | file | size | files |',
        '|---|---|---|---:|---:|',
        ...result.rows.map(row => `| ${row.name} | ${row.registry} | \`${row.file}\` | ${(row.bytes / 1024).toFixed(1)} KiB | ${row.files} |`),
    ];
    if (result.todos.length > 0) {
        lines.push('', release ? '**Not ready to publish:**' : '**TODO before the first release** (a release refuses these):', ...result.todos.map(todo => `- ${todo}`));
    }
    if (result.problems.length > 0) {
        lines.push('', '**Problems:**', ...result.problems.map(problem => `- ${problem}`));
    }

    return `${lines.join('\n')}\n`;
}

function main(argv) {
    let out;
    let release = false;
    let extractTo;
    for (let i = 0; i < argv.length; i += 1) {
        if (argv[i] === '--release') {
            release = true;
        } else if (argv[i] === '--extract') {
            extractTo = path.resolve(argv[i + 1]);
            i += 1;
        } else if (!out && !argv[i].startsWith('--')) {
            out = path.resolve(argv[i]);
        } else {
            throw new Error(`unknown argument ${argv[i]}`);
        }
    }
    if (!out) {
        throw new Error('usage: node scripts/release/check-packages.mjs <out> [--release] [--extract <dir>]');
    }
    if (extractTo) {
        rmSync(extractTo, { recursive: true, force: true });
    }

    const result = checkPackages(out, { extractTo });
    const markdown = render(result, release);
    process.stdout.write(markdown);
    if (process.env.GITHUB_STEP_SUMMARY) {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
    }
    if (!release && process.env.GITHUB_ACTIONS === 'true') {
        for (const todo of result.todos) {
            process.stdout.write(`::warning title=TODO before the first release::${todo}\n`);
        }
    }
    const failed = [...result.problems, ...(release ? result.todos : [])];
    process.stdout.write(failed.length > 0 ? `\npackages: FAILED, ${failed.length} problem(s)\n` : `\npackages: ok${result.todos.length > 0 ? `, ${result.todos.length} TODO(s) before the first release` : ''}\n`);

    return failed.length > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    try {
        process.exitCode = main(process.argv.slice(2));
    } catch (error) {
        process.stderr.write(`packages: ${error.message}\n`);
        process.exitCode = 1;
    }
}
