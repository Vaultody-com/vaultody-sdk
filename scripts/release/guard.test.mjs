// The release guard: the roots as each language embeds them, the build defaults, the package checks, the
// stable-only checks, and the tag a release runs on (real git tags, SSH-signed with throwaway keys).
//   node --test scripts/

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
    PACKAGE_DIRS, ROOT, checkDefaults, checkPackages, checkRootFingerprint, checkRoots, checkRun, checkStable, checkStableDefaults, checkTag, guard,
    readDefaults, readEmbeddedRoots, readSlot, readTestMaterial,
} from './guard.mjs';

const VECTORS = JSON.parse(readFileSync(path.join(ROOT, 'test-vectors/v1.json'), 'utf8'));
const pemOf = base64 => `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;
const TEST_ROOT = { pem: pemOf(VECTORS.keys.roots.current.publicKeySpkiDerBase64), fingerprint: VECTORS.keys.roots.current.rootId };

/** A fresh P-256 root, as a release would embed it: its SPKI PEM and the SHA-256 of the DER. */
function freshRoot() {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const der = publicKey.export({ type: 'spki', format: 'der' });

    return { pem: publicKey.export({ type: 'spki', format: 'pem' }), fingerprint: createHash('sha256').update(der).digest('hex') };
}

const EMPTY = { pem: '', fingerprint: '' };
const same = (current, next = EMPTY) => ({ node: { current, next }, python: { current, next }, php: { current, next } });
const testMaterial = readTestMaterial();

/** A temporary directory with the given repository files copied in. */
function copyOf(files) {
    const dir = mkdtempSync(path.join(tmpdir(), 'vaultody-guard-'));
    for (const file of files) {
        mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
        cpSync(path.join(ROOT, file), path.join(dir, file), { recursive: true });
    }

    return dir;
}

describe('scripts/release/guard.mjs: roots', () => {
    it('reads the repository\'s roots in all three languages: every slot empty today', () => {
        const roots = readEmbeddedRoots();
        assert.deepEqual(roots, same(EMPTY));
        assert.deepEqual(checkRoots(roots, { testMaterial }), { problems: [], slots: { current: null, next: null } });
    });

    it('reads a root written the way a release fills it in, in each language\'s own file', () => {
        const dir = copyOf(['node/packages/verify/src/roots.js', 'python/vaultody-verify/vaultody_verify/roots.py', 'php/src/Verify/EmbeddedRoots.php']);
        try {
            const root = freshRoot();
            const node = path.join(dir, 'node/packages/verify/src/roots.js');
            writeFileSync(node, readFileSync(node, 'utf8').replace(/current: Object\.freeze\(\{\s*pem: '',\s*fingerprint: '',/,
                `current: Object.freeze({\n        pem: ${JSON.stringify(root.pem)},\n        fingerprint: '${root.fingerprint}',`));
            const python = path.join(dir, 'python/vaultody-verify/vaultody_verify/roots.py');
            writeFileSync(python, readFileSync(python, 'utf8')
                .replace('CURRENT_ROOT_PEM = ""', `CURRENT_ROOT_PEM = """\\\n${root.pem}"""`)
                .replace('CURRENT_ROOT_FINGERPRINT = ""', `CURRENT_ROOT_FINGERPRINT = "${root.fingerprint}"`));
            const php = path.join(dir, 'php/src/Verify/EmbeddedRoots.php');
            writeFileSync(php, readFileSync(php, 'utf8').replace("public const CURRENT = ['pem' => '', 'fingerprint' => ''];",
                `public const CURRENT = [\n        'pem' => '${root.pem}',\n        'fingerprint' => '${root.fingerprint}',\n    ];`));

            const roots = readEmbeddedRoots(dir);
            for (const language of ['node', 'python', 'php']) {
                assert.equal(roots[language].current.pem.trim(), root.pem.trim(), language);
                assert.equal(roots[language].current.fingerprint, root.fingerprint, language);
            }
            const result = checkRoots(roots, { testMaterial });
            assert.deepEqual(result.problems, []);
            assert.equal(result.slots.current.fingerprint, root.fingerprint);
            assert.equal(result.slots.next, null);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('refuses a slot that is half set, not P-256, not a public key, or whose fingerprint does not match', () => {
        const root = freshRoot();
        const ed25519 = generateKeyPairSync('ed25519').publicKey;
        assert.equal(readSlot(EMPTY), null);
        assert.deepEqual(readSlot({ pem: root.pem, fingerprint: '' }), { error: 'the PEM and its fingerprint must be set together' });
        assert.deepEqual(readSlot({ pem: root.pem, fingerprint: root.fingerprint.toUpperCase() }), { error: 'the fingerprint must be 64 lowercase hex characters' });
        assert.match(readSlot({ pem: root.pem, fingerprint: freshRoot().fingerprint }).error, /does not match the key/);
        assert.match(readSlot({ pem: ed25519.export({ type: 'spki', format: 'pem' }), fingerprint: root.fingerprint }).error, /P-256/);
        const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        assert.match(readSlot({ pem: privateKey.export({ type: 'pkcs8', format: 'pem' }), fingerprint: root.fingerprint }).error, /exactly one "PUBLIC KEY" block/);
        assert.deepEqual(readSlot(root), { der: readSlot(root).der, fingerprint: root.fingerprint });
    });

    it('refuses a test-only root in any slot, a root listed as not for production, and languages that differ', () => {
        assert.deepEqual(checkRoots(same(TEST_ROOT), { testMaterial }).problems,
            [`the current root ${TEST_ROOT.fingerprint} is a test-only root (it is in the test vectors or tests)`]);
        assert.deepEqual(checkRoots(same(freshRoot(), TEST_ROOT), { testMaterial }).problems,
            [`the next root ${TEST_ROOT.fingerprint} is a test-only root (it is in the test vectors or tests)`]);
        const qa = freshRoot();
        assert.deepEqual(checkRoots(same(qa), { testMaterial, nonProduction: [qa.fingerprint] }).problems,
            [`the current root ${qa.fingerprint} is listed as not a production root (NON_PRODUCTION_ROOTS)`]);
        const root = freshRoot();
        const roots = same(root);
        roots.php = { current: EMPTY, next: EMPTY };
        assert.deepEqual(checkRoots(roots, { testMaterial }).problems,
            [`the current root differs between the languages: node ${root.fingerprint}, python ${root.fingerprint}, php empty`]);
    });
});

describe('scripts/release/guard.mjs: build defaults', () => {
    const FILES = ['node/packages/sdk/src/defaults.js', 'python/vaultody-sdk/vaultody_sdk/_defaults.py', 'php/src/Transport/Transport.php'];
    const RC = { DEFAULT_RESPONSE_SIGNATURE: 'when-present', ADDRESS_PATHS_PUBLIC: false };
    const STABLE = { DEFAULT_RESPONSE_SIGNATURE: 'required', ADDRESS_PATHS_PUBLIC: true };
    const all = values => ({ node: { ...values }, python: { ...values }, php: { ...values } });

    /** A copy of the three files with the defaults written the way a stable release commit writes them. */
    function stableCopy(languages = ['node', 'python', 'php']) {
        const dir = copyOf(FILES);
        const edit = (file, from, to) => {
            const full = path.join(dir, file);
            const text = readFileSync(full, 'utf8');
            assert.ok(text.includes(from), `${file}: ${from}`);
            writeFileSync(full, text.replace(from, to));
        };
        if (languages.includes('node')) {
            edit(FILES[0], "const DEFAULT_RESPONSE_SIGNATURE = 'when-present';", "const DEFAULT_RESPONSE_SIGNATURE = 'required';");
            edit(FILES[0], 'const ADDRESS_PATHS_PUBLIC = false;', 'const ADDRESS_PATHS_PUBLIC = true;');
        }
        if (languages.includes('python')) {
            edit(FILES[1], 'DEFAULT_RESPONSE_SIGNATURE = "when-present"', 'DEFAULT_RESPONSE_SIGNATURE = "required"');
            edit(FILES[1], 'ADDRESS_PATHS_PUBLIC = False', 'ADDRESS_PATHS_PUBLIC = True');
        }
        if (languages.includes('php')) {
            edit(FILES[2], "public const DEFAULT_RESPONSE_SIGNATURE = 'when-present';", "public const DEFAULT_RESPONSE_SIGNATURE = 'required';");
            edit(FILES[2], 'public const ADDRESS_PATHS_PUBLIC = false;', 'public const ADDRESS_PATHS_PUBLIC = true;');
        }

        return dir;
    }

    it('reads the repository\'s defaults in all three languages: a release candidate\'s today', () => {
        const defaults = readDefaults();
        assert.deepEqual(defaults, all(RC));
        assert.deepEqual(checkDefaults(defaults), { problems: [], values: RC });
        assert.deepEqual(guard(ROOT, { report: true }).defaults, RC);
    });

    it('a stable release is refused while responses may be unsigned by default or address paths are not public', () => {
        assert.deepEqual(checkStableDefaults(RC), [
            'DEFAULT_RESPONSE_SIGNATURE is "when-present": a stable release refuses unsigned responses by default, so it must be "required" in every language',
            'ADDRESS_PATHS_PUBLIC is false: a stable release ships after the address derivation paths are public, and requires them on generateDepositAddress, so it must be true in every language',
        ]);
        assert.deepEqual(checkStableDefaults(STABLE), []);
        assert.ok(guard(ROOT, { report: true }).stable.some(problem => problem.startsWith('DEFAULT_RESPONSE_SIGNATURE is "when-present"')));
    });

    it('reads the defaults as a stable release commit writes them, in each language\'s own file', () => {
        const dir = stableCopy();
        try {
            const defaults = readDefaults(dir);
            assert.deepEqual(defaults, all(STABLE));
            assert.deepEqual(checkDefaults(defaults), { problems: [], values: STABLE });
            assert.deepEqual(checkStableDefaults(checkDefaults(defaults).values), []);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('refuses languages that differ, and a value that is not allowed; a stable release then names the disagreement', () => {
        const dir = stableCopy(['node', 'python']);
        try {
            const result = checkDefaults(readDefaults(dir));
            assert.deepEqual(result.problems, [
                'DEFAULT_RESPONSE_SIGNATURE differs between the languages: node "required", python "required", php "when-present"',
                'ADDRESS_PATHS_PUBLIC differs between the languages: node true, python true, php false',
            ]);
            assert.deepEqual(checkStableDefaults(result.values), [
                'DEFAULT_RESPONSE_SIGNATURE is not agreed between the languages: a stable release refuses unsigned responses by default, so it must be "required" in every language',
                'ADDRESS_PATHS_PUBLIC is not agreed between the languages: a stable release ships after the address derivation paths are public, and requires them on generateDepositAddress, so it must be true in every language',
            ]);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
        const odd = all(RC);
        odd.python.DEFAULT_RESPONSE_SIGNATURE = 'always';
        odd.php.ADDRESS_PATHS_PUBLIC = 'yes';
        assert.deepEqual(checkDefaults(odd).problems, [
            'python DEFAULT_RESPONSE_SIGNATURE is "always", not one of "when-present", "required"',
            'DEFAULT_RESPONSE_SIGNATURE differs between the languages: node "when-present", python "always", php "when-present"',
            'php ADDRESS_PATHS_PUBLIC is "yes", not one of false, true',
            'ADDRESS_PATHS_PUBLIC differs between the languages: node false, python false, php "yes"',
        ]);
    });

    it('refuses a PHP constant it can\'t read exactly once', () => {
        const dir = copyOf(FILES);
        try {
            const php = path.join(dir, FILES[2]);
            writeFileSync(php, readFileSync(php, 'utf8').replace("public const DEFAULT_RESPONSE_SIGNATURE = 'when-present';", 'public const DEFAULT_RESPONSE_SIGNATURE = self::MODE;'));
            assert.throws(() => readDefaults(dir), /DEFAULT_RESPONSE_SIGNATURE must be declared exactly once/);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('scripts/release/guard.mjs: packages and stable releases', () => {
    const MANIFESTS = ['node/packages/verify/package.json', 'node/packages/sdk/package.json', 'python/vaultody-verify/pyproject.toml',
        'python/vaultody-sdk/pyproject.toml', 'php/composer.json', 'CHANGELOG.md', 'contract/pending'];

    it('refuses to publish what the repository has today: private packages, no release notes; the licence is in place', () => {
        const problems = checkPackages(ROOT, { version: '0.9.0-rc.1', repository: 'Vaultody-com/vaultody-sdk' });
        for (const expected of ['node/packages/sdk/package.json: still "private": true', 'python/vaultody-sdk/pyproject.toml: still "Private :: Do Not Upload"',
            'CHANGELOG.md has no "## 0.9.0-rc.1" section (the release notes)']) {
            assert.ok(problems.includes(expected), expected);
        }
        assert.deepEqual(problems.filter(problem => /licen[cs]e/i.test(problem)), []);
    });

    it('refuses a repository without its LICENSE, or a package whose copy is missing', () => {
        const dir = copyOf(MANIFESTS);
        try {
            assert.equal(checkPackages(dir, { version: '0.9.0-rc.1' })[0], 'no LICENSE: the repository and every package ship the Apache-2.0 licence');
            writeFileSync(path.join(dir, 'LICENSE'), 'the licence\n');
            assert.deepEqual(checkPackages(dir, { version: '0.9.0-rc.1' }).filter(problem => problem.includes('LICENSE')),
                PACKAGE_DIRS.map(pkg => `${pkg}/LICENSE is missing or differs from LICENSE (each package ships its own copy)`));
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('passes packages that are ready, and holds the npm repository to the one publishing', () => {
        const dir = copyOf(MANIFESTS);
        try {
            writeFileSync(path.join(dir, 'LICENSE'), 'the licence\n');
            for (const pkg of PACKAGE_DIRS) {
                writeFileSync(path.join(dir, pkg, 'LICENSE'), 'the licence\n');
            }
            for (const pkg of ['node/packages/verify', 'node/packages/sdk']) {
                const file = path.join(dir, pkg, 'package.json');
                const manifest = JSON.parse(readFileSync(file, 'utf8'));
                delete manifest.private;
                writeFileSync(file, JSON.stringify(manifest));
            }
            for (const pkg of ['python/vaultody-verify', 'python/vaultody-sdk']) {
                const file = path.join(dir, pkg, 'pyproject.toml');
                writeFileSync(file, readFileSync(file, 'utf8').replace(/\n\s*"Private :: Do Not Upload",/, ''));
            }
            writeFileSync(path.join(dir, 'CHANGELOG.md'), '# Changelog\n\n## 0.9.0-rc.1\n\n- The first release candidate.\n');

            assert.deepEqual(checkPackages(dir, { version: '0.9.0-rc.1', repository: 'Vaultody-com/vaultody-sdk' }), []);
            assert.deepEqual(checkPackages(dir, { version: '0.9.0-rc.1', repository: 'Vaultody-com/another-repository' }), [
                'node/packages/verify/package.json: repository is git+https://github.com/Vaultody-com/vaultody-sdk.git, not Vaultody-com/another-repository (npm trusted publishing refuses that)',
                'node/packages/sdk/package.json: repository is git+https://github.com/Vaultody-com/vaultody-sdk.git, not Vaultody-com/another-repository (npm trusted publishing refuses that)',
            ]);
            for (const [file, licence] of [['node/packages/sdk/package.json', 'UNLICENSED'], ['php/composer.json', 'proprietary']]) {
                const manifest = path.join(dir, file);
                const before = readFileSync(manifest, 'utf8');
                writeFileSync(manifest, JSON.stringify({ ...JSON.parse(before), license: licence }));
                assert.deepEqual(checkPackages(dir, { version: '0.9.0-rc.1', repository: 'Vaultody-com/vaultody-sdk' }), [`${file}: license is ${licence}`]);
                writeFileSync(manifest, before);
            }
            assert.deepEqual(checkPackages(dir, { version: '0.9.0-rc.2', repository: 'Vaultody-com/vaultody-sdk' }),
                ['CHANGELOG.md has no "## 0.9.0-rc.2" section (the release notes)']);
            writeFileSync(path.join(dir, 'php/LICENSE'), 'another licence\n');
            assert.deepEqual(checkPackages(dir, { version: '0.9.0-rc.1', repository: 'Vaultody-com/vaultody-sdk' }),
                ['php/LICENSE is missing or differs from LICENSE (each package ships its own copy)']);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('refuses a stable release without the production root, named by the run, or with an operation still pending', () => {
        const root = freshRoot();
        const slots = { current: readSlot(root), next: null };
        assert.deepEqual(checkStable(ROOT, { slots: { current: null, next: null }, rootFingerprint: root.fingerprint }), [
            'no current root embedded: a stable release needs the production root key and its fingerprint in every language',
            'contract/pending/ still has list-api-key-signing-keys.yaml: a stable release covers only operations published on production',
        ]);
        const dir = copyOf(['contract/openapi.json']);
        try {
            assert.deepEqual(checkStable(dir, { slots, rootFingerprint: root.fingerprint }), []);
            assert.deepEqual(checkStable(dir, { slots }), ['no --root-fingerprint: a stable release names the production root fingerprint published to clients']);
            assert.deepEqual(checkStable(dir, { slots, report: true }), []);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
        assert.deepEqual(checkRootFingerprint({ slots, rootFingerprint: root.fingerprint }), []);
        assert.deepEqual(checkRootFingerprint({ slots, rootFingerprint: TEST_ROOT.fingerprint }),
            [`--root-fingerprint ${TEST_ROOT.fingerprint} is not the embedded current root ${root.fingerprint}`]);
        assert.deepEqual(checkRootFingerprint({ slots: { current: null, next: null }, rootFingerprint: root.fingerprint }),
            [`--root-fingerprint ${root.fingerprint} given, but no current root is embedded`]);
    });
});

describe('scripts/release/guard.mjs: the run and its tag', () => {
    // git with no user or system configuration, so a developer's settings do not change the result
    const env = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 'Release', GIT_AUTHOR_EMAIL: 'release@example.com',
        GIT_COMMITTER_NAME: 'Release', GIT_COMMITTER_EMAIL: 'release@example.com' };
    const run = (cwd, ...args) => execFileSync('git', args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

    /** A repository whose main allows one SSH key to sign release tags, and a second key it does not allow. */
    function repository() {
        const dir = mkdtempSync(path.join(tmpdir(), 'vaultody-tags-'));
        const repo = path.join(dir, 'repo');
        mkdirSync(repo);
        for (const name of ['allowed', 'other']) {
            execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', path.join(dir, name)]);
        }
        run(repo, 'init', '-q', '-b', 'main');
        writeFileSync(path.join(repo, 'VERSION'), '0.9.0-rc.1\n');
        run(repo, 'add', 'VERSION');
        run(repo, 'commit', '-q', '-m', 'first');
        const first = run(repo, 'rev-parse', 'HEAD');
        mkdirSync(path.join(repo, '.github'));
        const key = readFileSync(path.join(dir, 'allowed.pub'), 'utf8').trim().split(' ').slice(0, 2).join(' ');
        writeFileSync(path.join(repo, '.github/release-signers'), `# release managers\nrelease@example.com namespaces="git" ${key}\n`);
        run(repo, 'add', '.github/release-signers');
        run(repo, 'commit', '-q', '-m', 'signers');
        const head = run(repo, 'rev-parse', 'HEAD');
        const sign = (key, ...args) => run(repo, '-c', 'gpg.format=ssh', '-c', `user.signingkey=${path.join(dir, key)}`, 'tag', '-s', '-m', 'release', ...args);

        return { dir, repo, first, head, sign };
    }

    it('accepts an annotated tag on main, signed by a release signer, on the commit of the run', () => {
        const { dir, repo, head, sign } = repository();
        try {
            sign('allowed', 'v0.9.0-rc.1');
            assert.deepEqual(checkTag(repo, { version: '0.9.0-rc.1', sha: head, mainRef: 'main' }), []);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('refuses a missing, lightweight, unsigned or foreign-signed tag, another commit, and a commit not on main', () => {
        const { dir, repo, first, head, sign } = repository();
        try {
            const check = version => checkTag(repo, { version, sha: head, mainRef: 'main' });
            assert.deepEqual(check('0.9.0-rc.1'), ['there is no tag v0.9.0-rc.1']);
            run(repo, 'tag', 'v0.9.0-rc.2');
            assert.deepEqual(check('0.9.0-rc.2'), ['v0.9.0-rc.2 is a lightweight tag: a release tag is annotated and signed (git tag -s)']);
            run(repo, 'tag', '-a', '-m', 'release', 'v0.9.0-rc.3');
            assert.deepEqual(check('0.9.0-rc.3'), ['v0.9.0-rc.3 has no SSH signature (git tag -s with gpg.format=ssh)']);
            sign('other', 'v0.9.0-rc.4');
            assert.equal(check('0.9.0-rc.4').length, 1);
            assert.match(check('0.9.0-rc.4')[0], /^v0\.9\.0-rc\.4: the signature is not from a release signer on main/);
            sign('allowed', 'v0.9.0-rc.5', first);
            assert.deepEqual(check('0.9.0-rc.5'), [`v0.9.0-rc.5 points at ${first}, but the run is on ${head}`]);
            run(repo, 'checkout', '-q', '-b', 'side');
            run(repo, 'commit', '-q', '--allow-empty', '-m', 'not on main');
            const side = run(repo, 'rev-parse', 'HEAD');
            sign('allowed', 'v0.9.0-rc.6');
            assert.deepEqual(checkTag(repo, { version: '0.9.0-rc.6', sha: side, mainRef: 'main' }), [`v0.9.0-rc.6 (${side}) is not on main`]);
            // A main without .github/release-signers: nobody may release.
            assert.deepEqual(checkTag(repo, { version: '0.9.0-rc.5', sha: first, mainRef: first }),
                [`no release signer in .github/release-signers on ${first}: nobody may release yet`]);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('refuses a run that asks for another version, is not on the tag, or is in a private repository', () => {
        const problems = checkRun(ROOT, { inputVersion: '0.9.0-rc.2', version: '0.9.0-rc.1', ref: 'refs/heads/main', sha: 'x', visibility: 'private' });
        assert.deepEqual(problems, [
            'the run asks for "0.9.0-rc.2", but VERSION is 0.9.0-rc.1',
            'the repository is private: npm provenance and GitHub attestations need a public repository. Nothing is published without provenance; make the repository public first',
            'the run is on refs/heads/main: a release runs on its signed tag refs/tags/v0.9.0-rc.1 ("Use workflow from: Tags")',
        ]);
    });
});
