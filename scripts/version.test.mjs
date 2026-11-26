// The version source: VERSION and every package agree on the repository as it is, `set` writes every
// place, and a place that differs fails.
//   node --test scripts/

import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { PLACES, ROOT, checkVersions, parseVersion, setVersion, toPep440 } from './version.mjs';

/** A copy of VERSION and every file that states a version, in a temporary directory. */
function copyOfRepository() {
    const dir = mkdtempSync(path.join(tmpdir(), 'vaultody-version-'));
    for (const file of new Set(['VERSION', ...PLACES.map(place => place.file)])) {
        mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
        cpSync(path.join(ROOT, file), path.join(dir, file));
    }

    return dir;
}

describe('scripts/version.mjs', () => {
    it('reads X.Y.Z and X.Y.Z-rc.N, and nothing else', () => {
        assert.deepEqual(parseVersion('1.2.3'), { version: '1.2.3', major: 1, minor: 2, patch: 3, rc: null, stable: true });
        assert.deepEqual(parseVersion('0.9.0-rc.12'), { version: '0.9.0-rc.12', major: 0, minor: 9, patch: 0, rc: 12, stable: false });
        for (const bad of ['1.2', '1.2.3.4', 'v1.2.3', '01.2.3', '1.2.3-rc', '1.2.3-rc.0', '1.2.3-rc.01', '1.2.3-beta.1', '1.2.3rc1', '1.2.3-RC.1', ' 1.2.3', '', undefined]) {
            assert.equal(parseVersion(bad), null, String(bad));
        }
    });

    it('spells a release candidate the PEP 440 way for Python', () => {
        assert.equal(toPep440('0.9.0-rc.1'), '0.9.0rc1');
        assert.equal(toPep440('1.0.0'), '1.0.0');
        assert.throws(() => toPep440('1.0.0-beta.1'), /not a release version/);
    });

    it('passes on the repository as it is', () => {
        const result = checkVersions();
        assert.deepEqual(result.problems, []);
        assert.equal(result.places.length, 12);
    });

    it('writes every place, in each language\'s spelling, and nothing else', () => {
        const dir = copyOfRepository();
        try {
            const before = new Map(PLACES.map(place => [place.file, readFileSync(path.join(dir, place.file), 'utf8')]));
            const result = setVersion('0.9.0-rc.1', dir);
            assert.deepEqual(result.problems, []);
            assert.equal(readFileSync(path.join(dir, 'VERSION'), 'utf8'), '0.9.0-rc.1\n');
            assert.deepEqual(result.places.map(place => place.value),
                ['0.9.0-rc.1', '0.9.0-rc.1', '0.9.0-rc.1', '0.9.0-rc.1', '0.9.0-rc.1', '0.9.0-rc.1', '0.9.0rc1', '0.9.0rc1', '0.9.0rc1', '0.9.0rc1', '0.9.0rc1', '0.9.0-rc.1']);
            // Only the version changed: putting the old one back gives the same bytes.
            setVersion(checkVersions().version, dir);
            for (const [file, text] of before) {
                assert.equal(readFileSync(path.join(dir, file), 'utf8'), text, file);
            }
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it('fails on a place that differs, on a place it cannot find, and on a VERSION that is not a release version', () => {
        const dir = copyOfRepository();
        try {
            const sdk = path.join(dir, 'python/vaultody-sdk/pyproject.toml');
            writeFileSync(sdk, readFileSync(sdk, 'utf8').replace(/vaultody-verify==[^"]*/, 'vaultody-verify==0.0.9'));
            const php = path.join(dir, 'php/src/Version.php');
            writeFileSync(php, readFileSync(php, 'utf8').replace(/SDK_VERSION = /, 'SDK_VERSION_X = '));
            const version = checkVersions(dir).version;
            assert.deepEqual(checkVersions(dir).problems, [
                `python/vaultody-sdk/pyproject.toml: the vaultody-verify pin is 0.0.9; VERSION ${version} means ${toPep440(version)}`,
                'php/src/Version.php: no SDK_VERSION found',
            ]);
            assert.throws(() => setVersion('1.0', dir), /not a release version/);
            writeFileSync(path.join(dir, 'VERSION'), '1.0.0-beta.1\n');
            assert.equal(checkVersions(dir).problems[0], 'VERSION is "1.0.0-beta.1": a release version is X.Y.Z or X.Y.Z-rc.N');
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});
