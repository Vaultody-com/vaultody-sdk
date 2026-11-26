'use strict';

// The `vaultody keys` command line (bin/vaultody.js, shipped with @vaultody/sdk), run as a separate process the
// way a customer runs it: generate →
// fingerprint → prove, the files it writes, the challenge format it accepts, its exit codes, and that it
// never prints key material. When OpenSSL 3 or later is on PATH, the openssl commands the dashboard shows
// are checked against it.

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, describe, it } = require('node:test');

const keys = require('@vaultody/verify/keys');

const CHALLENGE_VECTORS = require('../../../../test-vectors/keypair-challenge-v1.json');

const BIN = path.join(__dirname, '..', 'bin', 'vaultody.js');
const API_KEY_ID = '6630f1c2a9e4b5d7c8e9f0d4';
const CHALLENGE = CHALLENGE_VECTORS.challengeFormat.find(formatCase => formatCase.valid).challenge;
const PROOF_TAG = 'vaultody-keypair-challenge-v1';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-cli-'));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
let counter = 0;
const tmpDir = () => {
    const dir = path.join(tmp, String(counter += 1));
    fs.mkdirSync(dir);

    return dir;
};

const modeOf = file => fs.statSync(file).mode & 0o777;

// Every private key body any test wrote or read, so each run can check none of it was printed
const privateBodies = new Set();
const remember = privatePem => {
    privateBodies.add(privatePem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '').slice(0, 40));
};
for (const vectorKey of Object.values(CHALLENGE_VECTORS.keys)) {
    remember(vectorKey.privateKeyPkcs8Pem);
}

/** Runs the CLI in a clean environment: no credentials leak in from the machine running the tests. */
function cli(args, { env = {} } = {}) {
    const result = spawnSync(process.execPath, [BIN, ...args], {
        env: { PATH: process.env.PATH, ...env },
        encoding: 'utf8',
    });
    const output = result.stdout + result.stderr;
    assert.doesNotMatch(output, /PRIVATE KEY/, 'printed a PEM private key');
    for (const body of privateBodies) {
        assert.ok(!output.includes(body), 'printed private key material');
    }

    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** The proof string, built here from the format, independently of src/keys.js */
const proofString = (apiKeyId, fingerprint, challenge) => Buffer.from([PROOF_TAG, apiKeyId, fingerprint, challenge].join('\n'), 'utf8');

function generate(dir, algorithm, extra = []) {
    const out = path.join(dir, 'private.pem');
    const publicOut = path.join(dir, 'public.pem');
    const result = cli(['keys', 'generate', '--algorithm', algorithm, '--out', out, '--public-out', publicOut, ...extra]);
    if (result.code === 0) {
        remember(fs.readFileSync(out, 'utf8'));
    }

    return { ...result, out, publicOut };
}

describe('vaultody keys: generate → fingerprint → prove', () => {
    for (const algorithm of ['ed25519', 'p-256']) {
        it(algorithm, () => {
            const dir = tmpDir();
            const generated = generate(dir, algorithm);
            assert.equal(generated.code, 0, generated.stderr);
            assert.match(generated.stdout, /^SHA256:[A-Za-z0-9+/]{43}\n$/);
            const fingerprint = generated.stdout.trim();
            assert.match(generated.stderr, /private\.pem/);
            assert.match(generated.stderr, /public\.pem/);

            assert.equal(modeOf(generated.out), 0o600);
            assert.equal(modeOf(generated.publicOut), 0o644);
            assert.match(fs.readFileSync(generated.out, 'utf8'), /^-----BEGIN PRIVATE KEY-----\n[\s\S]+\n-----END PRIVATE KEY-----\n$/);
            assert.match(fs.readFileSync(generated.publicOut, 'utf8'), /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n$/);

            // The fingerprint, from either half, is the SHA-256 of the public key's SPKI DER
            const spkiDer = crypto.createPublicKey(fs.readFileSync(generated.publicOut, 'utf8')).export({ format: 'der', type: 'spki' });
            assert.equal(fingerprint, `SHA256:${crypto.createHash('sha256').update(spkiDer).digest('base64').replace(/=+$/, '')}`);
            for (const keyFile of [generated.publicOut, generated.out]) {
                const printed = cli(['keys', 'fingerprint', '--key', keyFile]);
                assert.deepEqual(printed, { code: 0, stdout: `${fingerprint}\n`, stderr: '' });
            }

            // prove prints the base64 signature and nothing else
            const proved = cli(['keys', 'prove', '--key', generated.out, '--api-key-id', API_KEY_ID, '--challenge', CHALLENGE]);
            assert.equal(proved.code, 0, proved.stderr);
            assert.equal(proved.stderr, '');
            assert.match(proved.stdout, /^[A-Za-z0-9+/]+={0,2}\n$/);
            const signature = proved.stdout.slice(0, -1);
            const signatureBytes = Buffer.from(signature, 'base64');
            assert.equal(signatureBytes.toString('base64'), signature, 'canonical base64');

            const publicKey = crypto.createPublicKey(fs.readFileSync(generated.publicOut, 'utf8'));
            const message = proofString(API_KEY_ID, fingerprint, CHALLENGE);
            if (algorithm === 'ed25519') {
                assert.equal(signatureBytes.length, 64);
                assert.equal(crypto.verify(null, message, publicKey, signatureBytes), true);
            } else {
                assert.equal(signatureBytes[0], 0x30, 'DER, not P1363');
                assert.equal(crypto.verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, signatureBytes), true);
            }
            assert.equal(keys.verifyChallengeProof(keys.readSigningKeyFile(generated.publicOut), { apiKeyId: API_KEY_ID, challenge: CHALLENGE, signature }), true);
        });
    }
});

describe('vaultody keys generate: files', () => {
    it('never overwrites without --force; --force replaces both with fresh modes', () => {
        const dir = tmpDir();
        const first = generate(dir, 'ed25519');
        const before = fs.readFileSync(first.out, 'utf8');

        const again = generate(dir, 'ed25519');
        assert.equal(again.code, 2);
        assert.equal(again.stdout, '');
        assert.match(again.stderr, /already exists.*--force/);
        assert.equal(fs.readFileSync(first.out, 'utf8'), before);

        fs.chmodSync(first.out, 0o644);
        const forced = generate(dir, 'p-256', ['--force']);
        assert.equal(forced.code, 0, forced.stderr);
        assert.notEqual(forced.stdout, first.stdout);
        assert.notEqual(fs.readFileSync(first.out, 'utf8'), before);
        assert.equal(modeOf(first.out), 0o600);
        assert.equal(modeOf(first.publicOut), 0o644);
        assert.equal(cli(['keys', 'fingerprint', '--key', first.out]).stdout, forced.stdout);
    });

    it('writes nothing when the public key file already exists', () => {
        const dir = tmpDir();
        fs.writeFileSync(path.join(dir, 'public.pem'), 'existing');
        const refused = generate(dir, 'ed25519');
        assert.equal(refused.code, 2);
        assert.deepEqual(fs.readdirSync(dir), ['public.pem']);
    });

    it('does not write through a symlink in place of the private key', () => {
        const dir = tmpDir();
        const target = path.join(dir, 'elsewhere');
        fs.symlinkSync(target, path.join(dir, 'private.pem'));
        assert.equal(generate(dir, 'ed25519').code, 2);
        assert.equal(fs.existsSync(target), false);
    });

    it('reports a directory that does not exist as a usage error', () => {
        const dir = path.join(tmpDir(), 'missing');
        assert.equal(generate(dir, 'ed25519').code, 2);
    });
});

describe('vaultody keys prove: the challenge format is strict', () => {
    const dir = tmpDir();
    const keyFile = path.join(dir, 'private.pem');
    fs.writeFileSync(keyFile, CHALLENGE_VECTORS.keys.ed25519.privateKeyPkcs8Pem, { mode: 0o600 });

    for (const formatCase of CHALLENGE_VECTORS.challengeFormat) {
        it(`${JSON.stringify(formatCase.challenge)} → ${formatCase.valid ? 'signed' : 'exit 2'}`, () => {
            const result = cli(['keys', 'prove', '--key', keyFile, '--api-key-id', API_KEY_ID, '--challenge', formatCase.challenge]);
            if (formatCase.valid) {
                assert.equal(result.code, 0, result.stderr);
            } else {
                assert.equal(result.code, 2);
                assert.equal(result.stdout, '');
                assert.match(result.stderr, /--challenge must be "vk-chal-"/);
            }
        });
    }

    it('signs the vector\'s proof, byte for byte (Ed25519 is deterministic)', () => {
        const vector = CHALLENGE_VECTORS.cases.find(candidate => candidate.name === 'valid_ed25519');
        const result = cli(['keys', 'prove', '--key', keyFile, '--api-key-id', vector.signed.apiKeyId, '--challenge', vector.signed.challenge]);
        assert.deepEqual(result, { code: 0, stdout: `${vector.signed.signature}\n`, stderr: '' });
    });
});

describe('vaultody: exit codes and messages', () => {
    const dir = tmpDir();
    const privateFile = path.join(dir, 'private.pem');
    const publicFile = path.join(dir, 'public.pem');
    const rsaFile = path.join(dir, 'rsa.pem');
    const ed25519PublicFile = path.join(dir, 'ed25519-public.pem');
    fs.writeFileSync(ed25519PublicFile, CHALLENGE_VECTORS.keys.ed25519.publicKeySpkiPem);
    fs.writeFileSync(privateFile, CHALLENGE_VECTORS.keys.p256.privateKeyPkcs8Pem, { mode: 0o600 });
    fs.writeFileSync(publicFile, CHALLENGE_VECTORS.keys.p256.publicKeySpkiPem);
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({ format: 'pem', type: 'pkcs8' });
    remember(rsa);
    fs.writeFileSync(rsaFile, rsa, { mode: 0o600 });
    const proveWith = (...extra) => ['keys', 'prove', '--key', privateFile, '--api-key-id', API_KEY_ID, '--challenge', CHALLENGE, ...extra];

    const cases = [
        { args: [], code: 2, stderr: /Usage: vaultody keys <command>/ },
        { args: ['--help'], code: 0, stdout: /Usage: vaultody keys <command>/ },
        { args: ['keys', '--help'], code: 0, stdout: /Exit codes: 0 ok, 1 refused or not registered, 2 usage error, 3 network or unexpected error/ },
        { args: ['--version'], code: 0, stdout: /^\d+\.\d+\.\d+\n$/ },
        { args: ['keys'], code: 2, stderr: /expected "keys <command>"/ },
        { args: ['key', 'generate'], code: 2, stderr: /expected "keys <command>"/ },
        { args: ['keys', 'sign'], code: 2, stderr: /unknown command/ },
        { args: ['keys', 'constructor'], code: 2, stderr: /unknown command/ },
        { args: ['keys', 'generate', '--help'], code: 0, stdout: /--public-out/ },
        { args: ['keys', 'verify', '-h'], code: 0, stdout: /environment: VAULTODY_API_KEY, VAULTODY_API_SECRET, VAULTODY_PASSPHRASE\./ },
        { args: ['keys', 'verify', '--help'], code: 0, stdout: /--api-version {9}the x-api-version to send, YYYY-MM-DD \(default 2026-03-20/ },
        { args: ['keys', 'generate', '--out', 'a.pem', '--public-out', 'b.pem'], code: 2, stderr: /--algorithm is required/ },
        { args: ['keys', 'generate', '--algorithm', 'rsa', '--out', 'a.pem', '--public-out', 'b.pem'], code: 2, stderr: /--algorithm must be "ed25519" or "p-256"/ },
        { args: ['keys', 'generate', '--algorithm', 'P-256', '--out', 'a.pem', '--public-out', 'b.pem'], code: 2, stderr: /--algorithm must be/ },
        { args: ['keys', 'generate', '--algorithm', 'ed25519', '--out', path.join(dir, 'same.pem'), '--public-out', path.join(dir, 'same.pem')], code: 2, stderr: /two different files/ },
        { args: ['keys', 'fingerprint'], code: 2, stderr: /--key is required/ },
        { args: ['keys', 'fingerprint', '--key'], code: 2, stderr: /--key needs a value/ },
        { args: ['keys', 'fingerprint', '--key', ''], code: 2, stderr: /--key needs a value/ },
        { args: ['keys', 'fingerprint', '--key', publicFile, '--key', privateFile], code: 2, stderr: /--key was given more than once/ },
        { args: ['keys', 'fingerprint', '--key', path.join(dir, 'missing.pem')], code: 2, stderr: /cannot read the key file/ },
        { args: ['keys', 'fingerprint', '--key', dir], code: 2, stderr: /not a file/ },
        { args: ['keys', 'fingerprint', '--key', rsaFile], code: 2, stderr: /This is an RSA key\. Only Ed25519 and ECDSA P-256 keys are supported\./ },
        { args: ['keys', 'fingerprint', '--key', publicFile, '--force'], code: 2, stderr: /unknown option --force/ },
        { args: ['keys', 'fingerprint', '--key', publicFile, 'TEST-ONLY-stray-value'], code: 2, stderr: /unexpected argument/ },
        { args: ['keys', 'prove', '--key', privateFile, '--challenge', CHALLENGE], code: 2, stderr: /--api-key-id is required/ },
        { args: proveWith('--force'), code: 2, stderr: /unknown option --force/ },
        { args: ['keys', 'prove', '--key', privateFile, '--api-key-id', 'TEST-ONLY-api-key-value', '--challenge', CHALLENGE], code: 2, stderr: /24-character API key id/ },
        { args: ['keys', 'prove', '--key', publicFile, '--api-key-id', API_KEY_ID, '--challenge', CHALLENGE], code: 2, stderr: /This is a public key\. Signing needs the private key/ },
        { args: ['keys', 'verify', '--key', publicFile], code: 2, stderr: /This is a public key/ },
        { args: ['keys', 'verify', '--key', privateFile], code: 2, stderr: /set VAULTODY_API_KEY, VAULTODY_API_SECRET, VAULTODY_PASSPHRASE in the environment/ },
        { args: ['keys', 'verify', '--key', privateFile, '--api-secret=TEST-ONLY-secret-value'], code: 2, stderr: /unknown option --api-secret\. The API credentials are read only from the environment/ },
        { args: ['keys', 'verify', '--key', privateFile, '--passphrase', 'TEST-ONLY-passphrase-value'], code: 2, stderr: /read only from the environment/ },
        { args: ['keys', 'verify', '--key', privateFile, '--root', 'https://user:TEST-ONLY-password@rest.vaultody.com'], code: 2, stderr: /must not hold a user name or password/ },
        { args: ['keys', 'verify', '--key', privateFile, '--root', 'rest.vaultody.com'], code: 2, stderr: /absolute URL/ },
        { args: ['keys', 'verify', '--key', privateFile, '--api-version', '2026-3-20'], code: 2, stderr: /--api-version must be a date, YYYY-MM-DD/ },
        { args: ['keys', 'verify', '--key', privateFile, '--api-version', '2026-03-20', '--api-version', '2026-11-01'], code: 2, stderr: /--api-version was given more than once/ },
        { args: ['keys', 'verify', '--key', privateFile, '--root', 'http://rest.example.test'], code: 2, stderr: /must be an https URL.*localhost, for a port-forward/ },
        { args: ['keys', 'verify', '--key', privateFile, '--response-root-key', ed25519PublicFile], code: 2, stderr: /must be an EC P-256 key/ },
        { args: ['keys', 'verify', '--key', privateFile, '--response-root-key', privateFile], code: 2, stderr: /PUBLIC KEY/ },
    ];

    for (const { args, code, stdout, stderr } of cases) {
        it(`${args.map(arg => arg.replace(dir, '<dir>')).join(' ') || '(no arguments)'} → ${code}`, () => {
            const result = cli(args);
            assert.equal(result.code, code, result.stderr);
            if (stdout) {
                assert.match(result.stdout, stdout);
            }
            if (stderr) {
                assert.match(result.stderr, stderr);
            }
            if (code !== 0) {
                assert.equal(result.stdout, '', 'nothing on stdout when it fails');
            }
            assert.ok(!(result.stdout + result.stderr).includes('TEST-ONLY-'), 'repeated a value it was given');
        });
    }
});

describe('vaultody keys verify: plain http to another machine', () => {
    it('is refused with the credentials set, before the key or the credentials are used', () => {
        const dir = tmpDir();
        const privateFile = path.join(dir, 'private.pem');
        fs.writeFileSync(privateFile, CHALLENGE_VECTORS.keys.ed25519.privateKeyPkcs8Pem, { mode: 0o600 });
        const env = { VAULTODY_API_KEY: 'TEST-ONLY-key-value', VAULTODY_API_SECRET: 'VEVTVC1PTkxZ', VAULTODY_PASSPHRASE: 'TEST-ONLY-passphrase-value' };
        for (const root of ['http://rest.vaultody.com', 'http://10.0.0.1:8080/v2']) {
            const result = cli(['keys', 'verify', '--key', privateFile, '--root', root], { env });
            assert.equal(result.code, 2);
            assert.equal(result.stdout, '');
            assert.match(result.stderr, /the API root must be an https URL: the request carries the passphrase/);
            assert.ok(!result.stderr.includes('TEST-ONLY-'));
        }
    });
});

// OpenSSL 3 is the first with `pkeyutl -rawin` for Ed25519; macOS ships LibreSSL, which lacks it.
function openSslVersion() {
    try {
        const version = execFileSync('openssl', ['version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
        const major = /^OpenSSL (\d+)\./.exec(version);

        return major && Number(major[1]) >= 3 ? version : null;
    } catch (e) {
        return null;
    }
}

const OPENSSL = openSslVersion();

describe(`the dashboard's openssl commands (${OPENSSL || 'skipped'})`, { skip: OPENSSL ? false : 'OpenSSL 3 or later is not on PATH' }, () => {
    // The commands exactly as the dashboard shows them; file names are passed as arguments.
    const sh = (script, ...args) => execFileSync('sh', ['-c', script, 'sh', ...args], { encoding: 'utf8' });
    const OPENSSL_FINGERPRINT = 'printf \'SHA256:%s\\n\' "$(openssl pkey -pubin -in "$1" -outform DER | openssl dgst -sha256 -binary | openssl base64 -A | tr -d \'=\')"';
    const OPENSSL_GENERATE = {
        ed25519: 'openssl genpkey -algorithm ed25519 -out "$1" && openssl pkey -in "$1" -pubout -out "$2"',
        'p-256': 'openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" && openssl pkey -in "$1" -pubout -out "$2"',
    };
    const OPENSSL_PROOF_FILE = 'printf \'vaultody-keypair-challenge-v1\\n%s\\n%s\\n%s\' "$1" "$2" "$3" > "$4"';
    const OPENSSL_PROVE = {
        ed25519: 'openssl pkeyutl -sign -inkey "$1" -rawin -in "$2" | openssl base64 -A',
        'p-256': 'openssl dgst -sha256 -sign "$1" "$2" | openssl base64 -A',
    };
    const OPENSSL_VERIFY = {
        ed25519: 'openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in "$2" -sigfile "$3"',
        'p-256': 'openssl dgst -sha256 -verify "$1" -signature "$3" "$2"',
    };
    // A final newline, should some OpenSSL print one, is not part of the signature.
    const signatureOf = output => output.replace(/\n$/, '');

    for (const algorithm of ['ed25519', 'p-256']) {
        it(`${algorithm}: the openssl fingerprint equals the CLI's, for keys made by either`, () => {
            const cliDir = tmpDir();
            const cliKeys = generate(cliDir, algorithm);
            assert.equal(sh(OPENSSL_FINGERPRINT, cliKeys.publicOut), cliKeys.stdout);

            const opensslDir = tmpDir();
            const privateFile = path.join(opensslDir, 'private.pem');
            const publicFile = path.join(opensslDir, 'public.pem');
            sh(OPENSSL_GENERATE[algorithm], privateFile, publicFile);
            remember(fs.readFileSync(privateFile, 'utf8'));
            const fingerprint = sh(OPENSSL_FINGERPRINT, publicFile);
            assert.match(fingerprint, /^SHA256:[A-Za-z0-9+/]{43}\n$/);
            assert.equal(cli(['keys', 'fingerprint', '--key', publicFile]).stdout, fingerprint);
            assert.equal(cli(['keys', 'fingerprint', '--key', privateFile]).stdout, fingerprint);
        });

        it(`${algorithm}: a proof made with openssl is accepted by the CLI's verifier`, () => {
            const dir = tmpDir();
            const privateFile = path.join(dir, 'private.pem');
            const publicFile = path.join(dir, 'public.pem');
            const challengeFile = path.join(dir, 'challenge.txt');
            sh(OPENSSL_GENERATE[algorithm], privateFile, publicFile);
            remember(fs.readFileSync(privateFile, 'utf8'));
            const fingerprint = sh(OPENSSL_FINGERPRINT, publicFile).trim();

            sh(OPENSSL_PROOF_FILE, API_KEY_ID, fingerprint, CHALLENGE, challengeFile);
            assert.deepEqual(fs.readFileSync(challengeFile), proofString(API_KEY_ID, fingerprint, CHALLENGE));
            const signature = signatureOf(sh(OPENSSL_PROVE[algorithm], privateFile, challengeFile));

            const publicKey = keys.readSigningKeyFile(publicFile, { accept: 'public' });
            assert.equal(keys.verifyChallengeProof(publicKey, { apiKeyId: API_KEY_ID, challenge: CHALLENGE, signature }), true);
            assert.equal(keys.verifyChallengeProof(publicKey, { apiKeyId: '6630f1c2a9e4b5d7c8e9f0d5', challenge: CHALLENGE, signature }), false);
        });

        it(`${algorithm}: openssl verifies the CLI's proof`, () => {
            const dir = tmpDir();
            const generated = generate(dir, algorithm);
            const proved = cli(['keys', 'prove', '--key', generated.out, '--api-key-id', API_KEY_ID, '--challenge', CHALLENGE]);
            assert.equal(proved.code, 0, proved.stderr);
            const challengeFile = path.join(dir, 'challenge.txt');
            const signatureFile = path.join(dir, 'signature.bin');
            sh(OPENSSL_PROOF_FILE, API_KEY_ID, generated.stdout.trim(), CHALLENGE, challengeFile);
            fs.writeFileSync(signatureFile, Buffer.from(proved.stdout.trim(), 'base64'));
            assert.match(sh(OPENSSL_VERIFY[algorithm], generated.publicOut, challengeFile, signatureFile), /Verified (OK|Successfully)/);
        });
    }
});

describe('the vaultody command ships with @vaultody/sdk', () => {
    it('is the package\'s bin (npx @vaultody/sdk keys ...), and @vaultody/verify declares none', () => {
        const manifest = require('../package.json');
        assert.deepEqual(manifest.bin, { vaultody: './bin/vaultody.js' });
        assert.ok(manifest.files.includes('bin/'));
        assert.match(fs.readFileSync(BIN, 'utf8'), /^#!\/usr\/bin\/env node\n/);
        assert.equal(require('@vaultody/verify/package.json').bin, undefined);
    });
});
