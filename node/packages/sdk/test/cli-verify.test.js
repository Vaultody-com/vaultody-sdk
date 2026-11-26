'use strict';

// `vaultody keys verify` against a local stand-in for the API. The command asks through the SDK's client
// (listApiKeySigningKeys), so this also holds the client's transport to the gateway's checks. The stand-in checks
// the request the way the gateway does, written out here independently of the SDK and @vaultody-com/verify: the HMAC
// v2 x-api-sign over the fields in the gateway's order, then x-api-keypair-id and x-api-keypair-sign against the
// keys registered on the API key. It answers like GET /api-keys/current/signing-keys, signing the response when a
// test asks it to.

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { after, before, beforeEach, describe, it } = require('node:test');

const { embeddedFingerprints } = require('@vaultody-com/verify/response');
const { main } = require('../bin/vaultody');
// The response signer of @vaultody-com/verify's own tests (test-only keys of test-vectors/v1.json)
const { rootPem, signFresh, FRESH_BASE } = require('../../verify/test/helpers');

const REQUEST_VECTORS = require('../../../../test-vectors/request-keypair-v1.json');

const BIN = path.join(__dirname, '..', 'bin', 'vaultody.js');
const VECTOR_KEYS = REQUEST_VECTORS.keys;
const REQUEST_TAG = 'vaultody-request-keypair-v1';
const NONCE = /^[\x21-\x7e]{1,128}$/;
const PATH = '/api-keys/current/signing-keys';
// The API versions the stand-in knows, and the one the route was introduced in
const API_VERSIONS = ['2024-12-12', '2026-03-20', '2026-11-01'];
const ROUTE_SINCE = '2026-03-20';

const API_KEY = `vk-test-${crypto.randomBytes(12).toString('hex')}`;
const API_SECRET = crypto.randomBytes(32).toString('base64');
const PASSPHRASE = `pass-${crypto.randomBytes(8).toString('hex')}`;
const ENV = Object.freeze({ VAULTODY_API_KEY: API_KEY, VAULTODY_API_SECRET: API_SECRET, VAULTODY_PASSPHRASE: PASSPHRASE });
const SECRETS = [API_KEY, API_SECRET, PASSPHRASE];

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-verify-'));
const keyFile = name => path.join(tmp, `${name}.pem`);
for (const [name, vectorKey] of Object.entries(VECTOR_KEYS)) {
    fs.writeFileSync(keyFile(name), vectorKey.privateKeyPkcs8Pem, { mode: 0o600 });
}
const ROOT_FILE = path.join(tmp, 'root.pem');
fs.writeFileSync(ROOT_FILE, rootPem('current'));
const PRIVATE_BODIES = Object.values(VECTOR_KEYS).map(vectorKey => vectorKey.privateKeyPkcs8Pem.split('\n')[1].slice(0, 40));

const envelope = fields => JSON.stringify({ apiVersion: '2024-12-12', requestId: 'req-6630f1c2', context: '', ...fields });
const refusal = (status, code, message) => ({ status, body: envelope({ error: { code, message } }) });
const itemOf = (name, status = 'active') => ({
    fingerprint: VECTOR_KEYS[name].fingerprint,
    algorithm: VECTOR_KEYS[name].algorithm,
    status,
    createdTimestamp: 1794200000,
    approvedTimestamp: 1794200100,
});
const listOf = items => ({ status: 200, body: envelope({ data: { limit: 2, offset: 0, total: items.length, items } }) });

function verifiesWith(vectorKey, message, signatureText) {
    const signature = Buffer.from(signatureText || '', 'base64');
    const publicKey = crypto.createPublicKey(vectorKey.publicKeySpkiPem);
    try {
        return vectorKey.algorithm === 'ed25519'
            ? crypto.verify(null, message, publicKey, signature)
            : crypto.verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, signature);
    } catch (e) {
        return false;
    }
}

/**
 * The gateway's checks, in its order, for an API key holding `registered` signing keys. The command runs on the
 * vectors' clock in this process (a signed answer is checked as at that time), on the real one as a separate
 * process (realClock).
 */
function gateway(req, body, registered, { realClock = false } = {}) {
    const h = req.headers;
    if (!h['x-api-key'] || !h['x-api-sign'] || !h['x-api-timestamp'] || !h['x-api-passphrase']) {
        return refusal(401, 'missing_authorization_header', 'Authorization headers are missing.');
    }
    if (h['x-api-key'] !== API_KEY || h['x-api-passphrase'] !== PASSPHRASE) {
        return refusal(401, 'invalid_api_key', 'The provided API key is invalid.');
    }
    if (h['x-api-version'] !== undefined && !API_VERSIONS.includes(h['x-api-version'])) {
        return refusal(400, 'invalid_api_version', 'The provided API version is invalid.');
    }
    if (h['x-api-sign-version'] !== '2' || !NONCE.test(h['x-api-nonce'] || '')) {
        return refusal(401, 'invalid_api_sign', 'The provided API sign is invalid.');
    }

    const queryAt = req.url.indexOf('?');
    const fields = [
        h['x-api-timestamp'],
        req.method,
        queryAt === -1 ? req.url : req.url.slice(0, queryAt),
        h['x-api-version'] || '',
        h['x-api-passphrase'],
        h['x-api-nonce'],
        queryAt === -1 ? '' : req.url.slice(queryAt + 1),
        body.toString('utf8'),
    ];
    const expectedSign = crypto.createHmac('sha256', Buffer.from(API_SECRET, 'base64')).update(['v2', ...fields].join('\n')).digest('base64');
    if (h['x-api-sign'] !== expectedSign) {
        return refusal(401, 'invalid_api_sign', 'The provided API sign is invalid.');
    }
    const now = realClock ? Date.now() / 1000 : FRESH_BASE.verify.now;
    if (Math.abs(now - Number(h['x-api-timestamp'])) > 60) {
        return refusal(401, 'invalid_api_timestamp', 'The timestamp is too old.');
    }

    if (registered.length > 0) {
        if (!h['x-api-keypair-sign']) {
            return refusal(401, 'missing_api_keypair_sign', 'x-api-keypair-sign is missing.');
        }
        const vectorKey = registered.map(name => VECTOR_KEYS[name]).find(candidate => candidate.fingerprint === h['x-api-keypair-id']);
        if (!vectorKey) {
            return refusal(401, 'unknown_api_keypair_id', 'The x-api-keypair-id is not a key of this API key.');
        }
        // the key-pair string: the tag, the x-api-key the request was sent with, then the HMAC v2 fields
        if (!verifiesWith(vectorKey, Buffer.from([REQUEST_TAG, h['x-api-key'], ...fields].join('\n'), 'utf8'), h['x-api-keypair-sign'])) {
            return refusal(401, 'invalid_api_keypair_sign', 'The provided x-api-keypair-sign is invalid.');
        }
    }

    // The route exists from its version on; without x-api-version an API key with no default version has none.
    if (h['x-api-version'] === undefined || h['x-api-version'] < ROUTE_SINCE) {
        return refusal(400, 'uri_not_found', 'The requested URI was not found.');
    }

    return listOf(registered.map(name => itemOf(name)));
}

describe('vaultody keys verify against a local API', () => {
    let server;
    let origin;
    // Each test sets how the API behaves and reads back the request it received.
    let behaviour;
    let received;

    // The stand-in API; tests that need it on another address start a second server with this handler.
    let handle;

    before(async () => {
        handle = (req, res) => {
            const chunks = [];
            req.on('data', chunk => chunks.push(chunk));
            req.on('end', () => {
                const body = Buffer.concat(chunks);
                received = { method: req.method, url: req.url, headers: req.headers, body };
                const answer = behaviour.respond ? behaviour.respond(req, body) : gateway(req, body, behaviour.registered || [], behaviour);
                let headers = { 'content-type': 'application/json' };
                if (behaviour.sign) {
                    const signed = signFresh({
                        method: req.method,
                        url: req.url,
                        requestBody: body,
                        apiSign: req.headers['x-api-sign'] || '',
                        keypairSign: req.headers['x-api-keypair-sign'] || '',
                        status: answer.status,
                        body: Buffer.from(answer.body),
                    });
                    headers = { ...headers, ...(behaviour.alterSignature ? behaviour.alterSignature(signed, req) : signed) };
                }
                res.writeHead(answer.status, headers);
                res.end(behaviour.alterBody ? behaviour.alterBody(answer.body) : answer.body);
            });
        };
        server = http.createServer(handle);
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        origin = `http://127.0.0.1:${server.address().port}`;
    });

    after(() => {
        server.closeAllConnections();
        server.close();
        fs.rmSync(tmp, { recursive: true, force: true });
    });

    beforeEach(() => {
        behaviour = { registered: [] };
        received = null;
    });

    /**
     * Runs the command in this process, so the response check can use the vectors' clock, and the client's retries
     * wait no time.
     */
    async function verify(keyName, { env = ENV, root = origin, signed = false, extra = [], timeoutMs } = {}) {
        let stdout = '';
        let stderr = '';
        const args = ['keys', 'verify', '--key', keyFile(keyName), '--root', root, ...extra];
        if (signed) {
            args.push('--response-root-key', ROOT_FILE);
        }
        const code = await main(args, {
            env,
            stdout: text => { stdout += text; },
            stderr: text => { stderr += text; },
            now: FRESH_BASE.verify.now,
            sleep: async () => {},
            timeoutMs,
        });
        for (const secret of [...SECRETS, ...PRIVATE_BODIES]) {
            assert.ok(!(stdout + stderr).includes(secret), 'printed a credential or private key material');
        }

        return { code, stdout, stderr };
    }

    it('a registered, active key, unsigned response: exit 4, the answer could not be verified', async () => {
        behaviour = { registered: ['ed25519'] };
        const result = await verify('ed25519');
        assert.equal(result.code, 4, result.stderr);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /^vaultody: the response was not signed, so the answer could not be verified\.\n/);
        assert.match(result.stderr, /removed the signature and could have changed the answer too\. Do not rely on it\./);
        assert.match(result.stderr, /--allow-unsigned accepts an unsigned answer with a warning/);
        assert.match(result.stderr, /Unverified answer: SHA256:\S+ is listed as registered and active\.\nRequest id: req-6630f1c2\n$/);
        assert.doesNotMatch(result.stderr, /OK:/);
    });

    it('a registered, active Ed25519 key, unsigned response, --allow-unsigned: exit 0 with a warning', async () => {
        behaviour = { registered: ['ed25519'] };
        const result = await verify('ed25519', { extra: ['--allow-unsigned'] });
        assert.equal(result.code, 0, result.stderr);
        assert.equal(result.stderr, 'vaultody: warning: the response was not signed, so the answer could not be verified. Accepted because of --allow-unsigned.\n');
        assert.match(result.stdout, new RegExp(`^OK: ${VECTOR_KEYS.ed25519.fingerprint.replace(/[+/]/g, '\\$&')} \\(ed25519\\) is registered and active on this API key\\.\n`));
        assert.match(result.stdout, /Response signature: none\. .* accepted only because of --allow-unsigned\./);
        assert.match(result.stdout, /\(this key\)/);

        // What went over the wire: one signed GET, with no body and without the secret
        assert.equal(received.method, 'GET');
        assert.equal(received.url, PATH);
        assert.equal(received.body.length, 0);
        assert.equal(received.headers['x-api-sign-version'], '2');
        assert.match(received.headers['x-api-nonce'], /^[0-9a-f]{32}$/);
        assert.equal(received.headers['x-api-keypair-id'], VECTOR_KEYS.ed25519.fingerprint);
        // sent by the SDK's client
        assert.match(received.headers['user-agent'], /^vaultody-sdk-node\//);
        // the version the route was introduced in, signed on the version line (the stand-in checked both signatures)
        assert.equal(received.headers['x-api-version'], '2026-03-20');
        assert.ok(!JSON.stringify(received.headers).includes(API_SECRET), 'sent the API secret');
    });

    it('a P-256 key during a rotation, signed response verified: exit 0', async () => {
        behaviour = { registered: ['ed25519', 'p256'], sign: true };
        const result = await verify('p256', { signed: true });
        assert.equal(result.code, 0, result.stderr);
        assert.match(result.stdout, /is registered and active/);
        assert.match(result.stdout, /Response signature: verified \(root [0-9a-f]{64}\)\./);
        assert.equal(result.stdout.split('\n').filter(line => line.startsWith('  SHA256:')).length, 2);
    });

    it('signs the path as sent under an API root with a path prefix', async () => {
        behaviour = { registered: ['p256'], sign: true };
        const result = await verify('p256', { signed: true, root: `${origin}/v2/` });
        assert.equal(result.code, 0, result.stderr);
        assert.equal(received.url, `/v2${PATH}`);
    });

    it('--api-version sends and signs another version', async () => {
        behaviour = { registered: ['p256'], sign: true };
        const result = await verify('p256', { signed: true, extra: ['--api-version', '2026-11-01'] });
        assert.equal(result.code, 0, result.stderr);
        assert.equal(received.headers['x-api-version'], '2026-11-01');
    });

    it('a version older than the route: the API answers uri_not_found, exit 3', async () => {
        behaviour = { registered: ['ed25519'] };
        const result = await verify('ed25519', { extra: ['--api-version', '2024-12-12'] });
        assert.equal(result.code, 3);
        assert.match(result.stderr, /unexpected answer: the API answered 400 \(uri_not_found\)/);
    });

    it('a version the API does not know: invalid_api_version, exit 3', async () => {
        behaviour = { registered: ['ed25519'] };
        const result = await verify('ed25519', { extra: ['--api-version', '2026-03-21'] });
        assert.equal(result.code, 3);
        assert.match(result.stderr, /\(invalid_api_version\)/);
    });

    it('an --api-version that is not YYYY-MM-DD: exit 2, nothing sent', async () => {
        for (const version of ['2026-3-20', '20260320', '2026-13-01', '2026-03-32', '2026-00-10', 'latest', ' 2026-03-20', '2026-03-20\n', '']) {
            const result = await verify('ed25519', { extra: ['--api-version', version] });
            assert.equal(result.code, 2, JSON.stringify(version));
            assert.match(result.stderr, /--api-version must be a date, YYYY-MM-DD, such as 2026-03-20/);
        }
        assert.equal(received, null);
    });

    it('a signed response whose body was changed on the way: exit 1', async () => {
        behaviour = { registered: ['ed25519'], sign: true, alterBody: body => body.replace('"active"', '"active" ') };
        const result = await verify('ed25519', { signed: true });
        assert.equal(result.code, 1);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /the response failed its signature check \(invalid\); do not trust it/);
    });

    it('a signed response that answers a request without this x-api-keypair-sign: exit 1', async () => {
        behaviour = {
            registered: ['ed25519'],
            sign: true,
            alterSignature: (signed, req) => signFresh({
                method: req.method, url: req.url, apiSign: req.headers['x-api-sign'], keypairSign: '', status: 200, body: Buffer.from(listOf([itemOf('ed25519')]).body),
            }),
        };
        const result = await verify('ed25519', { signed: true });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /signature check \(invalid\)/);
    });

    it('a response with some of its signature headers stripped: exit 1', async () => {
        behaviour = { registered: ['ed25519'], sign: true, alterSignature: ({ 'x-api-response-sign': dropped, ...rest }) => rest };
        const result = await verify('ed25519', { signed: true });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /signature check \(missing\)/);
    });

    it('a signed response with every signature header stripped on the way: exit 4, even with --allow-unsigned', async () => {
        behaviour = { registered: ['ed25519'], sign: true, alterSignature: () => ({}) };
        for (const extra of [[], ['--allow-unsigned']]) {
            const result = await verify('ed25519', { signed: true, extra });
            assert.equal(result.code, 4, result.stderr);
            assert.equal(result.stdout, '');
            assert.match(result.stderr, /vaultody: the response was not signed, so the answer could not be verified\./);
            // with a root key given, an unsigned answer is never accepted, so the flag is not offered
            assert.doesNotMatch(result.stderr, /--allow-unsigned accepts/);
            if (extra.length > 0) {
                assert.match(result.stderr, /^vaultody: warning: --allow-unsigned is ignored: --response-root-key is given, so the response must be signed\.\n/);
            }
        }
    });

    it('a signed response and no root key to check it with', async () => {
        behaviour = { registered: ['ed25519'], sign: true };
        const result = await verify('ed25519');
        if (embeddedFingerprints().length === 0) {
            assert.equal(result.code, 2);
            assert.match(result.stderr, /the response is signed, but this build has no response-signing root keys.*--response-root-key/);
        } else {
            // once the production roots are embedded, a test root is simply not trusted
            assert.equal(result.code, 1);
            assert.match(result.stderr, /unknown_root/);
        }
    });

    it('a key not registered on the API key: the API refuses it, exit 1', async () => {
        behaviour = { registered: ['ed25519'], sign: true };
        const result = await verify('ed25519_other', { signed: true });
        assert.equal(result.code, 1);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /the API refused the request: unknown_api_keypair_id \(HTTP 401\)/);
        assert.match(result.stderr, /not registered on this API key, or its registration is not approved yet/);
        assert.match(result.stderr, /Request id: req-6630f1c2/);
        assert.match(result.stderr, /Response signature: verified/);
    });

    it('an unsigned refusal: exit 4, with what the unverified answer said', async () => {
        behaviour = { registered: ['ed25519'] };
        const result = await verify('ed25519_other');
        assert.equal(result.code, 4);
        assert.match(result.stderr, /Unverified answer: the API refused the request: unknown_api_keypair_id \(HTTP 401\)\.\n/);
        assert.match(result.stderr, /not registered on this API key, or its registration is not approved yet/);
    });

    it('an unsigned refusal, --allow-unsigned: exit 1 with a warning', async () => {
        behaviour = { registered: ['ed25519'] };
        const result = await verify('ed25519_other', { extra: ['--allow-unsigned'] });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /^vaultody: warning: the response was not signed/);
        assert.match(result.stderr, /the API refused the request: unknown_api_keypair_id \(HTTP 401\)/);
    });

    it('an API key with no signing keys: nothing listed, exit 1', async () => {
        behaviour = { registered: [], sign: true };
        const result = await verify('ed25519', { signed: true });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /is not a signing key of this API key/);
        assert.match(result.stderr, /This API key has no signing keys\./);
    });

    it('a key listed but not active: exit 1', async () => {
        behaviour = { respond: () => listOf([itemOf('p256', 'pending')]), sign: true };
        const result = await verify('p256', { signed: true });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /is on this API key but not active/);
    });

    it('a wrong API secret: the API refuses the HMAC, exit 1 with a hint', async () => {
        behaviour = { registered: ['ed25519'], sign: true };
        const result = await verify('ed25519', { signed: true, env: { ...ENV, VAULTODY_API_SECRET: crypto.randomBytes(32).toString('base64') } });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /invalid_api_sign \(HTTP 401\)/);
        assert.match(result.stderr, /Check VAULTODY_API_SECRET and VAULTODY_PASSPHRASE/);
    });

    it('never prints a credential, even one the API echoes back', async () => {
        behaviour = { respond: () => refusal(403, 'ip_address_not_whitelisted', `not for ${PASSPHRASE} / ${API_KEY}`), sign: true };
        const result = await verify('ed25519', { signed: true });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /not for \[redacted\] \/ \[redacted\]/);
    });

    it('prints what the API sends only as printable ASCII on one line', async () => {
        behaviour = { respond: () => refusal(401, 'unknown_api_keypair_id', 'no\u001b[2J\nfake line'), sign: true };
        const result = await verify('ed25519', { signed: true });
        assert.equal(result.code, 1);
        assert.match(result.stderr, /: no\?\[2J\?fake line\n/);
        assert.doesNotMatch(result.stderr, /\u001b/);
    });

    for (const [status, code] of [[500, 'unexpected_server_error'], [429, 'request_limit_reached'], [404, 'resource_not_found']]) {
        it(`HTTP ${status}: exit 3`, async () => {
            behaviour = { respond: () => refusal(status, code, 'no') };
            const result = await verify('ed25519');
            assert.equal(result.code, 3);
            assert.match(result.stderr, new RegExp(`unexpected answer: the API answered ${status} \\(${code}\\)\\. Request id: req-6630f1c2`));
        });
    }

    for (const [name, answer] of [
        ['a body that is not JSON', { status: 200, body: '<html>ok</html>' }],
        ['JSON without the list', { status: 200, body: envelope({ data: { item: {} } }) }],
        ['a refusal that is not JSON', { status: 401, body: 'Unauthorized' }],
        ['a body far too large', { status: 200, body: 'x'.repeat(2 * 1024 * 1024) }],
    ]) {
        it(`${name}: exit 3`, async () => {
            behaviour = { respond: () => answer };
            const result = await verify('ed25519');
            assert.equal(result.code, 3, result.stderr);
            assert.match(result.stderr, /unexpected answer|network error/);
        });
    }

    it('no API at the root: exit 3', async () => {
        const closed = http.createServer();
        await new Promise(resolve => closed.listen(0, '127.0.0.1', resolve));
        const { port } = closed.address();
        await new Promise(resolve => closed.close(resolve));
        const result = await verify('ed25519', { root: `http://127.0.0.1:${port}` });
        assert.equal(result.code, 3);
        assert.match(result.stderr, /network error: .*ECONNREFUSED/);
    });

    it('no answer in time: a timeout, not a hang, exit 3', async () => {
        const silent = http.createServer(() => {});
        await new Promise(resolve => silent.listen(0, '127.0.0.1', resolve));
        try {
            const result = await verify('ed25519', { root: `http://127.0.0.1:${silent.address().port}`, timeoutMs: 200 });
            assert.equal(result.code, 3);
            assert.match(result.stderr, /network error: .*timeout/i);
        } finally {
            silent.closeAllConnections();
            silent.close();
        }
    });

    it('plain http to the API through localhost (a port-forward): allowed', async () => {
        behaviour = { registered: ['ed25519'] };
        // Listening on "localhost" itself, which may resolve to ::1 before 127.0.0.1
        const forwarded = http.createServer(handle);
        await new Promise(resolve => forwarded.listen(0, 'localhost', resolve));
        try {
            behaviour = { registered: ['ed25519'], sign: true };
            const result = await verify('ed25519', { signed: true, root: `http://localhost:${forwarded.address().port}` });
            assert.equal(result.code, 0, result.stderr);
            assert.equal(result.stderr, '');
            assert.equal(received.url, PATH);
        } finally {
            forwarded.closeAllConnections();
            forwarded.close();
        }
    });

    it('plain http to another machine: refused, nothing is sent, exit 2', async () => {
        for (const root of ['http://rest.vaultody.com', 'http://rest.example.test/v2', 'http://10.0.0.1:8080']) {
            const result = await verify('ed25519', { root });
            assert.equal(result.code, 2, root);
            assert.match(result.stderr, /the API root must be an https URL: the request carries the passphrase, so plain http is allowed only to this machine \(localhost, for a port-forward\)/);
        }
        assert.equal(received, null);
    });

    it('reads the passphrase from VAULTODY_PASSPHRASE only, as the developer docs name it', async () => {
        const { VAULTODY_PASSPHRASE: passphrase, ...rest } = ENV;
        const result = await verify('ed25519', { env: { ...rest, VAULTODY_API_PASSPHRASE: passphrase } });
        assert.equal(result.code, 2);
        assert.match(result.stderr, /set VAULTODY_PASSPHRASE in the environment/);
        assert.equal(received, null);
    });

    it('missing credentials: nothing is sent, exit 2', async () => {
        const result = await verify('ed25519', { env: { VAULTODY_API_KEY: API_KEY } });
        assert.equal(result.code, 2);
        assert.match(result.stderr, /set VAULTODY_API_SECRET, VAULTODY_PASSPHRASE in the environment/);
        assert.equal(received, null);
    });

    it('as a separate process, an unsigned response: exit 4', async () => {
        behaviour = { registered: ['p256'], realClock: true };
        const { code, stdout, stderr } = await new Promise(resolve => {
            execFile(process.execPath, [BIN, 'keys', 'verify', '--key', keyFile('p256'), '--root', origin], {
                env: { PATH: process.env.PATH, ...ENV },
                encoding: 'utf8',
            }, (error, out, err) => resolve({ code: error ? error.code : 0, stdout: out, stderr: err }));
        });
        assert.equal(code, 4, stderr);
        assert.equal(stdout, '');
        assert.match(stderr, /the response was not signed, so the answer could not be verified/);
    });

    it('as a separate process with the credentials in its environment, --allow-unsigned: exit 0', async () => {
        behaviour = { registered: ['p256'], realClock: true };
        const { code, stdout, stderr } = await new Promise(resolve => {
            execFile(process.execPath, [BIN, 'keys', 'verify', '--key', keyFile('p256'), '--root', origin, '--allow-unsigned'], {
                env: { PATH: process.env.PATH, ...ENV },
                encoding: 'utf8',
            }, (error, out, err) => resolve({ code: error ? error.code : 0, stdout: out, stderr: err }));
        });
        assert.equal(code, 0, stderr);
        assert.match(stdout, /^OK: SHA256:/);
        assert.match(stderr, /^vaultody: warning: the response was not signed/);
        for (const secret of SECRETS) {
            assert.ok(!(stdout + stderr).includes(secret));
        }
    });

    it('as a separate process, a refusal: exit 1', async () => {
        behaviour = { registered: ['ed25519'], realClock: true };
        const code = await new Promise(resolve => {
            execFile(process.execPath, [BIN, 'keys', 'verify', '--key', keyFile('p256'), '--root', origin, '--allow-unsigned'], {
                env: { PATH: process.env.PATH, ...ENV },
            }, error => resolve(error ? error.code : 0));
        });
        assert.equal(code, 1);
    });
});
