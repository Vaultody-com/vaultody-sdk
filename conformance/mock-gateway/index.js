'use strict';

/**
 * A mock of the Vaultody API gateway for SDK tests and CI: an HTTP server on 127.0.0.1 that checks every
 * request the way the gateway does and answers with signed responses.
 *
 * It is written independently of the SDKs and of @vaultody/verify, from the wire formats in test-vectors/
 * and the gateway's request-signing, replay-protection and response-signing code, so an SDK
 * bug can't be mirrored here. Only node:crypto and node:http; no dependency.
 *
 *  - Request signatures: x-api-sign version 2 (HMAC-SHA256 over the v2 string, keyed with the decoded API
 *    secret), x-api-timestamp within 30 s + 10 s of drift, and for an API key with registered key pairs
 *    x-api-nonce, x-api-keypair-id and x-api-keypair-sign (Ed25519 raw, P-256 DER only).
 *  - Replay protection per API key and nonce: a duplicate within 3 s of the first request gets the first
 *    answer again with x-api-replayed: true; one that arrives while the first still runs waits up to 5 s,
 *    then gets 409 duplicate_api_request_in_progress; a later one 401 duplicate_api_request. A 429 forgets
 *    the record, as the gateway does. Enforced for key-pair requests; for a legacy key "report" by default,
 *    as on production: the duplicate runs again (which the tests count).
 *  - Response signing with the TEST-ONLY root and pod keys of test-vectors/v1.json, over the request as
 *    received: every answer, errors included.
 *  - Routes: any route a test registers, else GET /api-keys/current/signing-keys and GET /vaults/{main|test}
 *    from its state, else 404.
 *  - Faults, in the order a test queues them: a status before the route (429, 5xx) or after it ran (5xx), a
 *    dropped connection before or after the route, a delay; and a MITM hook that rewrites an answer after it
 *    was signed (swap an address, change an xpub, strip a header).
 */

const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');

const VECTORS_DIR = path.resolve(__dirname, '..', '..', 'test-vectors');
const RESPONSE_VECTORS = require(path.join(VECTORS_DIR, 'v1.json'));

const SIGNATURE_MAX_AGE_SECONDS = 30;
const SIGNATURE_DRIFT_SECONDS = 10;
const REPLAY_RESPONSE_WINDOW_MS = 3000;
const REPLAY_RECORD_TTL_MS = 42000;
const REPLAY_BODY_LIMIT = 64 * 1024;
const IN_PROGRESS_WAIT_MS = 5000;
const NONCE = /^[\x21-\x7e]{1,128}$/;

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest();
const b64 = bytes => Buffer.from(bytes).toString('base64');

/** The roots and pod keys of v1.json, as key objects. */
const ROOTS = Object.fromEntries(Object.entries(RESPONSE_VECTORS.keys.roots).map(([name, root]) => [name, {
    rootId: root.rootId,
    privateKey: crypto.createPrivateKey(root.privateKeyPkcs8Pem),
    publicKeySpkiDerBase64: root.publicKeySpkiDerBase64,
}]));
const PODS = Object.fromEntries(Object.entries(RESPONSE_VECTORS.keys.podKeys).map(([name, pod]) => [name, {
    privateKey: crypto.createPrivateKey(pod.privateKeyPkcs8Pem),
    publicKeyBase64: pod.publicKeyBase64,
    keyId: pod.keyId,
}]));

/** The TEST-ONLY root public keys, as SPKI PEM, for a client's roots option. */
const rootPem = name => crypto.createPublicKey({ key: Buffer.from(ROOTS[name].publicKeySpkiDerBase64, 'base64'), format: 'der', type: 'spki' })
    .export({ format: 'pem', type: 'spki' });

function certificateHeader(rootName, podName, notBefore, notAfter) {
    const pod = PODS[podName];
    const root = ROOTS[rootName];
    const cert = Buffer.from(['vaultody-response-key-v1', root.rootId, pod.publicKeyBase64, pod.keyId, String(notBefore), String(notAfter)].join('\n'), 'latin1');
    const signature = crypto.sign('sha256', cert, { key: root.privateKey, dsaEncoding: 'der' });

    return `${b64(cert)}.${b64(signature)}`;
}

/** The bytes the gateway signs for one answer: the tagged header lines, then the raw response body. */
function responseMessage({ request, status, body, nowSeconds, unreadBody = false }) {
    const bodyHash = unreadBody ? 'unread' : sha256(request.body).toString('hex');

    return Buffer.concat([
        Buffer.from(['vaultody-response-v1', String(nowSeconds), String(status), request.method, request.path, request.query, bodyHash,
            request.headers['x-api-sign'] || '', request.headers['x-api-keypair-sign'] || ''].join('\n').concat('\n'), 'latin1'),
        body,
    ]);
}

/** The four response-signing headers for one answer to one request as received. */
function signResponse({ request, status, body, nowSeconds, signing }) {
    // A window of one hour at most, as the gateway issues and every verifier requires (60 s back for clock skew).
    const notBefore = signing.notBefore !== undefined ? signing.notBefore : nowSeconds - 60;
    const notAfter = signing.notAfter !== undefined ? signing.notAfter : nowSeconds + 3540;
    const message = responseMessage({ request, status, body, nowSeconds, unreadBody: signing.unreadBody });

    return {
        'x-api-response-sign': b64(crypto.sign(null, message, PODS[signing.pod || 'pod1'].privateKey)),
        'x-api-response-timestamp': String(nowSeconds),
        'x-api-response-sign-version': signing.version || '1',
        'x-api-response-cert': certificateHeader(signing.root || 'current', signing.pod || 'pod1', notBefore, notAfter),
    };
}

/**
 * The v2 string: tag, timestamp, method, path, x-api-version, passphrase, nonce, query, body, "\n"-joined. The key-pair
 * string has the x-api-key the request came with between the tag and the timestamp, so a request signed for one API
 * key is refused under another that holds the same key pair.
 */
const taggedMessage = (tag, request, apiKeyLine = []) => Buffer.from([
    tag,
    ...apiKeyLine,
    request.headers['x-api-timestamp'] || '',
    request.method,
    request.path,
    request.headers['x-api-version'] || '',
    request.headers['x-api-passphrase'] || '',
    request.headers['x-api-nonce'] || '',
    request.query,
    request.body.toString('utf8'),
].join('\n'), 'utf8');

const fingerprintOf = publicKey => `SHA256:${sha256(publicKey.export({ format: 'der', type: 'spki' })).toString('base64').replace(/=+$/, '')}`;

function canonicalBase64(text) {
    if (typeof text !== 'string' || text === '') {
        return null;
    }
    const bytes = Buffer.from(text, 'base64');

    return bytes.toString('base64') === text ? bytes : null;
}

function errorBody(code, message, requestId) {
    return { requestId, error: { code, message } };
}

class MockGateway {
    /**
     * @param {Object} [options]
     * @param {function(): number} [options.clock] milliseconds; share a fake one with the client
     * @param {Object} [options.keys] apiKey → { secret, passphrase, keypairs?: [publicKeyPem], replay?: 'enforce'|'report' }
     * @param {Object|false} [options.signing] { root: 'current'|'next'|'unpinned', pod, version, unreadBody,
     *        notBefore, notAfter }, or false to answer unsigned (as production does today)
     * @param {number} [options.inProgressWaitMs]
     */
    constructor({ clock = Date.now, keys = {}, signing = { root: 'current' }, inProgressWaitMs = IN_PROGRESS_WAIT_MS } = {}) {
        this.clock = clock;
        this.keys = new Map(Object.entries(keys).map(([apiKey, entry]) => [apiKey, {
            ...entry,
            replay: entry.replay || 'report',
            keypairs: (entry.keypairs || []).map(pem => {
                const publicKey = crypto.createPublicKey(pem);

                return { publicKey, fingerprint: fingerprintOf(publicKey), algorithm: publicKey.asymmetricKeyType === 'ed25519' ? 'ed25519' : 'p-256' };
            }),
        }]));
        this.signing = signing;
        this.inProgressWaitMs = inProgressWaitMs;
        this.routes = [];
        this.faults = [];
        this.mitm = null;
        this.replay = new Map();
        this.requests = [];
        this.executions = [];
        this.vaults = { main: [], test: [] };
        this.requestCounter = 0;
        this.server = http.createServer((req, res) => {
            this.handle(req, res).catch(error => {
                res.statusCode = 500;
                res.end(String(error && error.stack));
            });
        });
    }

    async listen() {
        await new Promise(resolve => this.server.listen(0, '127.0.0.1', resolve));
        this.url = `http://127.0.0.1:${this.server.address().port}`;

        return this;
    }

    async close() {
        this.server.closeAllConnections();
        await new Promise(resolve => this.server.close(resolve));
    }

    /** Registers a route: handler(request) → { status, body, headers } (body: object, string or Buffer). */
    route(method, pattern, handler) {
        this.routes.push({ method, pattern, handler });

        return this;
    }

    /**
     * Queues faults: each request takes the first queued fault that matches it (fault.match(request), any
     * request when absent), or null for no fault. A fault acts before the route (it did not run) or after it
     * ran ("when", default "before"):
     *  - { status, code, headers }: an error answer, signed like any other;
     *  - { drop: true }: the connection closed with no answer;
     *  - { delayMs }: the answer held back (real time), after the route;
     *  - { advanceClockMs }: the fake clock moved on (needs a clock with advance(ms)).
     * Pass null to let one request through untouched.
     */
    fault(...faults) {
        this.faults.push(...faults);

        return this;
    }

    takeFault(request) {
        const index = this.faults.findIndex(fault => fault === null || !fault.match || fault.match(request));
        if (index === -1) {
            return null;
        }
        const fault = this.faults.splice(index, 1)[0];
        if (fault === null) {
            return null;
        }

        return { when: 'before', ...fault };
    }

    nowSeconds() {
        return Math.floor(this.clock() / 1000);
    }

    newRequestId() {
        this.requestCounter += 1;

        return `6630f1c2a9e4b5d7c8e9${this.requestCounter.toString(16).padStart(4, '0')}`;
    }

    async readRequest(req) {
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        const queryAt = req.url.indexOf('?');

        return {
            method: req.method,
            path: queryAt === -1 ? req.url : req.url.slice(0, queryAt),
            query: queryAt === -1 ? '' : req.url.slice(queryAt + 1),
            headers: req.headers,
            body: Buffer.concat(chunks),
        };
    }

    /** The gateway's authentication, in its order. Returns null when the request passes, else an answer. */
    authenticate(request) {
        const { headers } = request;
        const entry = this.keys.get(headers['x-api-key']);
        if (!headers['x-api-key'] || !headers['x-api-sign'] || !headers['x-api-timestamp'] || !headers['x-api-passphrase']) {
            return { status: 401, code: 'missing_authorization_header' };
        }
        if (!entry || entry.passphrase !== headers['x-api-passphrase']) {
            return { status: 401, code: 'invalid_api_key' };
        }
        if (headers['x-api-sign-version'] !== '2') {
            return { status: 401, code: 'invalid_api_sign' };
        }
        const timestamp = Number(headers['x-api-timestamp']);
        if (!/^[0-9]+$/.test(headers['x-api-timestamp']) || Math.abs(this.nowSeconds() - timestamp) > SIGNATURE_MAX_AGE_SECONDS + SIGNATURE_DRIFT_SECONDS) {
            return { status: 401, code: 'invalid_api_timestamp' };
        }
        if (headers['x-api-nonce'] !== undefined && !NONCE.test(headers['x-api-nonce'])) {
            return { status: 401, code: 'invalid_api_sign' };
        }
        const expected = crypto.createHmac('sha256', Buffer.from(entry.secret, 'base64')).update(taggedMessage('v2', request)).digest();
        const given = canonicalBase64(headers['x-api-sign']);
        if (!given || given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
            return { status: 401, code: 'invalid_api_sign' };
        }

        request.keypairVerified = null;
        if (entry.keypairs.length > 0) {
            if (!headers['x-api-nonce']) {
                return { status: 401, code: 'missing_api_nonce' };
            }
            if (!headers['x-api-keypair-sign'] || !headers['x-api-keypair-id']) {
                return { status: 401, code: 'missing_api_keypair_sign' };
            }
            const key = entry.keypairs.find(candidate => candidate.fingerprint === headers['x-api-keypair-id']);
            if (!key) {
                return { status: 401, code: 'unknown_api_keypair_id' };
            }
            const signature = canonicalBase64(headers['x-api-keypair-sign']);
            const message = taggedMessage('vaultody-request-keypair-v1', request, [headers['x-api-key'] || '']);
            let ok = false;
            try {
                ok = signature !== null && (key.algorithm === 'ed25519'
                    ? signature.length === 64 && crypto.verify(null, message, key.publicKey, signature)
                    : crypto.verify('sha256', message, { key: key.publicKey, dsaEncoding: 'der' }, signature));
            } catch (e) {
                ok = false;
            }
            if (!ok) {
                return { status: 401, code: 'invalid_api_keypair_sign' };
            }
            request.keypairVerified = key.fingerprint;
        }

        return null;
    }

    builtInRoute(request) {
        const entry = this.keys.get(request.headers['x-api-key']);
        if (request.method === 'GET' && request.path === '/api-keys/current/signing-keys') {
            const items = entry.keypairs.map(key => ({ fingerprint: key.fingerprint, algorithm: key.algorithm, status: 'active', createdTimestamp: 1795000000, approvedTimestamp: 1795000300 }));

            return { status: 200, body: { apiVersion: '2026-03-20', requestId: this.newRequestId(), data: { limit: 2, offset: 0, total: items.length, items } } };
        }
        const vaults = /^\/vaults\/(main|test)$/i.exec(request.path);
        if (request.method === 'GET' && vaults) {
            const params = new URLSearchParams(request.query);
            const limit = Number(params.get('limit') || 50);
            const all = this.vaults[vaults[1].toLowerCase()];
            const after = params.get('startingAfter');
            const start = after ? all.findIndex(item => item.id === after) + 1 : 0;
            const items = all.slice(start, start + limit);
            const hasMore = start + limit < all.length;

            return {
                status: 200,
                body: { apiVersion: '2026-03-20', requestId: this.newRequestId(), data: { limit, hasMore, ...(hasMore ? { startingAfter: items[items.length - 1].id } : {}), items } },
            };
        }

        return null;
    }

    async runRoute(request) {
        // A route a test registered wins over the built-in ones.
        const route = this.routes.find(candidate => candidate.method === request.method && candidate.pattern.test(request.path));
        const builtIn = route ? null : this.builtInRoute(request);
        if (!route && !builtIn) {
            return { status: 404, body: errorBody('uri_not_found', 'not found', this.newRequestId()) };
        }
        this.executions.push({ method: request.method, path: request.path, nonce: request.headers['x-api-nonce'] });

        return builtIn || route.handler(request, this);
    }

    /** Serialises an answer and signs it over the request as received. */
    finish(request, answer) {
        const body = Buffer.isBuffer(answer.body) ? answer.body
            : Buffer.from(typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body === undefined ? {} : answer.body), 'utf8');
        const headers = { 'content-type': 'application/json', ...(answer.headers || {}) };
        if (this.signing) {
            Object.assign(headers, signResponse({ request, status: answer.status, body, nowSeconds: this.nowSeconds(), signing: this.signing }));
        }

        return { status: answer.status, headers, body };
    }

    async handle(req, res) {
        const request = await this.readRequest(req);
        this.requests.push(request);
        const now = this.clock();
        const send = response => {
            let out = response;
            if (this.mitm) {
                out = this.mitm({ request, response }) || response;
            }
            res.writeHead(out.status, out.headers);
            res.end(out.body);
        };

        const fault = this.takeFault(request);
        const before = fault && fault.when === 'before' ? fault : null;
        const after = fault && fault.when === 'after' ? fault : null;
        if (before && before.drop) {
            req.socket.destroy();

            return;
        }
        if (before && before.advanceClockMs) {
            this.clock.advance(before.advanceClockMs);
        }

        const refused = this.authenticate(request);
        if (refused) {
            send(this.finish(request, { status: refused.status, body: errorBody(refused.code, refused.code, this.newRequestId()) }));

            return;
        }

        // Replay protection, before the route.
        const entry = this.keys.get(request.headers['x-api-key']);
        const nonce = request.headers['x-api-nonce'];
        const enforce = request.keypairVerified !== null || entry.replay === 'enforce';
        const recordKey = nonce ? `${request.headers['x-api-key']}\u0000${nonce}` : null;
        for (const [key, record] of this.replay) {
            if (now - record.firstAt > REPLAY_RECORD_TTL_MS) {
                this.replay.delete(key);
            }
        }
        const record = recordKey ? this.replay.get(recordKey) : undefined;
        if (record && enforce) {
            if (record.running) {
                const done = await Promise.race([record.done, new Promise(resolve => setTimeout(() => resolve(null), this.inProgressWaitMs))]);
                if (!done) {
                    send(this.finish(request, { status: 409, body: errorBody('duplicate_api_request_in_progress', 'in progress', this.newRequestId()) }));

                    return;
                }
            }
            if (record.answer && this.clock() - record.firstAt <= REPLAY_RESPONSE_WINDOW_MS && record.answer.body.length <= REPLAY_BODY_LIMIT) {
                send(this.finish(request, { ...record.answer, headers: { ...(record.answer.headers || {}), 'x-api-replayed': 'true' } }));

                return;
            }
            send(this.finish(request, { status: 401, body: errorBody('duplicate_api_request', 'duplicate', this.newRequestId()) }));

            return;
        }

        if (before && before.status) {
            if (before.status !== 429 && recordKey) {
                this.replay.set(recordKey, { firstAt: now, running: false, answer: null, done: Promise.resolve(true) });
            }
            send(this.finish(request, { status: before.status, headers: before.headers, body: errorBody(before.code === undefined ? 'unexpected_server_error' : before.code, 'injected', this.newRequestId()) }));

            return;
        }

        let resolveDone;
        const newRecord = { firstAt: now, running: true, answer: null, done: new Promise(resolve => { resolveDone = resolve; }) };
        if (recordKey) {
            this.replay.set(recordKey, newRecord);
        }

        let answer = await this.runRoute(request);
        if (after && after.status) {
            answer = { status: after.status, headers: after.headers, body: errorBody(after.code === undefined ? 'unexpected_server_error' : after.code, 'injected', this.newRequestId()) };
        }
        if (after && after.delayMs) {
            await new Promise(resolve => setTimeout(resolve, after.delayMs));
        }
        if (after && after.advanceClockMs) {
            this.clock.advance(after.advanceClockMs);
        }
        const body = Buffer.isBuffer(answer.body) ? answer.body : Buffer.from(typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body), 'utf8');
        newRecord.answer = { status: answer.status, headers: answer.headers, body };
        newRecord.running = false;
        resolveDone(true);
        if (answer.status === 429 && recordKey) {
            this.replay.delete(recordKey);
        }
        if (after && after.drop) {
            req.socket.destroy();

            return;
        }
        send(this.finish(request, { status: answer.status, headers: answer.headers, body }));
    }
}

/**
 * @param {Object} [options] as for MockGateway
 * @returns {Promise<MockGateway>} listening on 127.0.0.1, its url set
 */
const startMockGateway = options => new MockGateway(options).listen();

/** A fake clock: call it for the time, advance(ms) to move it. */
function fakeClock(startMs) {
    let now = startMs;
    const clock = () => now;
    clock.advance = ms => {
        now += ms;
    };
    clock.set = ms => {
        now = ms;
    };

    return clock;
}

module.exports = {
    MockGateway,
    startMockGateway,
    fakeClock,
    rootPem,
    signResponse,
    responseMessage,
    certificateHeader,
    fingerprintOf,
    ROOT_IDS: Object.fromEntries(Object.entries(ROOTS).map(([name, root]) => [name, root.rootId])),
};
