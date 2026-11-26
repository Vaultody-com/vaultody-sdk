'use strict';

// test-vectors/transport-errors-v1.json, the Node rows: what fetch throws → may the request have been sent.

const assert = require('node:assert/strict');
const net = require('node:net');
const { describe, it } = require('node:test');

const { classifyTransportError } = require('../src/transportErrors');
const { load } = require('./vectors');

const VECTORS = load('transport-errors-v1.json');

/** Rebuilds the error a vector describes as real Error objects, the way undici nests them. */
function build(description) {
    const { name, message = '', code, cause, errors } = description;
    const error = errors
        ? new AggregateError(errors.map(build), message)
        : name === 'TypeError' ? new TypeError(message) : new Error(message);
    if (!errors && name !== 'TypeError' && name !== 'Error') {
        error.name = name;
    }
    if (code !== undefined) {
        error.code = code;
    }
    if (cause !== undefined) {
        error.cause = build(cause);
    }

    return error;
}

describe('test-vectors/transport-errors-v1.json (node)', () => {
    for (const vector of VECTORS.node) {
        it(vector.name, () => {
            assert.deepEqual(classifyTransportError(build(vector.error)), vector.expected);
        });
    }

    it('a real refused connection is not sent', async () => {
        // A port that was just free: nothing listens on it any more.
        const server = net.createServer();
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const { port } = server.address();
        await new Promise(resolve => server.close(resolve));

        let error;
        try {
            await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(5000) });
        } catch (e) {
            error = e;
        }
        assert.ok(error);
        assert.deepEqual(classifyTransportError(error), { sent: false });
    });

    it('anything that is not an error is unknown', () => {
        for (const value of [undefined, null, 'ECONNREFUSED', 42]) {
            assert.deepEqual(classifyTransportError(value), { sent: 'unknown' });
        }
    });
});
