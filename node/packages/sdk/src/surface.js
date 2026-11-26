'use strict';

/**
 * What this SDK really exposes, for scripts/coverage.mjs: the methods of the client found by walking it,
 * and the operation table. A method counts only when it is bound to an operation, through its
 * `operationId` property.
 */

const { API_VERSION, SDK_VERSION } = require('./version');
const { OPERATIONS } = require('./operations');

/**
 * @param {Object|null} client a client instance whose namespaces hold the API methods (null: none)
 * @returns {Array<{ namespace: string, method: string, operationId: string }>}
 */
function clientMethods(client) {
    if (!client) {
        return [];
    }

    const methods = [];
    for (const namespace of Object.keys(client).sort()) {
        const group = client[namespace];
        if (!group || typeof group !== 'object') {
            continue;
        }
        let proto = group;
        const names = new Set();
        while (proto && proto !== Object.prototype) {
            Object.getOwnPropertyNames(proto).forEach(name => names.add(name));
            proto = Object.getPrototypeOf(proto);
        }
        for (const method of [...names].sort()) {
            const fn = method === 'constructor' ? null : group[method];
            if (typeof fn === 'function' && typeof fn.operationId === 'string') {
                methods.push({ namespace, method, operationId: fn.operationId });
            }
        }
    }

    return methods;
}

/**
 * @param {Object|null} [client]
 * @returns {{ language: 'node', sdkVersion: string, apiVersion: string, clients: { node: Array<Object> }, operations: Array<Object> }}
 */
function describeSurface(client = null) {
    return {
        language: 'node',
        sdkVersion: SDK_VERSION,
        apiVersion: API_VERSION,
        clients: { node: clientMethods(client) },
        // Each param as the contract states it: name, place and whether it is required. The schemas the methods
        // check values against are compared with the document by test/contract.test.js.
        operations: OPERATIONS.map(({ operationId, method, path, params }) => ({
            operationId,
            method,
            path,
            params: params.map(param => ({ name: param.name, in: param.in, required: param.required })),
        })),
    };
}

module.exports = {
    clientMethods,
    describeSurface,
};
