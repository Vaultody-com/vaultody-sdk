'use strict';

/**
 * The client's low-level calls, for the SDK's own tests and conformance runs only. They take any operationId,
 * or an operation entry of the table's shape, and do not check params against the API reference as the API
 * methods do, so they are not part of the SDK's API: the client does not expose them and the package does not
 * export this module (package.json "exports"). Like the client's `unsupported` options, they may change without
 * notice.
 *
 *   const { request, paginate } = require('../src/internal');
 *   await request(client, 'listVaults', { networkType: 'main' }, { context });
 *   for await (const vault of paginate(client, 'listVaults', { networkType: 'main' }, { limit: 2 })) { ... }
 */

const { lowLevelCalls } = require('./client');

/**
 * One call through the client's whole pipeline: { item, meta } or a Page.
 *
 * @param {import('./client').Vaultody} client
 * @param {string|Object} operationId
 * @param {Object} [params]
 * @param {{ context?: string, signal?: AbortSignal }} [options]
 */
const request = (client, operationId, params, options) => lowLevelCalls(client).request(operationId, params, options);

/**
 * Every item of a list operation, page by page: a Pager.
 *
 * @param {import('./client').Vaultody} client
 * @param {string|Object} operationId
 * @param {Object} [params]
 * @param {{ limit?: number, maxItems?: number, context?: string, signal?: AbortSignal }} [options]
 */
const paginate = (client, operationId, params, options) => lowLevelCalls(client).paginate(operationId, params, options);

module.exports = {
    request,
    paginate,
};
