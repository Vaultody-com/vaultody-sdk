'use strict';

/**
 * Turns an operation and one flat params object into the request: the target (path and query) exactly as
 * sent and signed, and the body bytes. The operation table says where each param goes; a param the operation
 * does not have is refused rather than dropped, so a misspelt name never silently changes a request.
 */

const { buildRequestTarget } = require('./requestTarget');
const { ParameterError } = require('./errors');

// The gateway reads request bodies up to this size; a larger one could not be bound to its response.
const MAX_BODY_BYTES = 1024 * 1024;

const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

/**
 * @param {Object} operation an entry of the operation table
 * @param {Object} params path, query and body fields together; undefined values are left out
 * @param {{ context?: string }} [options] context: a value of the caller's own the API returns unchanged (in
 *        the query of a GET, in the body of a POST or PUT)
 * @returns {{ method: string, target: string, path: string, query: string, bodyText: string, body: Buffer|null }}
 * @throws {ParameterError} unknown_param, missing_path_param, invalid_path_param, invalid_query_param,
 *         invalid_context, body_too_large
 */
function buildRequest(operation, params = {}, { context } = {}) {
    if (!isPlainObject(params)) {
        throw new ParameterError('invalid_params', 'params must be a plain object of the operation\'s fields');
    }
    const declared = new Map(operation.params.map(param => [param.name, param]));
    for (const name of Object.keys(params)) {
        if (!declared.has(name)) {
            throw new ParameterError('unknown_param', `${operation.operationId} has no parameter ${name}`);
        }
    }
    if (context !== undefined && context !== null && typeof context !== 'string') {
        throw new ParameterError('invalid_context', 'context must be a string');
    }

    const pathParams = {};
    const query = [];
    const item = {};
    for (const [name, value] of Object.entries(params)) {
        if (value === undefined) {
            continue;
        }
        const where = declared.get(name).in;
        if (where === 'path') {
            pathParams[name] = value;
        } else if (where === 'body') {
            item[name] = value;
        }
    }
    // Query pairs go in the table's order, so one call always signs the same target.
    for (const param of operation.params) {
        if (param.in === 'query' && params[param.name] !== undefined) {
            query.push([param.name, params[param.name]]);
        }
    }

    const hasBody = operation.method === 'POST' || operation.method === 'PUT';
    if (!hasBody && context !== undefined && context !== null) {
        query.push(['context', context]);
    }

    const target = buildRequestTarget(operation.path, pathParams, query);
    const queryAt = target.indexOf('?');
    let bodyText = '';
    if (hasBody) {
        bodyText = JSON.stringify(context === undefined || context === null ? { data: { item } } : { context, data: { item } });
        if (Buffer.byteLength(bodyText, 'utf8') > MAX_BODY_BYTES) {
            throw new ParameterError('body_too_large', `the request body is larger than ${MAX_BODY_BYTES} bytes`);
        }
    }

    return {
        method: operation.method,
        target,
        path: queryAt === -1 ? target : target.slice(0, queryAt),
        query: queryAt === -1 ? '' : target.slice(queryAt + 1),
        bodyText,
        body: hasBody ? Buffer.from(bodyText, 'utf8') : null,
    };
}

module.exports = {
    MAX_BODY_BYTES,
    buildRequest,
};
