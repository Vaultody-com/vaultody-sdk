'use strict';

/**
 * The request target (path and query) of a call, built so it is exactly what goes on the request line and
 * what is signed (test-vectors/path-encoding-v1.json).
 */

const { ParameterError } = require('./errors');

const UNRESERVED = /[A-Za-z0-9\-._~]/;

/**
 * Every UTF-8 byte outside the RFC 3986 unreserved set as %XX, uppercase hex, "/" included.
 *
 * @param {string} text
 * @returns {string}
 * @throws {URIError} for text with no UTF-8 form (a lone surrogate)
 */
function percentEncode(text) {
    if (!text.isWellFormed()) {
        throw new URIError('not valid Unicode');
    }
    let out = '';
    for (const byte of Buffer.from(text, 'utf8')) {
        const char = String.fromCharCode(byte);
        out += UNRESERVED.test(char) ? char : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    }

    return out;
}

function pathValue(name, value) {
    if (value === undefined || value === null) {
        throw new ParameterError('missing_path_param', `${name} is required`);
    }
    let text;
    if (typeof value === 'string') {
        text = value;
    } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
        text = String(value);
    } else {
        throw new ParameterError('invalid_path_param', `${name} must be a string or an integer`);
    }
    // An empty segment, or a dot segment a URL would remove, changes the path that is signed.
    if (text === '' || text === '.' || text === '..' || !text.isWellFormed()) {
        throw new ParameterError('invalid_path_param', `${name} must be a non-empty value other than "." and ".."`);
    }

    return percentEncode(text);
}

function queryValue(name, value) {
    if (typeof value === 'string') {
        if (!value.isWellFormed()) {
            throw new ParameterError('invalid_query_param', `${name} is not valid Unicode`);
        }

        return percentEncode(value);
    }
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    if (typeof value === 'number' && Number.isSafeInteger(value)) {
        return String(value);
    }

    throw new ParameterError('invalid_query_param', `${name} must be a string, an integer or a boolean`);
}

/**
 * @param {string} template the operation path, such as "/vaults/{vaultId}/utxos"
 * @param {Object} pathParams name → string or integer
 * @param {Array<[string, *]>} [query] name/value pairs in the order to send; a null or undefined value
 *        leaves the pair out
 * @returns {string} path and query, such as "/vaults/abc/utxos?limit=10"
 * @throws {ParameterError} missing_path_param, invalid_path_param or invalid_query_param
 */
function buildRequestTarget(template, pathParams, query = []) {
    const params = pathParams || {};
    const path = template.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name) => pathValue(name, Object.prototype.hasOwnProperty.call(params, name) ? params[name] : undefined));
    const pairs = query
        .filter(([, value]) => value !== null && value !== undefined)
        .map(([name, value]) => `${percentEncode(name)}=${queryValue(name, value)}`);

    return pairs.length === 0 ? path : `${path}?${pairs.join('&')}`;
}

module.exports = {
    percentEncode,
    buildRequestTarget,
};
