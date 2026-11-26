'use strict';

/**
 * Checks the params of an API method against its operation's schemas (operations.js) before anything is
 * built, signed or sent: every required field is there, every field has the documented type and, where the
 * document lists them, one of the documented values; a field the operation does not have is refused, at any
 * depth. Nothing is converted or dropped: a request goes out exactly as the caller wrote it, or not at all.
 *
 * Fields left undefined count as absent. null is refused: the document declares no field nullable.
 */

const { ParameterError } = require('./errors');

const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

const EXPECTED = Object.freeze({
    string: 'a string',
    integer: 'an integer',
    boolean: 'true or false',
    object: 'an object',
    array: 'an array',
});

const fail = (code, param, message) => new ParameterError(code, message, { param });

function checkValue(value, schema, where) {
    const expected = schema && has(EXPECTED, schema.type) ? EXPECTED[schema.type] : undefined;
    if (expected === undefined) {
        // A schema this module can't read would check nothing: refuse rather than pass the value.
        throw fail('invalid_param', where, `${where} has no schema the SDK can check`);
    }
    switch (schema.type) {
    case 'string':
        if (typeof value !== 'string') {
            throw fail('invalid_param', where, `${where} must be ${expected}`);
        }
        if (schema.enum && !schema.enum.includes(value)) {
            throw fail('invalid_param', where, `${where} must be one of ${schema.enum.join(', ')}`);
        }
        break;
    case 'integer':
        if (!Number.isSafeInteger(value)) {
            throw fail('invalid_param', where, `${where} must be ${expected}`);
        }
        if (typeof schema.minimum === 'number' && value < schema.minimum) {
            throw fail('invalid_param', where, `${where} must be at least ${schema.minimum}`);
        }
        if (typeof schema.maximum === 'number' && value > schema.maximum) {
            throw fail('invalid_param', where, `${where} must be at most ${schema.maximum}`);
        }
        break;
    case 'boolean':
        if (typeof value !== 'boolean') {
            throw fail('invalid_param', where, `${where} must be ${expected}`);
        }
        break;
    case 'object':
        if (!isPlainObject(value)) {
            throw fail('invalid_param', where, `${where} must be ${expected}`);
        }
        checkFields(value, schema.properties || {}, schema.required || [], `${where}.`);
        break;
    case 'array':
        if (!Array.isArray(value)) {
            throw fail('invalid_param', where, `${where} must be ${expected}`);
        }
        value.forEach((entry, index) => {
            const at = `${where}[${index}]`;
            if (entry === undefined || entry === null) {
                throw fail('invalid_param', at, `${at} can't be empty`);
            }
            checkValue(entry, schema.items, at);
        });
        break;
    }
}

function checkFields(object, properties, required, prefix) {
    for (const key of Object.keys(object)) {
        if (!has(properties, key)) {
            throw fail('unknown_param', `${prefix}${key}`, `${prefix}${key} is not a field the API documents here`);
        }
    }
    for (const name of Object.keys(properties)) {
        const schema = properties[name];
        const where = `${prefix}${name}`;
        const value = object[name];
        if (value === undefined) {
            if (required.includes(name)) {
                throw fail('missing_param', where, `${where} is required`);
            }
            continue;
        }
        if (value === null) {
            throw fail('invalid_param', where, `${where} can't be null; leave it out instead`);
        }
        checkValue(value, schema, where);
    }
}

/**
 * @param {Object} operation an entry of the operation table, with a schema on every param
 * @param {*} params the call's flat params
 * @throws {ParameterError} invalid_params (not a plain object), unknown_param, missing_param or invalid_param;
 *         `param` names the field, nested ones as `recipients[0].amount`. The value itself is never echoed.
 */
function validateParams(operation, params) {
    if (!isPlainObject(params)) {
        throw new ParameterError('invalid_params', `the params of ${operation.operationId} must be a plain object of its fields`);
    }
    const properties = Object.create(null);
    const required = [];
    for (const param of operation.params) {
        properties[param.name] = param.schema;
        if (param.required) {
            required.push(param.name);
        }
    }
    try {
        checkFields(params, properties, required, '');
    } catch (error) {
        if (error instanceof ParameterError) {
            error.message = `${operation.operationId}: ${error.message}`;
        }
        throw error;
    }
}

module.exports = {
    validateParams,
};
