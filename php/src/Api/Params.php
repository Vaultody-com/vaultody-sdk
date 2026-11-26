<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Api;

use Vaultody\Sdk\Exception\ParameterError;

/**
 * Checks a method's flat params and its call options against the operation table (Operations::ALL), which
 * follows the published OpenAPI document, before anything is signed or sent:
 *
 *  - a param the operation does not document is refused (unknown_param), at any depth of a body object;
 *  - a required one that is missing or null is refused (missing_param); an optional one that is null is left
 *    out, as if not given;
 *  - a value of the wrong JSON type is refused (invalid_param): strings stay strings (amounts, ids, and
 *    path values such as an XRP tag), integers integers, booleans booleans; limit is 1 to the operation's
 *    maximum;
 *  - a value outside the list the operation documents for a param (blockchain, network, feePriority, ...)
 *    is refused (invalid_param), matched exactly: the SDK pins the API version, so the values that version
 *    takes are known, and a typo such as 'MAIN' is caught before sending. Each operation has its own list
 *    (prepareStrategy is minimize-dust in createMultipleTransfer but minimize_dust in
 *    estimateTransactionFeeByAssetId). The error names the field ($param, nested ones as recipients[0].amount, as
 *    in Node and Python), never the value given;
 *  - an unknown call option is refused (unknown_option). The one call option is `context`, a string the API
 *    returns unchanged.
 *
 * @internal
 */
final class Params
{
    public const OPTIONS = ['context'];

    /**
     * @param array<string, mixed> $operation an Operations::ALL entry
     * @param array<array-key, mixed> $params
     * @param array<array-key, mixed> $options
     * @return array<string, mixed> what the transport sends: the params as given (nulls left out, empty
     *         objects as JSON objects), the page size when a list is asked for without one, and context
     * @throws ParameterError
     */
    public static function prepare(array $operation, array $params, array $options): array
    {
        $operationId = $operation['operationId'];
        foreach ($options as $name => $value) {
            if (!in_array($name, self::OPTIONS, true)) {
                throw new ParameterError('unknown_option', sprintf('%s takes no option %s; the options are: %s', $operationId, json_encode($name), implode(', ', self::OPTIONS)));
            }
        }
        $context = $options['context'] ?? null;
        if ($context !== null && !is_string($context)) {
            throw new ParameterError('invalid_option', 'the context option must be a string');
        }

        $documented = [];
        foreach ($operation['params'] as $param) {
            $documented[$param['name']] = $param;
        }

        $sent = [];
        foreach ($params as $name => $value) {
            if (!is_string($name) || !isset($documented[$name])) {
                $hint = $name === 'context' ? ': context is a call option, pass it in the second argument' : '';
                throw new ParameterError('unknown_param', sprintf('%s takes no parameter %s%s', $operationId, json_encode($name), $hint), is_string($name) ? $name : (string) $name);
            }
            if ($value === null) {
                continue;
            }
            $sent[$name] = self::value($documented[$name]['type'], $value, $operationId, $name);
        }
        foreach ($documented as $name => $param) {
            if ($param['required'] && !array_key_exists($name, $sent)) {
                throw new ParameterError('missing_param', sprintf('%s needs the parameter %s', $operationId, $name), $name);
            }
        }

        if ($operation['paging'] !== 'none' && isset($documented['limit']) && !isset($sent['limit']) && $operation['maxLimit'] !== null) {
            $sent['limit'] = $operation['maxLimit'];
        }
        if ($context !== null) {
            $sent['context'] = $context;
        }

        return $sent;
    }

    /**
     * @param string|array<string, mixed> $type
     * @throws ParameterError
     */
    private static function value(string|array $type, mixed $value, string $operationId, string $at): mixed
    {
        $name = is_string($type) ? $type : $type['type'];
        $wrong = static fn (string $what, ?string $param = null): ParameterError => new ParameterError('invalid_param', sprintf('%s: %s must be %s', $operationId, $param ?? $at, $what), $param ?? $at);

        switch ($name) {
            case 'string':
                if (!is_string($value)) {
                    throw $wrong('a string');
                }
                // Exactly one of the values the operation documents (case included); the message names the
                // field and the documented values, never the value given.
                if (is_array($type) && isset($type['enum']) && !in_array($value, $type['enum'], true)) {
                    throw $wrong('one of the documented values: ' . implode(', ', $type['enum']));
                }

                return $value;
            case 'boolean':
                if (!is_bool($value)) {
                    throw $wrong('a boolean');
                }

                return $value;
            case 'integer':
                if (!is_int($value)) {
                    throw $wrong('an integer');
                }
                if (is_array($type) && ((isset($type['minimum']) && $value < $type['minimum']) || (isset($type['maximum']) && $value > $type['maximum']))) {
                    throw $wrong(sprintf('from %d to %d', $type['minimum'] ?? PHP_INT_MIN, $type['maximum'] ?? PHP_INT_MAX));
                }

                return $value;
            case 'array':
                if (!is_array($value) || !array_is_list($value)) {
                    throw $wrong('a list');
                }
                $items = [];
                foreach ($value as $index => $item) {
                    if ($item === null) {
                        throw $wrong('an item, not null', sprintf('%s[%d]', $at, $index));
                    }
                    $items[] = self::value($type['items'], $item, $operationId, sprintf('%s[%d]', $at, $index));
                }

                return $items;
            case 'object':
                if (!is_array($value) || ($value !== [] && array_is_list($value))) {
                    throw $wrong('an object (an array with string keys)');
                }
                $object = [];
                foreach ($value as $key => $field) {
                    if (!is_string($key) || !isset($type['properties'][$key])) {
                        throw new ParameterError('unknown_param', sprintf('%s: %s has no field %s', $operationId, $at, json_encode($key)), sprintf('%s.%s', $at, $key));
                    }
                    if ($field === null) {
                        continue;
                    }
                    $object[$key] = self::value($type['properties'][$key], $field, $operationId, $at . '.' . $key);
                }
                foreach ($type['required'] as $required) {
                    if (!array_key_exists($required, $object)) {
                        throw new ParameterError('missing_param', sprintf('%s: %s needs the field %s', $operationId, $at, $required), sprintf('%s.%s', $at, $required));
                    }
                }

                // An empty PHP array would be sent as a JSON list.
                return $object === [] ? new \stdClass() : $object;
        }

        throw new \LogicException(sprintf('the operation table names an unknown type %s', $name));
    }
}
