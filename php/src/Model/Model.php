<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/**
 * The base of every answer model. A model is a typed view of one object of an answer: each documented
 * field is a readonly property, and $raw keeps the object exactly as it came, undocumented fields included
 * (the API adds fields without a new version).
 *
 * Reading never throws on what the server sends: a field that is missing, or whose JSON type differs from
 * the documented one, is null in its property (an empty list for a list) and stays readable in $raw.
 * Amounts stay strings. The answer was verified (signature, vault addresses) before any model is built.
 *
 * A subclass declares its fields as promoted constructor parameters, typed and nullable, followed by
 * `array $raw = [], ?Meta $meta = null`; list fields name their element class in LISTS.
 */
abstract class Model implements \JsonSerializable
{
    /** @var array<string, class-string<Model>> the element class of each list field */
    protected const LISTS = [];

    /** @var array<class-string, array<string, array{types: list<string>, nullable: bool}>> */
    private static array $fields = [];

    /**
     * @param array<string, mixed> $raw the object as it came, every field kept
     * @param ?Meta $meta set on the object a method returns: request id, API version, whether the response
     *        signature was verified, the status of each address check; null on the objects inside it
     */
    public function __construct(
        public readonly array $raw = [],
        public readonly ?Meta $meta = null,
    ) {
    }

    /**
     * Builds the model from one object of an answer.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data, ?Meta $meta = null): static
    {
        $arguments = [];
        foreach (self::fieldsOf(static::class) as $name => $field) {
            $arguments[$name] = self::read($data[$name] ?? null, $field, static::LISTS[$name] ?? null);
        }
        $arguments['raw'] = $data;
        $arguments['meta'] = $meta;

        return new static(...$arguments);
    }

    /**
     * The documented fields of a model class and the types each accepts, from its constructor.
     *
     * @param class-string<Model> $class
     * @return array<string, array{types: list<string>, nullable: bool}>
     */
    public static function fieldsOf(string $class): array
    {
        if (isset(self::$fields[$class])) {
            return self::$fields[$class];
        }
        $fields = [];
        $constructor = (new \ReflectionClass($class))->getConstructor();
        foreach ($constructor?->getParameters() ?? [] as $parameter) {
            $name = $parameter->getName();
            if ($name === 'raw' || $name === 'meta') {
                continue;
            }
            $type = $parameter->getType();
            $named = $type instanceof \ReflectionUnionType ? $type->getTypes() : [$type];
            $types = [];
            foreach ($named as $one) {
                if ($one instanceof \ReflectionNamedType && $one->getName() !== 'null') {
                    $types[] = $one->getName();
                }
            }
            $fields[$name] = ['types' => $types, 'nullable' => $type === null || $type->allowsNull()];
        }

        return self::$fields[$class] = $fields;
    }

    /** @return class-string<Model>|null the element class of a list field */
    public static function listClassOf(string $class, string $field): ?string
    {
        return $class::LISTS[$field] ?? null;
    }

    /** @return array<string, mixed> the object as it came */
    public function jsonSerialize(): array
    {
        return $this->raw;
    }

    /**
     * @param array{types: list<string>, nullable: bool} $field
     * @param class-string<Model>|null $listOf
     */
    private static function read(mixed $value, array $field, ?string $listOf): mixed
    {
        foreach ($field['types'] as $type) {
            switch ($type) {
                case 'string':
                    if (is_string($value)) {
                        return $value;
                    }
                    break;
                case 'int':
                    if (is_int($value)) {
                        return $value;
                    }
                    break;
                case 'bool':
                    if (is_bool($value)) {
                        return $value;
                    }
                    break;
                case 'array':
                    if ($listOf !== null) {
                        if (!is_array($value) || !array_is_list($value)) {
                            break;
                        }
                        $items = [];
                        foreach ($value as $item) {
                            // An element that is not an object has no model; it stays in $raw.
                            if (is_array($item) && ($item === [] || !array_is_list($item))) {
                                $items[] = $listOf::fromArray($item);
                            }
                        }

                        return $items;
                    }
                    if (is_array($value)) {
                        return $value;
                    }
                    break;
                default:
                    if (is_subclass_of($type, self::class) && is_array($value) && ($value === [] || !array_is_list($value))) {
                        return $type::fromArray($value);
                    }
            }
        }

        return $field['nullable'] ? null : [];
    }
}
