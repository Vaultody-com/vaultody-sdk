<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

use Vaultody\Sdk\Exception\ApiError;
use Vaultody\Sdk\Exception\AuthenticationError;
use Vaultody\Sdk\Exception\ConflictError;
use Vaultody\Sdk\Exception\DuplicateTransferError;
use Vaultody\Sdk\Exception\InvalidRequestError;
use Vaultody\Sdk\Exception\NotFoundError;
use Vaultody\Sdk\Exception\PermissionDeniedError;
use Vaultody\Sdk\Exception\RateLimitError;
use Vaultody\Sdk\Exception\RequestSigningError;
use Vaultody\Sdk\Exception\ServerError;
use Vaultody\Sdk\Verify\Encoding;

/**
 * Reads an API response, already verified, into a result or a typed error
 * (test-vectors/envelope-errors-v1.json).
 */
final class Envelope
{
    /** Error class by code, before the class of the status. */
    public const CLASS_OF_CODE = [
        'api_keypair_required' => RequestSigningError::class,
        'missing_api_keypair_sign' => RequestSigningError::class,
        'missing_api_nonce' => RequestSigningError::class,
        // The gateway's idempotency: the nonce was used before for a different request; never retried.
        'api_nonce_reused' => RequestSigningError::class,
        'unknown_api_keypair_id' => RequestSigningError::class,
        'invalid_api_keypair_sign' => RequestSigningError::class,
        'invalid_api_key' => AuthenticationError::class,
        'invalid_api_sign' => AuthenticationError::class,
        'invalid_api_timestamp' => AuthenticationError::class,
        'missing_authorization_header' => AuthenticationError::class,
        'invalid_data' => InvalidRequestError::class,
        'missing_required_attributes' => InvalidRequestError::class,
        'extra_body_attributes' => InvalidRequestError::class,
        'extra_query_attributes' => InvalidRequestError::class,
        'invalid_api_version' => InvalidRequestError::class,
        'double_spending' => DuplicateTransferError::class,
    ];

    public const CLASS_OF_STATUS = [
        400 => InvalidRequestError::class,
        401 => AuthenticationError::class,
        403 => PermissionDeniedError::class,
        404 => NotFoundError::class,
        409 => ConflictError::class,
        415 => InvalidRequestError::class,
        422 => InvalidRequestError::class,
        429 => RateLimitError::class,
    ];

    /** @return class-string<ApiError> */
    public static function errorClassFor(int $status, ?string $code): string
    {
        if ($code !== null && isset(self::CLASS_OF_CODE[$code])) {
            return self::CLASS_OF_CODE[$code];
        }
        if ($status >= 500 && $status <= 599) {
            return ServerError::class;
        }

        return self::CLASS_OF_STATUS[$status] ?? ApiError::class;
    }

    /** Whether x-api-replayed is exactly "true": the gateway answered a duplicate with the first answer. */
    public static function replayed(array $headers): bool
    {
        $values = Encoding::headerValues($headers, 'x-api-replayed');

        return count($values) === 1 && $values[0] === 'true';
    }

    /**
     * @param array<array-key, mixed> $headers
     * @return array{kind: 'item', item: array<string, mixed>, apiVersion: ?string, requestId: ?string, context: ?string, replayed: bool}
     *       | array{kind: 'page', paging: 'cursor'|'offset', items: list<mixed>, limit: int|float|null, hasMore?: bool, startingAfter?: ?string,
     *               offset?: int|float|null, total?: int|float|null, apiVersion: ?string, requestId: ?string, context: ?string, replayed: bool}
     * @throws ApiError an error status, or a success the SDK can't read
     */
    public static function read(int $status, array $headers, string $body): array
    {
        $replayed = self::replayed($headers);
        $parsed = Json::decode($body);
        $top = $parsed instanceof \stdClass ? $parsed : new \stdClass();
        $meta = [
            'apiVersion' => self::stringOrNull($top->apiVersion ?? null),
            'requestId' => self::stringOrNull($top->requestId ?? null),
            'context' => self::stringOrNull($top->context ?? null),
            'replayed' => $replayed,
        ];

        if ($status >= 200 && $status <= 299) {
            $data = ($top->data ?? null) instanceof \stdClass ? $top->data : null;
            if ($data !== null && ($data->item ?? null) instanceof \stdClass) {
                return ['kind' => 'item', 'item' => Json::toArray($data->item)] + $meta;
            }
            if ($data !== null && is_array($data->items ?? null)) {
                $limit = self::number($data->limit ?? null);
                if (property_exists($data, 'offset') || property_exists($data, 'total')) {
                    return [
                        'kind' => 'page', 'paging' => 'offset', 'items' => Json::toArray($data->items), 'limit' => $limit,
                        'offset' => self::number($data->offset ?? null), 'total' => self::number($data->total ?? null),
                    ] + $meta;
                }

                return [
                    'kind' => 'page', 'paging' => 'cursor', 'items' => Json::toArray($data->items), 'limit' => $limit,
                    'hasMore' => ($data->hasMore ?? null) === true,
                    'startingAfter' => self::stringOrNull($data->startingAfter ?? null),
                ] + $meta;
            }

            throw new ApiError($status, null, null, $meta['requestId'], $meta['apiVersion'], $replayed);
        }

        $error = ($top->error ?? null) instanceof \stdClass ? $top->error : new \stdClass();
        $code = self::stringOrNull($error->code ?? null);
        $class = self::errorClassFor($status, $code);
        $hasDetails = property_exists($error, 'details');

        throw new $class(
            $status,
            $code,
            self::stringOrNull($error->message ?? null),
            $meta['requestId'],
            $meta['apiVersion'],
            $replayed,
            $hasDetails ? Json::toArray($error->details) : null,
            $hasDetails,
        );
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    private static function number(mixed $value): int|float|null
    {
        return is_int($value) || is_float($value) ? $value : null;
    }
}
