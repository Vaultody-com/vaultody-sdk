<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * Reads an answer of GET /api-keys/current/signing-keys, already verified, and says whether the key with a
 * given fingerprint is registered and active (test-vectors/signing-keys-v1.json). No I/O: the caller sends
 * the request and checks the response signature first.
 */
final class SigningKeysResponse
{
    public const ACTIVE = 'active';

    /**
     * @return array{outcome: 'active'|'inactive'|'not_listed'|'refused', fingerprint: string, status: int, requestId: ?string,
     *               keys: list<array{fingerprint: string, algorithm: string, status: string, createdTimestamp: mixed, approvedTimestamp: mixed}>,
     *               error: array{code: string, message: string}|null}
     * @throws UnexpectedResponseError an answer that is neither the list nor a refusal
     */
    public static function read(int $status, string $body, string $fingerprint): array
    {
        $result = ['fingerprint' => $fingerprint, 'status' => $status, 'requestId' => null, 'keys' => [], 'error' => null];

        if ($status === 401 || $status === 403) {
            $parsed = self::json($body, $status);
            $error = is_array($parsed['error'] ?? null) ? $parsed['error'] : [];
            $result['requestId'] = is_string($parsed['requestId'] ?? null) ? $parsed['requestId'] : null;
            $result['error'] = [
                'code' => is_string($error['code'] ?? null) ? $error['code'] : 'unknown',
                'message' => is_string($error['message'] ?? null) ? $error['message'] : '',
            ];

            return ['outcome' => 'refused'] + $result;
        }

        if ($status !== 200) {
            $parsed = json_decode($body, true);
            $code = is_array($parsed) && is_string($parsed['error']['code'] ?? null) ? $parsed['error']['code'] : null;
            $requestId = is_array($parsed) && is_string($parsed['requestId'] ?? null) ? $parsed['requestId'] : null;
            throw new UnexpectedResponseError(sprintf('the API answered %d%s', $status, $code !== null ? ' (' . $code . ')' : ''), $status, $requestId, $code);
        }

        $parsed = self::json($body, $status);
        $items = $parsed['data']['items'] ?? null;
        if (!is_array($items) || !array_is_list($items)) {
            throw new UnexpectedResponseError('the API answered 200 without a list of signing keys', $status);
        }
        $result['requestId'] = is_string($parsed['requestId'] ?? null) ? $parsed['requestId'] : null;
        foreach ($items as $item) {
            if (!is_array($item)) {
                continue;
            }
            $result['keys'][] = [
                'fingerprint' => self::text($item['fingerprint'] ?? null),
                'algorithm' => self::text($item['algorithm'] ?? null),
                'status' => self::text($item['status'] ?? null),
                'createdTimestamp' => $item['createdTimestamp'] ?? null,
                'approvedTimestamp' => $item['approvedTimestamp'] ?? null,
            ];
        }

        $outcome = 'not_listed';
        foreach ($result['keys'] as $key) {
            if ($key['fingerprint'] === $fingerprint) {
                $outcome = $key['status'] === self::ACTIVE ? 'active' : 'inactive';
                break;
            }
        }

        return ['outcome' => $outcome] + $result;
    }

    /** @return array<array-key, mixed> */
    private static function json(string $body, int $status): array
    {
        try {
            $parsed = json_decode($body, true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            throw new UnexpectedResponseError(sprintf('the API answered %d with a body that is not JSON', $status), $status);
        }

        return is_array($parsed) ? $parsed : [];
    }

    private static function text(mixed $value): string
    {
        return match (true) {
            is_string($value) => $value,
            $value === null => 'null',
            is_bool($value) => $value ? 'true' : 'false',
            is_scalar($value) => (string) $value,
            default => (string) json_encode($value),
        };
    }
}
