<?php

declare(strict_types=1);

// Shared helpers for the vector runners: loading a set from test-vectors/ and the request / response shapes
// the vectors use. Loaded once by run.php.

const VECTORS_DIR = __DIR__ . '/../../../test-vectors';

/** @return array<string, mixed> */
function vectors(string $name): array
{
    static $cache = [];

    return $cache[$name] ??= json_decode((string) file_get_contents(VECTORS_DIR . '/' . $name), true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
}

/** A DER SubjectPublicKeyInfo, base64, as PEM. */
function spki_pem(string $derBase64): string
{
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split($derBase64, 64, "\n") . "-----END PUBLIC KEY-----\n";
}

/** The test-only roots of v1.json, by slot name, as PEM. */
function root_pem(string $name): string
{
    return spki_pem(vectors('v1.json')['keys']['roots'][$name]['publicKeySpkiDerBase64']);
}

/**
 * A vector request (path and query kept apart, body base64) as the verifier takes it.
 *
 * @param array<string, mixed> $request
 * @return array{method: string, url: string, body: string, apiSign: string, keypairSign: string}
 */
function request_of(array $request): array
{
    return [
        'method' => $request['method'],
        'url' => $request['query'] === '' ? $request['path'] : $request['path'] . '?' . $request['query'],
        'body' => (string) base64_decode($request['bodyBase64'], true),
        'apiSign' => $request['apiSign'],
        'keypairSign' => $request['keypairSign'],
    ];
}

/**
 * @param array<string, mixed> $response
 * @return array{status: int, headers: array<string, mixed>, body: string}
 */
function response_of(array $response, ?array $headers = null): array
{
    return [
        'status' => $response['status'],
        'headers' => $headers ?? $response['headers'],
        'body' => (string) base64_decode($response['bodyBase64'], true),
    ];
}

/** Runs $run and returns the exception it throws, or fails the test when it throws none. */
function thrown(callable $run, string $class): Throwable
{
    try {
        $run();
    } catch (Throwable $error) {
        if (!$error instanceof $class) {
            throw new RuntimeException(sprintf('expected %s, got %s: %s', $class, get_class($error), $error->getMessage()), 0, $error);
        }

        return $error;
    }
    throw new RuntimeException('expected ' . $class . ', nothing was thrown');
}
