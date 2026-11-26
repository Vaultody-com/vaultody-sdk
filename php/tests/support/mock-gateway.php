<?php

declare(strict_types=1);

// A stand-in for the API gateway, run with PHP's built-in server (php -S) by MockGateway. It checks the
// request signatures, applies the gateway's replay rules (the first answer again within 3 s, later
// duplicate_api_request; a 429 forgets the nonce) and signs its answers like the gateway, with the TEST-ONLY
// keys of test-vectors/v1.json: pod key 1, certified by the "current" test root for an hour from a minute ago (a
// certificate may be valid for at most an hour).
//
// Answers come from a script the test writes (state.json): each entry is { status, body, headers, sign:
// yes|no|tamper|partial, delayMs }. The vault lists and the signing keys are served from state.json too;
// routes (path => list of entries) answers a given path first, for any of them.
// Every request received is appended to requests.jsonl.

require __DIR__ . '/../../src/autoload.php';

use Vaultody\Sdk\Verify\Keys;
use Vaultody\Sdk\Verify\SigningKey;
use Vaultody\Sdk\Verify\UsageError;

$dir = (string) getenv('MOCK_DIR');
$vectors = __DIR__ . '/../../../test-vectors';
$v1 = json_decode((string) file_get_contents($vectors . '/v1.json'), true);
$full = json_decode((string) file_get_contents($vectors . '/request-full-v1.json'), true);

$method = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];
$queryAt = strpos($uri, '?');
$path = $queryAt === false ? $uri : substr($uri, 0, $queryAt);
$query = $queryAt === false ? '' : substr($uri, $queryAt + 1);
$requestBody = (string) file_get_contents('php://input');
$headers = array_change_key_case(getallheaders(), CASE_LOWER);
$header = static fn (string $name): string => (string) ($headers[$name] ?? '');

// The HMAC v2 check, written out here rather than through the SDK, so a mistake there can't hide here.
$credentials = $full['credentials'];
$hmacMessage = implode("\n", ['v2', $header('x-api-timestamp'), $method, $path, $header('x-api-version'), $header('x-api-passphrase'), $header('x-api-nonce'), $query, $requestBody]);
$hmacValid = $header('x-api-key') === $credentials['apiKey']
    && $header('x-api-sign-version') === '2'
    && hash_equals(base64_encode(hash_hmac('sha256', $hmacMessage, (string) base64_decode($credentials['apiSecret'], true), true)), $header('x-api-sign'));

$keypairValid = null;
if ($header('x-api-keypair-id') !== '') {
    $registered = array_map(static fn (array $key): SigningKey => SigningKey::read($key['publicKeySpkiPem'], 'public'), array_values($full['keys']));
    // Over the request as received, under the x-api-key it came with (line 2 of the key-pair string).
    try {
        $verdict = Keys::verifyKeypairRequest($registered, [
            'apiKey' => $header('x-api-key'), 'timestamp' => $header('x-api-timestamp'), 'method' => $method, 'path' => $path,
            'apiVersion' => $header('x-api-version'), 'passphrase' => $header('x-api-passphrase'), 'nonce' => $header('x-api-nonce'),
            'query' => $query, 'body' => $requestBody,
        ], $header('x-api-keypair-id'), $header('x-api-keypair-sign'));
        $keypairValid = $verdict['valid'];
    } catch (UsageError) {
        // No x-api-key, or one that is not one line: nothing to check the signature under.
        $keypairValid = false;
    }
}

/** The four response-signing headers over this request and the given answer. */
$sign = static function (int $status, string $body) use ($v1, $method, $path, $query, $requestBody, $header): array {
    $pair = sodium_crypto_sign_seed_keypair((string) hex2bin($v1['keys']['podKeys']['pod1']['seedHex']));
    $publicKey = sodium_crypto_sign_publickey($pair);
    $now = time();
    $root = $v1['keys']['roots']['current'];
    $cert = implode("\n", ['vaultody-response-key-v1', $root['rootId'], base64_encode($publicKey), substr(hash('sha256', $publicKey), 0, 32), (string) ($now - 60), (string) ($now + 3540)]);
    openssl_sign($cert, $rootSignature, openssl_pkey_get_private($root['privateKeyPkcs8Pem']), OPENSSL_ALGO_SHA256);
    $message = implode("\n", ['vaultody-response-v1', (string) $now, (string) $status, $method, $path, $query, hash('sha256', $requestBody), $header('x-api-sign'), $header('x-api-keypair-sign')]) . "\n" . $body;

    return [
        'x-api-response-sign' => base64_encode(sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($pair))),
        'x-api-response-timestamp' => (string) $now,
        'x-api-response-sign-version' => '1',
        'x-api-response-cert' => base64_encode($cert) . '.' . base64_encode($rootSignature),
    ];
};

$envelope = static fn (array $data): string => json_encode(['apiVersion' => '2026-03-20', 'requestId' => 'mock-' . bin2hex(random_bytes(4)), 'data' => $data], JSON_UNESCAPED_SLASHES);
$errorBody = static fn (string $code): string => json_encode(['apiVersion' => '2026-03-20', 'requestId' => 'mock-error', 'error' => ['code' => $code, 'message' => 'TEST ' . $code]]);

$lock = fopen($dir . '/lock', 'c');
flock($lock, LOCK_EX);
$state = json_decode((string) file_get_contents($dir . '/state.json'), true);
$nonce = $header('x-api-nonce');
$now = microtime(true);
file_put_contents($dir . '/requests.jsonl', json_encode([
    'method' => $method, 'uri' => $uri, 'path' => $path, 'query' => $query, 'body' => $requestBody, 'nonce' => $nonce,
    'timestamp' => $header('x-api-timestamp'), 'apiVersion' => $header('x-api-version'), 'userAgent' => $header('user-agent'),
    'contentType' => $header('content-type'), 'keypairId' => $header('x-api-keypair-id'), 'hmacValid' => $hmacValid, 'keypairValid' => $keypairValid,
    'at' => $now,
], JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND);

$answer = null;
$replayed = false;
if (!$hmacValid || $keypairValid === false) {
    $answer = ['status' => 401, 'body' => $errorBody($hmacValid ? 'invalid_api_keypair_sign' : 'invalid_api_sign')];
} elseif ($nonce !== '' && isset($state['nonces'][$nonce])) {
    $seen = $state['nonces'][$nonce];
    if ($now - $seen['at'] <= 3.0) {
        $answer = $seen['answer'];
        $answer['delayMs'] = 0;
        $replayed = true;
    } else {
        $answer = ['status' => 401, 'body' => $errorBody('duplicate_api_request')];
    }
} elseif (($state['routes'][$path] ?? []) !== []) {
    // A scripted answer for one path, before what the mock serves on its own (the vault lists, signing keys).
    $answer = array_shift($state['routes'][$path]);
    if (is_array($answer['body'] ?? null)) {
        $answer['body'] = $envelope($answer['body']);
    }
} elseif (preg_match('#^/vaults/(main|test)$#', $path, $match) === 1) {
    parse_str($query, $params);
    $items = $state['vaults'][$match[1]] ?? [];
    $limit = (int) ($params['limit'] ?? 50);
    $start = 0;
    if (isset($params['startingAfter'])) {
        foreach ($items as $index => $item) {
            if ($item['id'] === $params['startingAfter']) {
                $start = $index + 1;
            }
        }
    }
    $page = array_slice($items, $start, $limit);
    $answer = [
        'status' => 200,
        'body' => $envelope(['limit' => $limit, 'startingAfter' => $params['startingAfter'] ?? null, 'hasMore' => $start + $limit < count($items), 'items' => $page]),
        'sign' => $state['signVaults'] ?? 'yes',
    ];
} elseif ($path === '/api-keys/current/signing-keys') {
    $answer = ['status' => 200, 'body' => $envelope(['limit' => 2, 'offset' => 0, 'total' => count($state['signingKeys'] ?? []), 'items' => $state['signingKeys'] ?? []]), 'sign' => $state['signSigningKeys'] ?? 'yes'];
} else {
    $answer = array_shift($state['script']) ?? ['status' => 500, 'body' => $errorBody('mock_script_empty')];
    if (is_array($answer['body'] ?? null)) {
        $answer['body'] = $envelope($answer['body']);
    }
}

// The gateway forgets the nonce of a request it refused with 429, so a resend of it is a new request.
if (!$replayed && $nonce !== '' && $answer['status'] !== 429 && !isset($state['nonces'][$nonce])) {
    $state['nonces'][$nonce] = ['at' => $now, 'answer' => $answer];
}
file_put_contents($dir . '/state.json', json_encode($state, JSON_UNESCAPED_SLASHES));
flock($lock, LOCK_UN);
fclose($lock);

if (($answer['delayMs'] ?? 0) > 0) {
    usleep($answer['delayMs'] * 1000);
}

$status = $answer['status'] ?? 200;
$body = (string) ($answer['body'] ?? '');
$signature = $sign($status, $body);
switch ($answer['sign'] ?? 'yes') {
    case 'no':
        $signature = [];
        break;
    case 'partial':
        unset($signature['x-api-response-cert']);
        break;
    case 'tamper':
        // Changed on the way, after the gateway signed it.
        $body .= ' ';
        break;
}

http_response_code($status);
header('Content-Type: application/json');
header_remove('X-Powered-By');
foreach ($signature + ($answer['headers'] ?? []) as $name => $value) {
    header($name . ': ' . $value);
}
if ($replayed) {
    header('x-api-replayed: true');
}
echo $body;
