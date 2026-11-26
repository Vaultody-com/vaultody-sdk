<?php

declare(strict_types=1);

// test-vectors/request-hmac-v2.json and request-full-v1.json, generated with the gateway's own apiSign and
// RequestKeypair: the HMAC v2 string and signature, the secrets refused, and every authentication header of
// a request, with and without a key pair.

use Vaultody\Sdk\Verify\Keys;
use Vaultody\Sdk\Verify\SigningKey;
use Vaultody\Sdk\Verify\UsageError;

$hmac = vectors('request-hmac-v2.json');
$full = vectors('request-full-v1.json');
$tests = [];

foreach ($hmac['cases'] as $vector) {
    $tests['request-hmac-v2.json ' . $vector['name']] = static function () use ($vector): void {
        ['secret' => $secret, 'request' => $request, 'expected' => $expected] = $vector;
        if (isset($expected['error'])) {
            $error = thrown(static fn () => Keys::hmacV2Signature($secret, $request), UsageError::class);
            check($error->code === $expected['error'], 'code ' . var_export($error->code, true));
            $error = thrown(static fn () => Keys::signHmacV2Request(['apiKey' => 'k', 'apiSecret' => $secret, 'passphrase' => $request['passphrase']], $request), UsageError::class);
            check($error->code === $expected['error'], 'code from signHmacV2Request');
            check($secret === '' || !str_contains($error->getMessage(), trim($secret)), 'the secret is in the message');

            return;
        }
        $message = Keys::hmacV2RequestMessage($request);
        check($message === $expected['signedString'], 'signed string');
        check(base64_encode($message) === $expected['signedStringBase64'], 'signed string bytes');
        check(Keys::hmacV2Signature($secret, $request) === $expected['signature'], 'signature');
    };
}

$keyOf = static fn (string $name, string $accept): SigningKey => SigningKey::read(
    $accept === 'private' ? $full['keys'][$name]['privateKeyPkcs8Pem'] : $full['keys'][$name]['publicKeySpkiPem'],
    $accept,
);

foreach ($full['cases'] as $vector) {
    $tests['request-full-v1.json ' . $vector['name']] = static function () use ($vector, $full, $keyOf): void {
        ['request' => $request, 'expected' => $expected] = $vector;
        $credentials = $full['credentials'];
        $headers = $vector['key'] !== null
            ? Keys::signApiRequest($keyOf($vector['key'], 'private'), $credentials, $request)
            : Keys::signHmacV2Request($credentials, $request);

        check(array_keys($headers) === array_keys($expected['headers']), 'header names and order: ' . json_encode(array_keys($headers)));
        foreach ($expected['headers'] as $name => $value) {
            if ($value !== null) {
                check($headers[$name] === $value, $name);
            }
        }
        if ($expected['keypairSignature'] === 'none') {
            check($expected['keypairSignedStringBase64'] === null, 'no key-pair string');

            return;
        }
        // The key-pair string carries the API key the request is sent with.
        $signedString = Keys::keypairRequestMessage(['apiKey' => $credentials['apiKey']] + $request);
        check(base64_encode($signedString) === $expected['keypairSignedStringBase64'], 'key-pair signed string');
        if ($expected['keypairSignature'] === 'exact') {
            check($headers['x-api-keypair-sign'] === $expected['headers']['x-api-keypair-sign'], 'Ed25519 signature byte for byte');
        }
        $registered = $keyOf($vector['key'], 'public');
        check(Keys::verifyKeypairRequest([$registered], ['apiKey' => $headers['x-api-key']] + $request, $headers['x-api-keypair-id'], $headers['x-api-keypair-sign']) === ['valid' => true], 'the gateway accepts it');
        check(Keys::verifyKeypairRequest([$registered], ['apiKey' => $credentials['apiKey'] . '0'] + $request, $headers['x-api-keypair-id'], $headers['x-api-keypair-sign'])['valid'] === false, 'not under another API key');
    };
}

$tests['request-full-v1.json: a fresh nonce on every request when none is given'] = static function () use ($full): void {
    $request = ['nonce' => null, 'timestamp' => null] + $full['cases'][0]['request'];
    $first = Keys::signHmacV2Request($full['credentials'], $request);
    $second = Keys::signHmacV2Request($full['credentials'], $request);
    check(preg_match('/^[0-9a-f]{32}$/D', $first['x-api-nonce']) === 1, 'nonce shape');
    check($first['x-api-nonce'] !== $second['x-api-nonce'], 'a new nonce each time');
    check(preg_match('/^[1-9][0-9]{9}$/D', $first['x-api-timestamp']) === 1, 'timestamp');
};

$tests['request-full-v1.json: no secret in the headers'] = static function () use ($full): void {
    $headers = Keys::signHmacV2Request($full['credentials'], $full['cases'][0]['request']);
    check(!in_array($full['credentials']['apiSecret'], $headers, true), 'secret in headers');
};

$tests['a nonce outside the allowed shape is refused'] = static function () use ($full): void {
    foreach (['has space', str_repeat('a', 129), "new\nline"] as $nonce) {
        thrown(static fn () => Keys::signHmacV2Request($full['credentials'], ['nonce' => $nonce] + $full['cases'][0]['request']), UsageError::class);
    }
};

return $tests;
