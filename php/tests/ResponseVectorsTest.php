<?php

declare(strict_types=1);

// test-vectors/v1.json: every case must come out exactly as the gateway's reference verifier says: same
// verdict, same reason. The vectors are the contract between the gateway and every verifier.

use Vaultody\Sdk\Exception\ResponseVerificationError;
use Vaultody\Sdk\Http\HttpResponse;
use Vaultody\Sdk\Transport\Operation;
use Vaultody\Sdk\Transport\Transport;
use Vaultody\Sdk\Verify\Keys;
use Vaultody\Sdk\Verify\ResponseSignatureError;
use Vaultody\Sdk\Verify\ResponseVerifier;

$vectors = vectors('v1.json');

$verdict = static function (array $vector, array $headers) use ($vectors): array {
    $verify = $vector['verify'];
    try {
        $result = ResponseVerifier::verify(request_of($verify['request']), response_of($verify['response'], $headers), [
            'roots' => array_map('root_pem', $verify['pinnedRoots']),
            'now' => $verify['now'],
            'maxClockSkewSeconds' => $vectors['verifier']['skewSeconds'],
        ]);

        return $result['verified'] ? ['valid' => true] : ['valid' => false, 'reason' => $result['reason'], 'returned' => true];
    } catch (ResponseSignatureError $error) {
        return ['valid' => false, 'reason' => $error->reason];
    }
};

// The transport collects every header as a list of values, under its lower-case name.
$asLists = static function (array $headers): array {
    $lists = [];
    foreach ($headers as $name => $value) {
        $lists[strtolower($name)][] = $value;
    }

    return $lists;
};

$tests = [
    'v1.json is the v1 format with cases in every category' => static function () use ($vectors): void {
        check($vectors['format'] === 'vaultody signed API responses, wire format v1', 'format');
        check($vectors['verifier']['skewSeconds'] === 300, 'skew');
        $categories = array_unique(array_column($vectors['cases'], 'category'));
        foreach (['valid', 'tampered', 'binding', 'time', 'root', 'certificate_form', 'header'] as $category) {
            check(in_array($category, $categories, true), 'no ' . $category . ' cases');
        }
    },
];

foreach ($vectors['cases'] as $vector) {
    $label = $vector['expected']['valid'] ? 'valid' : $vector['expected']['reason'];
    $tests['v1.json ' . $vector['name'] . ' -> ' . $label] = static function () use ($vector, $verdict): void {
        $actual = $verdict($vector, $vector['verify']['response']['headers']);
        check($actual === $vector['expected'], 'got ' . json_encode($actual));
    };
    $tests['v1.json ' . $vector['name'] . ' (headers as lists) -> ' . $label] = static function () use ($vector, $verdict, $asLists): void {
        $actual = $verdict($vector, $asLists($vector['verify']['response']['headers']));
        check($actual === $vector['expected'], 'got ' . json_encode($actual));
    };
    if ($vector['expected']['valid']) {
        $tests['v1.json ' . $vector['name'] . ' reports the key, root and time'] = static function () use ($vector): void {
            $verify = $vector['verify'];
            $result = ResponseVerifier::verify(request_of($verify['request']), response_of($verify['response']), [
                'roots' => array_map('root_pem', $verify['pinnedRoots']),
                'now' => $verify['now'],
            ]);
            check($result === [
                'verified' => true,
                'keyId' => $vector['signed']['certificate']['keyId'],
                'rootId' => $vector['signed']['certificate']['rootId'],
                'timestamp' => $vector['signed']['ts'],
            ], 'got ' . json_encode($result));
        };
    }
}

// The same cases through the SDK's own verification step: a client given the case's roots, so every answer must be
// signed, refuses exactly what the verifier refuses, with the same reason.
foreach ($vectors['cases'] as $vector) {
    $label = $vector['expected']['valid'] ? 'valid' : $vector['expected']['reason'];
    $tests['v1.json ' . $vector['name'] . ' through the transport -> ' . $label] = static function () use ($vector, $vectors): void {
        $verify = $vector['verify'];
        $transport = new Transport([
            'apiKey' => 'TEST-ONLY-key', 'apiSecret' => base64_encode('TEST-ONLY secret'), 'passphrase' => 'TEST-ONLY passphrase',
            'roots' => array_map('root_pem', $verify['pinnedRoots']),
            'clock' => static fn (): int => $verify['now'],
            'maxClockSkewSeconds' => $vectors['verifier']['skewSeconds'],
        ]);
        $request = $verify['request'];
        $response = response_of($verify['response']);
        $headers = [];
        foreach ($response['headers'] as $name => $value) {
            $headers[strtolower($name)][] = $value;
        }
        $step = fn (): array => $this->verifyResponse(
            new Operation('vectorCase', $request['method'], $request['path'], 'read'),
            $request['query'] === '' ? $request['path'] : $request['path'] . '?' . $request['query'],
            (string) base64_decode($request['bodyBase64'], true),
            [Keys::HEADERS['sign'] => $request['apiSign'], Keys::HEADERS['keypairSign'] => $request['keypairSign']],
            new HttpResponse($response['status'], $headers, $response['body']),
        );
        try {
            $actual = $step->call($transport)['verified'] ? ['valid' => true] : ['valid' => false, 'reason' => 'absent'];
        } catch (ResponseVerificationError $error) {
            $actual = ['valid' => false, 'reason' => $error->reason];
        }
        check($actual === $vector['expected'], 'got ' . json_encode($actual));
    };
}

/**
 * A response signed as the gateway signs it, with the TEST-ONLY current root and pod key 1 of v1.json, its certificate
 * valid from $notBefore to $notAfter and the response signed at $signedAt.
 *
 * @return array{array<string, string>, array{status: int, headers: array<string, string>, body: string}}
 */
$signedResponse = static function (int $notBefore, int $notAfter, int $signedAt) use ($vectors): array {
    $pair = sodium_crypto_sign_seed_keypair((string) hex2bin($vectors['keys']['podKeys']['pod1']['seedHex']));
    $publicKey = sodium_crypto_sign_publickey($pair);
    $root = $vectors['keys']['roots']['current'];
    $cert = implode("\n", ['vaultody-response-key-v1', $root['rootId'], base64_encode($publicKey), substr(hash('sha256', $publicKey), 0, 32), (string) $notBefore, (string) $notAfter]);
    openssl_sign($cert, $rootSignature, openssl_pkey_get_private($root['privateKeyPkcs8Pem']), OPENSSL_ALGO_SHA256);
    $request = ['method' => 'GET', 'url' => '/vaults/main?limit=1', 'body' => '', 'apiSign' => 'TEST-ONLY-sign', 'keypairSign' => ''];
    $body = '{"data":{"item":{}}}';
    $message = implode("\n", ['vaultody-response-v1', (string) $signedAt, '200', 'GET', '/vaults/main', 'limit=1', hash('sha256', ''), 'TEST-ONLY-sign', '']) . "\n" . $body;

    return [$request, ['status' => 200, 'body' => $body, 'headers' => [
        'x-api-response-sign' => base64_encode(sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($pair))),
        'x-api-response-timestamp' => (string) $signedAt,
        'x-api-response-sign-version' => '1',
        'x-api-response-cert' => base64_encode($cert) . '.' . base64_encode((string) $rootSignature),
    ]]];
};

$tests['a certificate valid for exactly MAX_CERT_LIFETIME_SECONDS (3600) is accepted, one second more is invalid'] = static function () use ($signedResponse): void {
    check(ResponseVerifier::MAX_CERT_LIFETIME_SECONDS === 3600, 'an hour');
    $notBefore = 1794200000;
    $options = ['roots' => [root_pem('current')], 'now' => $notBefore + 60];
    [$request, $response] = $signedResponse($notBefore, $notBefore + 3600, $notBefore + 30);
    check(ResponseVerifier::verify($request, $response, $options)['verified'] === true, '3600 s');

    foreach ([3601, 315360000] as $lifetime) {
        [$request, $response] = $signedResponse($notBefore, $notBefore + $lifetime, $notBefore + 30);
        $error = thrown(static fn () => ResponseVerifier::verify($request, $response, $options), ResponseSignatureError::class);
        check($error->reason === 'invalid' && str_contains($error->getMessage(), 'more than 3600 seconds'), $lifetime . ' s: ' . $error->reason . ' ' . $error->getMessage());
    }
};

return $tests;
