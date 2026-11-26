<?php

declare(strict_types=1);

// test-vectors/p1363-der-v1.json, webhook-v1.json and signing-keys-v1.json.

use Vaultody\Sdk\Verify\ConfigurationError;
use Vaultody\Sdk\Verify\Keys;
use Vaultody\Sdk\Verify\ResponseSignatureError;
use Vaultody\Sdk\Verify\ResponseVerifier;
use Vaultody\Sdk\Verify\SignatureFormatError;
use Vaultody\Sdk\Verify\SigningKeysResponse;
use Vaultody\Sdk\Verify\Webhook;
use Vaultody\Sdk\Verify\WebhookSignatureError;

$p1363 = vectors('p1363-der-v1.json');
$webhook = vectors('webhook-v1.json');
$signingKeys = vectors('signing-keys-v1.json');
$tests = [];

$p1363Key = openssl_pkey_get_public(spki_pem($p1363['publicKeySpkiDerBase64']));
foreach ($p1363['cases'] as $vector) {
    $tests['p1363-der-v1.json ' . $vector['name']] = static function () use ($vector, $p1363Key): void {
        $input = (string) hex2bin($vector['p1363Hex']);
        if (isset($vector['expected']['error'])) {
            $error = thrown(static fn () => Keys::p1363ToDer($input), SignatureFormatError::class);
            check($error->code === $vector['expected']['error'], 'code ' . $error->code);

            return;
        }
        $der = Keys::p1363ToDer($input);
        check(bin2hex($der) === $vector['expected']['derHex'], 'DER ' . bin2hex($der));
        if ($vector['messageBase64'] !== null) {
            check(openssl_verify((string) base64_decode($vector['messageBase64'], true), $der, $p1363Key, OPENSSL_ALGO_SHA256) === 1, 'OpenSSL verifies the DER');
        }
    };
}
$tests['p1363-der-v1.json: anything but 64 bytes is invalid_length'] = static function (): void {
    foreach ([null, 42, str_repeat('00', 64), str_repeat("\1", 63), str_repeat("\1", 65)] as $input) {
        check(thrown(static fn () => Keys::p1363ToDer($input), SignatureFormatError::class)->code === 'invalid_length', 'invalid_length');
    }
};

foreach ($webhook['cases'] as $vector) {
    $tests['webhook-v1.json ' . $vector['name']] = static function () use ($vector): void {
        $body = (string) base64_decode($vector['bodyBase64'], true);
        $secrets = count($vector['secrets']) === 1 ? $vector['secrets'][0] : $vector['secrets'];
        if ($vector['expected']['valid']) {
            check(Webhook::verifySignature($body, $vector['headers'], $secrets) === $vector['expected'], 'verdict');
            // The same with every header name lower-cased and given as a list, as a framework may hand them over
            $lists = [];
            foreach ($vector['headers'] as $name => $value) {
                $lists[strtolower($name)][] = $value;
            }
            check(Webhook::verifySignature($body, $lists, $vector['secrets']) === $vector['expected'], 'verdict with lists');
        } else {
            $error = thrown(static fn () => Webhook::verifySignature($body, $vector['headers'], $secrets), WebhookSignatureError::class);
            check($error->reason === $vector['expected']['reason'], 'reason ' . $error->reason);
        }
    };
}
$tests['webhook-v1.json: a decoded body is refused'] = static function () use ($webhook): void {
    $vector = $webhook['cases'][0];
    $parsed = json_decode((string) base64_decode($vector['bodyBase64'], true), true);
    thrown(static fn () => Webhook::verifySignature($parsed, $vector['headers'], $vector['secrets']), InvalidArgumentException::class);
};
$tests['webhook-v1.json: no usable secret is a configuration error'] = static function () use ($webhook): void {
    $vector = $webhook['cases'][0];
    $body = (string) base64_decode($vector['bodyBase64'], true);
    foreach ([null, '', [], [''], [$vector['secrets'][0], 42], ['a' => 'b']] as $secrets) {
        thrown(static fn () => Webhook::verifySignature($body, $vector['headers'], $secrets), ConfigurationError::class);
    }
};
$tests['webhook-v1.json: the header given twice is malformed'] = static function () use ($webhook): void {
    $vector = $webhook['cases'][0];
    $value = $vector['headers']['X-Signature'];
    $error = thrown(static fn () => Webhook::verifySignature((string) base64_decode($vector['bodyBase64'], true), ['x-signature' => [$value, $value]], $vector['secrets']), WebhookSignatureError::class);
    check($error->reason === 'malformed', 'malformed');
};

foreach ($signingKeys['cases'] as $vector) {
    $tests['signing-keys-v1.json ' . $vector['name']] = static function () use ($vector, $signingKeys): void {
        ['request' => $request, 'response' => $response, 'now' => $now, 'expected' => $expected] = $vector;
        try {
            $result = ResponseVerifier::verify(request_of($request), response_of($response), [
                'roots' => array_map('root_pem', $signingKeys['pinnedRoots']),
                'now' => $now,
                'requireResponseSignature' => false,
            ]);
            $signature = $result['verified'] ? 'verified' : 'absent';
        } catch (ResponseSignatureError $error) {
            $signature = ['error' => $error->reason];
        }
        check($signature === $expected['signature'], 'signature ' . json_encode($signature));
        if (!is_string($signature)) {
            return;
        }
        $read = SigningKeysResponse::read($response['status'], (string) base64_decode($response['bodyBase64'], true), $vector['fingerprint']);
        check($read['outcome'] === $expected['outcome'], 'outcome ' . $read['outcome']);
        if (isset($expected['code'])) {
            check($read['error']['code'] === $expected['code'], 'code');
        }
    };
}

return $tests;
