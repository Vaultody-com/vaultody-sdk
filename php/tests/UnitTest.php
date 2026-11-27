<?php

declare(strict_types=1);

// Unit tests of the pieces the vector sets do not cover on their own: the webhook helper's event, the rate
// limiter, key reading refusals, root setup, and that no secret shows in any dump.

use Vaultody\Sdk\Exception\ConfigurationError as SdkConfigurationError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Exception\WebhookPayloadError;
use Vaultody\Sdk\Exception\WebhookSignatureError;
use Vaultody\Sdk\RateLimiter;
use Vaultody\Sdk\Signer\KeyFileSigner;
use Vaultody\Sdk\Vaultody;
use Vaultody\Sdk\WebhookEvent;
use Vaultody\Sdk\Webhooks;
use Vaultody\Sdk\Verify\ConfigurationError;
use Vaultody\Sdk\Verify\EmbeddedRoots;
use Vaultody\Sdk\Verify\ResponseSignatureError;
use Vaultody\Sdk\Verify\ResponseVerifier;
use Vaultody\Sdk\Verify\Roots;
use Vaultody\Sdk\Verify\SigningKey;
use Vaultody\Sdk\Verify\SigningKeyError;

$webhook = vectors('webhook-v1.json');
$keys = vectors('request-keypair-v1.json')['keys'];
$tests = [];

$tests['webhooks: a verified delivery becomes a typed event, with its delivery fields'] = static function () use ($webhook): void {
    $vector = $webhook['cases'][0];
    $event = (new Webhooks())->verify((string) base64_decode($vector['bodyBase64'], true), $vector['headers'], $vector['secrets']);
    check($event->event === WebhookEvent::TRANSACTION_REQUEST && $event->isKnown(), 'event');
    check($event->idempotencyKey === '1f232491a0f5b5e32165546e80c36c9f8046f6581eca26c62542dbc8ec4f0fa1', 'idempotency key');
    check($event->webhookId === '68516e9c6620b0a4790ed541' && $event->apiVersion === '2026-03-20', 'webhook id and version');
    check($event->item['transactionType'] === 'COIN', 'item');
};

$tests['webhooks: an unknown event is returned as such, a reverted deposit is known, a bad signature is an error'] = static function (): void {
    $secret = 'TEST-ONLY webhook secret';
    $sign = static fn (string $body): array => ['X-Signature' => hash_hmac('sha256', $body, $secret)];
    $future = '{"webhookId":"w","idempotencyKey":"k","data":{"event":"SOMETHING_NEW","item":{"x":1}}}';
    $event = (new Webhooks())->verify($future, $sign($future), $secret);
    check($event->event === 'SOMETHING_NEW' && !$event->isKnown() && $event->item === ['x' => 1], 'unknown event');
    $reverted = '{"data":{"event":"INCOMING_TX_REVERTED","item":{"inclusion":"reorged"}}}';
    check((new Webhooks())->verify($reverted, $sign($reverted), [$secret . ' old', $secret])->isKnown(), 'reverted');
    check((new Webhooks())->verify($reverted, $sign($reverted), ['old', $secret])->secretIndex === 1, 'rotation');
    check(thrown(static fn () => (new Webhooks())->verify($reverted . ' ', $sign($reverted), $secret), WebhookSignatureError::class)->reason === 'mismatch', 'tampered');
    check(thrown(static fn () => (new Webhooks())->verify($reverted, [], $secret), WebhookSignatureError::class)->reason === 'missing', 'missing');
    thrown(static fn () => (new Webhooks())->verify($reverted, $sign($reverted), []), SdkConfigurationError::class);
    thrown(static fn () => (new Webhooks())->verify('[1]', $sign('[1]'), $secret), WebhookPayloadError::class);
    thrown(static fn () => (new Webhooks())->verify('not json', $sign('not json'), $secret), WebhookPayloadError::class);
};

$tests['rate limiter: a burst of 5, then one request every 200 ms'] = static function (): void {
    $now = 100.0;
    $slept = [];
    $limiter = new RateLimiter(5, 5, static function () use (&$now): float {
        return $now;
    }, static function (int $ms) use (&$now, &$slept): void {
        $slept[] = $ms;
        $now += $ms / 1000;
    });
    for ($i = 0; $i < 5; $i++) {
        $limiter->take();
    }
    check($slept === [], 'the burst goes at once');
    $limiter->take();
    $limiter->take();
    check(array_sum($slept) >= 400 && array_sum($slept) <= 401, 'waited ' . array_sum($slept));
    $now += 10;
    $slept = [];
    for ($i = 0; $i < 5; $i++) {
        $limiter->take();
    }
    check($slept === [], 'refilled, but never above the burst');
    $limiter->take();
    check($slept !== [], 'the sixth waits');
};

$tests['keys: encrypted, RSA, OpenSSH, certificates, several blocks and a public key where a private one is needed are refused'] = static function () use ($keys): void {
    $codeOf = static fn (string $pem, string $accept = 'any'): string => thrown(static fn () => SigningKey::read($pem, $accept), SigningKeyError::class)->code;
    check($codeOf("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n") === 'encrypted_key', 'encrypted');
    check($codeOf("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n") === 'unsupported_algorithm', 'RSA');
    check($codeOf('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test') === 'invalid_key', 'OpenSSH');
    check($codeOf("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n") === 'invalid_key', 'certificate');
    check($codeOf($keys['ed25519']['publicKeySpkiPem'] . $keys['p256']['publicKeySpkiPem']) === 'invalid_key', 'two blocks');
    check($codeOf($keys['ed25519']['publicKeySpkiPem'], 'private') === 'public_key', 'public where private');
    check($codeOf($keys['ed25519']['privateKeyPkcs8Pem'], 'public') === 'private_key', 'private where public');
    check($codeOf('') === 'invalid_key', 'empty');
    check($codeOf(str_repeat('a', 20000)) === 'invalid_key', 'too long');
    check(SigningKey::read("\r\n" . str_replace("\n", "\r\n", $keys['p256']['privateKeyPkcs8Pem']))->fingerprint === $keys['p256']['fingerprint'], 'CRLF line ends');
};

$tests['keys: a PEM block is read in linear time: a long run of whitespace is refused at once, never backtracked over'] = static function () use ($keys): void {
    $contents = \Closure::bind(static fn (string $pem, string $label): ?string => SigningKey::pemContents($pem, $label), null, SigningKey::class);
    $begin = '-----BEGIN PUBLIC KEY-----';
    $end = '-----END PUBLIC KEY-----';
    foreach ([
        'spaces, then a character' => [$begin . str_repeat(' ', 100000) . 'A', null],
        'spaces and line ends, then a character' => [$begin . str_repeat(" \n", 50000) . 'A', null],
        'a character no PEM body holds, after the spaces' => [$begin . str_repeat(' ', 100000) . '!' . $end, null],
        'another label at the end' => [$begin . str_repeat(' ', 100000) . '-----END PRIVATE KEY-----', null],
        'only whitespace inside' => [$begin . str_repeat(" \n", 50000) . $end, str_repeat(" \n", 50000)],
    ] as $what => [$pem, $expected]) {
        $started = hrtime(true);
        $inner = $contents($pem, 'PUBLIC KEY');
        $ms = (hrtime(true) - $started) / 1e6;
        check($inner === $expected, $what);
        check($ms < 100, sprintf('%s: %.1f ms', $what, $ms));
    }
    check($contents($begin . $end, 'PUBLIC KEY') === '' && $contents('-----BEGIN PUBLIC KEY----', 'PUBLIC KEY') === null, 'the two lines and nothing between; shorter is refused');

    // Through the reader, up to the size it reads at all, and with whitespace inside a real key.
    $started = hrtime(true);
    $error = thrown(static fn () => SigningKey::read($begin . str_repeat(' ', 16000) . 'A'), SigningKeyError::class);
    check($error->code === 'invalid_key' && (hrtime(true) - $started) / 1e6 < 100, 'refused at once');
    $spaced = str_replace("\n", "\n  \t\n", trim($keys['p256']['publicKeySpkiPem']));
    check(SigningKey::read($spaced, 'public')->fingerprint === $keys['p256']['fingerprint'], 'whitespace inside the body is still read');
};

$tests['keys: a pasted public key is read up to 1024 characters'] = static function () use ($keys): void {
    $pem = $keys['p256']['publicKeySpkiPem'];
    check(SigningKey::MAX_PUBLIC_KEY_PEM_LENGTH === 1024, 'the limit of a key registration');
    $padded = $pem . str_repeat("\n", 1024 - strlen($pem));
    check(strlen($padded) === 1024 && SigningKey::read($padded, 'public')->fingerprint === $keys['p256']['fingerprint'], '1024 characters are read');
    $error = thrown(static fn () => SigningKey::read($padded . "\n", 'public'), SigningKeyError::class);
    check($error->code === 'invalid_key' && str_contains($error->getMessage(), 'longer than 1024 characters'), 'one more is too long: ' . $error->getMessage());
};

$tests['keys: a SEC1 "EC PRIVATE KEY" reads as the same P-256 key'] = static function () use ($keys): void {
    $private = openssl_pkey_get_private($keys['p256']['privateKeyPkcs8Pem']);
    $details = openssl_pkey_get_details($private);
    // Rebuild the SEC1 form from the scalar and point, as "openssl ec" writes it.
    $d = str_pad($details['ec']['d'], 32, "\0", STR_PAD_LEFT);
    $point = "\x04" . str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
    $der = "\x30\x77\x02\x01\x01\x04\x20" . $d . "\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\xa1\x44\x03\x42\x00" . $point;
    $key = SigningKey::read(SigningKey::pem('EC PRIVATE KEY', $der), 'private');
    check($key->fingerprint === $keys['p256']['fingerprint'] && $key->verify('m', base64_encode($key->sign('m'))), 'same key, signs');
};

$tests['keys: a signing key never shows its private half'] = static function () use ($keys): void {
    $key = SigningKey::read($keys['ed25519']['privateKeyPkcs8Pem'], 'private');
    $seed = substr((string) base64_decode(substr(trim(explode("\n", $keys['ed25519']['privateKeyPkcs8Pem'])[1]), 0), true), -32);
    ob_start();
    var_dump($key);
    $dump = (string) ob_get_clean() . print_r($key, true) . var_export($key, true) . json_encode((array) $key) . json_encode($key);
    check(!str_contains($dump, $seed) && !str_contains($dump, bin2hex($seed)), 'the seed in a dump');
    thrown(static fn () => serialize($key), LogicException::class);
    thrown(static fn () => clone $key, LogicException::class);
    $signer = KeyFileSigner::fromPem($keys['ed25519']['privateKeyPkcs8Pem']);
    check(!str_contains(print_r($signer, true), $seed), 'the signer');
};

$tests['roots: the production root is embedded; with no root a signed response fails closed while an unsigned one needs no root'] = static function (): void {
    $embedded = Roots::embedded();
    check(count($embedded) === 1 && $embedded[0]->rootId === EmbeddedRoots::CURRENT['fingerprint'] && EmbeddedRoots::NEXT === ['pem' => '', 'fingerprint' => ''], 'the current root only');
    check(Roots::require(null) === $embedded, 'no roots option: the embedded root');
    thrown(static fn () => Roots::require([]), ConfigurationError::class);
    $vector = vectors('v1.json')['cases'][0];
    thrown(static fn () => ResponseVerifier::verify(request_of($vector['verify']['request']), response_of($vector['verify']['response']), ['now' => $vector['verify']['now'], 'roots' => []]), ConfigurationError::class);
    $unsigned = ResponseVerifier::verify(['method' => 'GET', 'url' => '/x'], ['status' => 200, 'headers' => [], 'body' => '{}'], ['requireResponseSignature' => false]);
    check($unsigned === ['verified' => false, 'reason' => 'missing'], 'unsigned, non-strict');
    check(thrown(static fn () => ResponseVerifier::verify(['method' => 'GET', 'url' => '/x'], ['status' => 200, 'headers' => [], 'body' => '{}']), ResponseSignatureError::class)->reason === 'missing', 'unsigned, strict');
};

$tests['roots: a malformed root is reported at once; a fingerprint must match its key; slots must be whole'] = static function (): void {
    $pem = root_pem('current');
    $rootId = vectors('v1.json')['keys']['roots']['current']['rootId'];
    check(Roots::parse(['current' => ['pem' => $pem, 'fingerprint' => $rootId], 'next' => ['pem' => '', 'fingerprint' => '']])[0]->rootId === $rootId, 'parsed');
    thrown(static fn () => Roots::parse(['pem' => $pem, 'fingerprint' => str_repeat('0', 64)]), ConfigurationError::class);
    thrown(static fn () => Roots::parse('not a key'), ConfigurationError::class);
    thrown(static fn () => Roots::parse(vectors('request-keypair-v1.json')['keys']['ed25519']['publicKeySpkiPem']), ConfigurationError::class);
    thrown(static fn () => Roots::loadEmbedded(['current' => ['pem' => $pem, 'fingerprint' => '']]), ConfigurationError::class);
    check(Roots::loadEmbedded(['current' => ['pem' => $pem, 'fingerprint' => $rootId]])[0]->rootId === $rootId, 'a filled slot loads');
    thrown(static fn () => ResponseVerifier::verify(['method' => 'GET', 'url' => '/x'], ['status' => 200, 'headers' => []], ['now' => 1700000000000]), InvalidArgumentException::class);
};

$tests['client: Vaultody holds the endpoint groups and the webhook helper, hands out no raw transport, and shows no credential'] = static function (): void {
    $vaultody = new Vaultody(['apiKey' => 'TEST-ONLY-key', 'apiSecret' => base64_encode('TEST-ONLY secret'), 'passphrase' => 'TEST-ONLY passphrase']);
    check($vaultody->webhooks instanceof Webhooks && $vaultody->__debugInfo()['transport']['origin'] === 'https://rest.vaultody.com', 'parts');
    // The raw pipeline skips the contract checks of the methods, so the client does not expose it.
    $public = array_map(static fn (ReflectionMethod $method): string => $method->getName(), (new ReflectionClass($vaultody))->getMethods(ReflectionMethod::IS_PUBLIC));
    check(array_values(array_diff($public, ['__construct', '__debugInfo', 'responseSignature'])) === [], 'public methods ' . json_encode($public));
    check($vaultody->responseSignature() === $vaultody->__debugInfo()['transport']['responseSignature'], 'the mode in force');
    $properties = array_map(static fn (ReflectionProperty $property): string => $property->getName(), (new ReflectionClass($vaultody))->getProperties(ReflectionProperty::IS_PUBLIC));
    check($properties === ['vaults', 'vaultAccounts', 'assetsAddresses', 'transactions', 'apiKeys', 'webhooks'], 'public properties ' . json_encode($properties));
    $dump = print_r($vaultody, true) . var_export($vaultody, true);
    check(!str_contains($dump, 'TEST-ONLY passphrase') && !str_contains($dump, base64_encode('TEST-ONLY secret')), 'credentials in a dump');
};

return $tests;
