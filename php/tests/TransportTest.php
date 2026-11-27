<?php

declare(strict_types=1);

// The transport against a local mock gateway (support/mock-gateway.php) that checks request signatures,
// applies the replay rules and signs its answers with the TEST-ONLY keys: signing, response verification and
// the latch, retries and outcome-unknown writes, paging, vault xpub pins and address checks.

require_once __DIR__ . '/support/MockGateway.php';
require_once __DIR__ . '/support/RecordingLogger.php';

use Vaultody\Sdk\Exception\AddressVerificationError;
use Vaultody\Sdk\Exception\ApiError;
use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\ConflictError;
use Vaultody\Sdk\Exception\ParameterError;
use Vaultody\Sdk\Exception\RateLimitError;
use Vaultody\Sdk\Exception\RequestOutcomeUnknownError;
use Vaultody\Sdk\Exception\RequestSigningError;
use Vaultody\Sdk\Exception\ResponseVerificationError;
use Vaultody\Sdk\Exception\TransportError;
use Vaultody\Sdk\Exception\VaultKeyChangedError;
use Vaultody\Sdk\Http\CurlHttpClient;
use Vaultody\Sdk\Http\HttpClient;
use Vaultody\Sdk\Http\HttpRequest;
use Vaultody\Sdk\Http\HttpResponse;
use Vaultody\Sdk\Signer\CallableSigner;
use Vaultody\Sdk\Signer\KeyFileSigner;
use Vaultody\Sdk\Transport\CoreOperations;
use Vaultody\Sdk\Transport\Item;
use Vaultody\Sdk\Transport\Operation;
use Vaultody\Sdk\Transport\Page;
use Vaultody\Sdk\Transport\Transport;
use Vaultody\Sdk\VaultKeys\FileVaultKeyStore;
use Vaultody\Sdk\VaultKeys\MemoryVaultKeyStore;
use Vaultody\Sdk\Verify\Keys;
use Vaultody\Sdk\Verify\SigningKey;

$gateway = MockGateway::start();
$full = vectors('request-full-v1.json');
$addresses = vectors('address-v1.json');

$tempDir = static function (): string {
    $dir = sys_get_temp_dir() . '/vaultody-transport-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);

    return $dir;
};

/** A transport against the mock gateway, trusting the TEST-ONLY current root, with no real waiting. */
$make = static function (array $options = []) use ($gateway, $full): Transport {
    return new Transport($options + [
        'apiKey' => $full['credentials']['apiKey'],
        'apiSecret' => $full['credentials']['apiSecret'],
        'passphrase' => $full['credentials']['passphrase'],
        'baseUrl' => $gateway->url(),
        'roots' => [root_pem('current')],
        'sleep' => static function (int $ms): void {
        },
        'maxRequestsPerSecond' => 1000,
        'timeoutSeconds' => 5,
        'logger' => new RecordingLogger(),
    ]);
};
/** The same, the mock gateway cleared first. */
$client = static function (array $options = []) use ($gateway, $make): Transport {
    $gateway->reset();

    return $make($options);
};
// Options for a client without response-signing roots, in when-present mode: a release candidate before production
// signs, which accepts unsigned answers until the first signed one (a client with roots requires a signature on every
// answer). A test that goes from unsigned to signed answers uses one up to the first signed answer, then a client
// with roots on the same store: an upgrade.
$candidate = ['roots' => null, 'responseSignature' => 'when-present'];
// A release candidate that embeds the TEST-ONLY current root: when-present all the same, the bridge to signing.
$bridge = ['roots' => null, 'responseSignature' => 'when-present', 'embeddedRoots' => [root_pem('current')], 'sdkVersion' => '0.9.0-rc.1'];

$events = [];
// Every security event a test sees must have a catalogued type and exactly its fields
// (test-vectors/security-events-v1.json); the transport swallows what the hook throws, so strays are collected
// and checked by the last test.
$catalogue = array_column(vectors('security-events-v1.json')['events'], 'fields', 'type');
$strayEvents = [];
$recordEvents = static function () use (&$events, &$strayEvents, $catalogue): callable {
    $events = [];

    return static function (array $event) use (&$events, &$strayEvents, $catalogue): void {
        if (array_keys($event) !== ($catalogue[$event['type'] ?? ''] ?? null)) {
            $strayEvents[] = $event;
        }
        $events[] = $event;
    };
};
$eventTypes = static function () use (&$events): array {
    return array_column($events, 'type');
};

$keyFile = static function (string $name) use ($full, $tempDir): string {
    $path = $tempDir() . '/private.pem';
    file_put_contents($path, $full['keys'][$name]['privateKeyPkcs8Pem']);

    return $path;
};

$write = new Operation('createSingleTransfer', 'POST', '/vaults/{vaultId}/transactions/single', 'write', ['vaultId'], [], true);
$read = new Operation('getVaultAccountById', 'GET', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}', 'read', ['vaultId', 'vaultAccountId']);
$deposit = new Operation('generateDepositAddress', 'POST', '/vaults/{vaultId}/{blockchain}/{network}/addresses', 'write', ['vaultId', 'blockchain', 'network'], [], true, addresses: Operation::ADDRESSES_IN_PATH);
$listAddresses = new Operation('listAddressesByVaultAccountId', 'GET', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/list-addresses', 'read', ['vaultId', 'vaultAccountId'], ['assetId', 'blockchain', 'limit', 'startingAfter'], paging: 'cursor', cursorField: 'addressId', addresses: Operation::ADDRESSES_IN_ITEMS);
$addAsset = new Operation('addAssetToVaultAccount', 'PUT', '/vaults/{vaultId}/vault-accounts/{vaultAccountId}/add-asset', 'write', ['vaultId', 'vaultAccountId'], [], true, addresses: Operation::ADDRESSES_ADD_ASSET);

$caseOf = static function (string $name) use ($addresses): array {
    foreach ($addresses['cases'] as $case) {
        if ($case['name'] === $name) {
            return $case;
        }
    }
    throw new RuntimeException('no address case ' . $name);
};
$btc = $caseOf('bitcoin/mainnet/P2WPKH/ecdsa-bip32-tv1-master/m/0/0/0');
$xpubOf = static function (string $name) use ($addresses): string {
    foreach ($addresses['xpubs'] as $xpub) {
        if ($xpub['name'] === $name) {
            return $xpub['xpub'];
        }
    }
    throw new RuntimeException('no xpub ' . $name);
};
$vault = static fn (string $id, string $type, ?string $ecdsa, ?string $eddsa = null): array => [
    'id' => $id, 'type' => $type, 'name' => 'TEST vault ' . $id,
    'mpcKeys' => array_values(array_filter([
        $ecdsa === null ? null : ['algorithm' => 'ECDSA', 'xpub' => $ecdsa],
        $eddsa === null ? null : ['algorithm' => 'EDDSA', 'xpub' => $eddsa],
    ])),
];
$addressItem = static fn (array $case, array $extra = []): array => $extra + [
    'address' => $case['address'], 'accountIndex' => $case['accountIndex'], 'isChange' => $case['change'],
    'addressIndex' => $case['addressIndex'], 'addressFormat' => $case['addressFormatWire'], 'label' => 'TEST',
];
$ok = static fn (array $item = ['ok' => true]): array => ['status' => 200, 'body' => ['item' => $item]];

$tests = [];

$tests['transport: a call is signed with HMAC v2, a fresh nonce and the pinned API version, and its signed answer verified'] = static function () use ($client, $gateway, $read, $ok): void {
    $transport = $client();
    $gateway->script([$ok(['id' => 'a1']), $ok(['id' => 'a1'])]);
    $first = $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1', 'context' => 'ctx 1']);
    $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']);
    check($first instanceof Item && $first->data === ['id' => 'a1'], 'item');
    check($first->meta->signature === 'verified', 'signature ' . $first->meta->signature);
    [$one, $two] = $gateway->requests();
    check($one['hmacValid'] && $two['hmacValid'], 'the mock gateway accepts the HMAC');
    check($one['uri'] === '/vaults/v1/vault-accounts/a1?context=ctx%201', 'uri ' . $one['uri']);
    check($one['apiVersion'] === '2026-03-20', 'x-api-version');
    check(preg_match('/^[0-9a-f]{32}$/D', $one['nonce']) === 1 && $one['nonce'] !== $two['nonce'], 'fresh nonces');
    check(str_starts_with($one['userAgent'], 'vaultody-sdk-php/'), 'user agent');
    check($one['keypairId'] === '', 'no key-pair headers without a signer');
};

$tests['transport: a body is {context, data: {item}} as UTF-8 JSON, and over 1 MiB is refused before sending'] = static function () use ($client, $gateway, $write, $ok): void {
    $transport = $client();
    $gateway->script([$ok()]);
    $transport->call($write, ['vaultId' => 'v1', 'context' => 'order-7', 'amount' => '0.1', 'note' => 'Сметка ✓/']);
    $request = $gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])[0];
    check($request['body'] === '{"context":"order-7","data":{"item":{"amount":"0.1","note":"Сметка ✓/"}}}', 'body ' . $request['body']);
    check($request['contentType'] === 'application/json', 'content type');
    check(thrown(static fn () => $transport->call($write, ['vaultId' => 'v1', 'blob' => str_repeat('a', 1048576)]), ParameterError::class)->code === 'body_too_large', 'too large');
    check(thrown(static fn () => $transport->call(new Operation('x', 'GET', '/x', 'read'), ['nope' => 1]), ParameterError::class)->code === 'unknown_param', 'unknown param');
    check(count($gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])) === 1, 'nothing more was sent');
};

$tests['transport: an Ed25519 key file signs x-api-keypair-sign, verified by the gateway'] = static function () use ($client, $gateway, $read, $ok, $keyFile, $full): void {
    $transport = $client(['privateKeyFile' => $keyFile('ed25519')]);
    $gateway->script([$ok()]);
    $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']);
    $request = $gateway->requests()[0];
    check($request['keypairValid'] === true && $request['hmacValid'], 'both signatures valid');
    check($request['keypairId'] === $full['keys']['ed25519']['fingerprint'], 'key id');
};

$tests['transport: a P-256 callable signer (KMS style, digest in, P1363 out) is converted to DER'] = static function () use ($client, $gateway, $read, $ok, $full): void {
    $private = openssl_pkey_get_private($full['keys']['p256']['privateKeyPkcs8Pem']);
    $calls = 0;
    $signer = new CallableSigner('p-256', $full['keys']['p256']['publicKeySpkiPem'], static function (string $digest) use ($private, &$calls): string {
        $calls++;
        check(strlen($digest) === 32, 'the callable gets SHA-256 of the message');
        // OpenSSL's sign() hashes its input again, so this signs SHA-256(SHA-256(message)): the wrong thing.
        openssl_sign($digest, $der, $private, OPENSSL_ALGO_SHA256);

        return $der;
    }, digestOnly: true);
    $transport = $client(['signer' => $signer]);
    $gateway->script([$ok()]);
    check(str_contains(thrown(static fn () => $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']), ConfigurationError::class)->getMessage(), 'does not verify'), 'a wrong signature is caught before sending');
    check($gateway->requests() === [], 'nothing was sent');

    // The right way: the whole message signed by OpenSSL, returned as P1363.
    $p1363 = new CallableSigner('p-256', $full['keys']['p256']['publicKeySpkiPem'], static function (string $message) use ($private): string {
        openssl_sign($message, $der, $private, OPENSSL_ALGO_SHA256);
        $offset = 2;
        $parts = [];
        for ($i = 0; $i < 2; $i++) {
            $length = ord($der[$offset + 1]);
            $parts[] = str_pad(ltrim(substr($der, $offset + 2, $length), "\0"), 32, "\0", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return implode('', $parts);
    }, digestOnly: false);
    $transport = $client(['signer' => $p1363]);
    $gateway->script([$ok()]);
    $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']);
    check($gateway->requests()[0]['keypairValid'] === true, 'the gateway accepts the converted DER');
};

$tests['transport: a signer whose public key is not Ed25519 or P-256, or does not match its algorithm, is refused at setup'] = static function () use ($client, $full): void {
    thrown(static fn () => $client(['signer' => new CallableSigner('ed25519', $full['keys']['p256']['publicKeySpkiPem'], static fn (string $m): string => '')]), ConfigurationError::class);
    thrown(static fn () => $client(['signer' => new CallableSigner('ed25519', "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE3igQViNP51xbh1OUFCn6280/+HBqh6mv\nVfzQWIvy7bvPhRkO2mtEcJPOTMMRj5bIdqEo2/sbYw3CHyYir6lH3g==\n-----END PUBLIC KEY-----\n", static fn (string $m): string => '')]), ConfigurationError::class);
    thrown(static fn () => $client(['privateKeyFile' => '/nonexistent/private.pem']), ConfigurationError::class);
};

$tests['transport: a release candidate that embeds the root accepts unsigned answers, then a verified one latches: unsigned is refused from then on, across clients sharing the store'] = static function () use ($client, $gateway, $read, $ok, $recordEvents, $eventTypes, $tempDir, $bridge, $candidate): void {
    $store = new FileVaultKeyStore($tempDir() . '/vault-keys.json');
    $transport = $client($bridge + ['vaultKeyStore' => $store, 'onSecurityEvent' => $recordEvents()]);
    check($transport->responseSignature() === 'when-present', 'a release candidate is not strict for its embedded root alone');
    $gateway->script([['status' => 200, 'body' => ['item' => ['n' => 1]], 'sign' => 'no'], $ok(), ['status' => 200, 'body' => ['item' => ['n' => 3]], 'sign' => 'no']]);
    $params = ['vaultId' => 'v1', 'vaultAccountId' => 'a1'];
    check($transport->call($read, $params)->meta->signature === 'absent', 'unsigned accepted before the latch');
    check($transport->call($read, $params)->meta->signature === 'verified', 'signed');
    check(thrown(static fn () => $transport->call($read, $params), ResponseVerificationError::class)->reason === 'missing', 'unsigned refused after the latch');
    check($eventTypes() === ['unsigned_response_accepted', 'response_signature_latched', 'response_verification_failed'], 'events ' . json_encode($eventTypes()));
    $latch = $store->read($transport->origin())['responseSignature'];
    check(is_array($latch) && array_keys($latch) === ['latchedAt', 'rootId'] && is_int($latch['latchedAt']) && $latch['rootId'] !== '', 'the latch is stored ' . json_encode($latch));

    $later = $client($candidate + ['vaultKeyStore' => $store]);
    $gateway->script([['status' => 200, 'body' => ['item' => []], 'sign' => 'no']]);
    check(thrown(static fn () => $later->call($read, $params), ResponseVerificationError::class)->reason === 'missing', 'a new client (a new PHP request) is latched too');
};

$tests['transport: required refuses an unsigned answer; a tampered or partly stripped one is refused in any mode and never retried'] = static function () use ($client, $gateway, $read, $write): void {
    $params = ['vaultId' => 'v1', 'vaultAccountId' => 'a1'];
    $transport = $client(['roots' => null, 'responseSignature' => 'required']);
    $gateway->script([['status' => 200, 'body' => ['item' => []], 'sign' => 'no']]);
    check(thrown(static fn () => $transport->call($read, $params), ResponseVerificationError::class)->reason === 'missing', 'required');

    $transport = $client();
    $gateway->script([['status' => 200, 'body' => ['item' => ['address' => 'bc1q']], 'sign' => 'tamper']]);
    check(thrown(static fn () => $transport->call($read, $params), ResponseVerificationError::class)->reason === 'invalid', 'tampered');
    check(count($gateway->requests()) === 1, 'not retried');

    $transport = $client();
    $gateway->script([['status' => 503, 'body' => '{}', 'sign' => 'partial']]);
    check(thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), ResponseVerificationError::class)->reason === 'missing', 'partial');
    check(count($gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])) === 1, 'an error answer is verified too, and not retried');
};

$tests['transport: a signed answer with no root configured fails closed'] = static function () use ($client, $gateway, $read, $ok): void {
    $transport = $client(['roots' => []]);
    $gateway->script([$ok()]);
    thrown(static fn () => $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']), ConfigurationError::class);
};

$tests['transport: a read is retried after 429 and 5xx, re-signed each time'] = static function () use ($client, $gateway, $read, $ok): void {
    $transport = $client();
    $gateway->script([['status' => 429, 'body' => '{"error":{"code":"request_limit_reached"}}'], ['status' => 502, 'body' => 'Bad Gateway'], $ok()]);
    $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']);
    $nonces = array_column($gateway->requests(), 'nonce');
    check(count($nonces) === 3 && count(array_unique($nonces)) === 3, 'three attempts, three nonces');

    $transport = $client();
    $gateway->script(array_fill(0, 6, ['status' => 429, 'body' => '{"error":{"code":"request_limit_reached"}}']));
    thrown(static fn () => $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']), RateLimitError::class);
    check(count($gateway->requests()) === 5, 'at most 5 attempts');
};

$tests['transport: a write refused with 429 is resent unchanged (same nonce), and runs once'] = static function () use ($client, $gateway, $write, $ok): void {
    $transport = $client();
    $gateway->script([['status' => 429, 'body' => '{"error":{"code":"request_limit_reached"}}'], ['status' => 201, 'body' => ['item' => ['transactionRequestId' => 't1']]]]);
    $result = $transport->call($write, ['vaultId' => 'v1', 'amount' => '1']);
    check($result->data === ['transactionRequestId' => 't1'], 'returned');
    $requests = $gateway->requestsExcept([Keys::SIGNING_KEYS_PATH]);
    check(count($requests) === 2 && $requests[0]['nonce'] === $requests[1]['nonce'], 'the same signed request twice');
};

$tests['transport: a write answered 5xx with a legacy key is outcome unknown, never sent again'] = static function () use ($client, $gateway, $write): void {
    $transport = $client();
    $gateway->script([['status' => 500, 'body' => '{"error":{"code":"unexpected_server_error"}}']]);
    $error = thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), RequestOutcomeUnknownError::class);
    $writes = $gateway->requestsExcept([Keys::SIGNING_KEYS_PATH]);
    check($error->nonce === $writes[0]['nonce'] && !$error->inProgress, 'nonce and not in progress');
    check(count($writes) === 1, 'sent once');
};

$tests['transport: a write whose answer was lost is resent at once with a confirmed key pair, and the replayed first answer returned'] = static function () use ($client, $gateway, $write, $keyFile, $full): void {
    $transport = $client(['privateKeyFile' => $keyFile('ed25519'), 'timeoutSeconds' => 1]);
    $gateway->set(['signingKeys' => [['fingerprint' => $full['keys']['ed25519']['fingerprint'], 'algorithm' => 'ed25519', 'status' => 'active']]]);
    // The gateway carries the transfer out, but its answer arrives after the client gave up.
    $gateway->script([['status' => 201, 'body' => ['item' => ['transactionRequestId' => 't1']], 'delayMs' => 1500]]);
    $result = $transport->call($write, ['vaultId' => 'v1', 'amount' => '1']);
    check($result->meta->replayed === true && $result->data === ['transactionRequestId' => 't1'], 'the first answer, replayed');
    $writes = $gateway->requestsExcept([Keys::SIGNING_KEYS_PATH]);
    check(count($writes) === 2 && $writes[0]['nonce'] === $writes[1]['nonce'], 'one resend of the same request');
    check(count($gateway->requests()) === 4, 'plus the signed read before the first write and the signed confirmation of the key pair');
};

$tests['transport: without a confirmed key pair, a lost answer is outcome unknown'] = static function () use ($client, $gateway, $write, $keyFile, $full, $candidate): void {
    // The key pair is configured, but the API key does not list it as active.
    $transport = $client(['privateKeyFile' => $keyFile('ed25519'), 'timeoutSeconds' => 1]);
    $gateway->set(['signingKeys' => [['fingerprint' => $full['keys']['ed25519']['fingerprint'], 'algorithm' => 'ed25519', 'status' => 'pending']]]);
    $gateway->script([['status' => 201, 'body' => ['item' => []], 'delayMs' => 1500]]);
    thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), RequestOutcomeUnknownError::class);
    check(count($gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])) === 1, 'not resent');

    // Listed as active, but in an unsigned answer (to a client without roots, which accepts it): not trusted either.
    $transport = $client($candidate + ['privateKeyFile' => $keyFile('ed25519'), 'timeoutSeconds' => 1]);
    $gateway->set(['signingKeys' => [['fingerprint' => $full['keys']['ed25519']['fingerprint'], 'algorithm' => 'ed25519', 'status' => 'active']], 'signSigningKeys' => 'no']);
    $gateway->script([['status' => 201, 'body' => ['item' => []], 'delayMs' => 1500]]);
    thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), RequestOutcomeUnknownError::class);
    check(count($gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])) === 1, 'not resent on an unsigned confirmation');
};

$tests['transport: a resend after the replay window learns nothing: outcome unknown, one request'] = static function () use ($client, $gateway, $write, $keyFile, $full): void {
    $transport = $client(['privateKeyFile' => $keyFile('ed25519'), 'timeoutSeconds' => 2.6]);
    $gateway->set(['signingKeys' => [['fingerprint' => $full['keys']['ed25519']['fingerprint'], 'algorithm' => 'ed25519', 'status' => 'active']]]);
    $gateway->script([['status' => 201, 'body' => ['item' => []], 'delayMs' => 3000]]);
    thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), RequestOutcomeUnknownError::class);
    check(count($gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])) === 1, 'not resent past 2.5 s');
};

// Nothing was executed, so the one retry is signed again with a new nonce (with the same one the gateway would
// only replay the conflict) and the same body: the caller gets the retried answer.
$tests['transport: the conflicts the docs say to retry are retried once, with a new nonce and the same body'] = static function () use ($client, $gateway, $write, $ok): void {
    foreach (['address_derivation_conflict', 'vault_accounts_creation_failed'] as $code) {
        $transport = $client();
        $conflict = ['status' => 409, 'body' => '{"error":{"code":"' . $code . '"}}'];
        $gateway->script([$conflict, ['status' => 201, 'body' => ['item' => ['transactionRequestId' => 't1']]]]);
        $result = $transport->call($write, ['vaultId' => 'v1', 'amount' => '1']);
        check($result->data === ['transactionRequestId' => 't1'], $code . ': the retried answer');
        $requests = $gateway->requestsExcept([Keys::SIGNING_KEYS_PATH]);
        check(count($requests) === 2, $code . ': retried once');
        check($requests[0]['nonce'] !== $requests[1]['nonce'], $code . ': a new nonce');
        check($requests[0]['body'] === $requests[1]['body'], $code . ': the same body');
    }

    // Only once: a second conflict reaches the caller, retryable.
    $transport = $client();
    $conflict = ['status' => 409, 'body' => '{"error":{"code":"address_derivation_conflict"}}'];
    $gateway->script([$conflict, $conflict, $ok()]);
    $error = thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), ConflictError::class);
    check($error->retryable && !$error->replayed, 'the second conflict, retryable');
    check(count($gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])) === 2, 'one retry only');
};

$tests['transport: a write signed again keeps its nonce and body, and runs once'] = static function () use ($client, $gateway, $write, $ok): void {
    // A 429 asking to wait 25 s: the signature would be too old to resend, so the write is signed again.
    $transport = $client();
    $gateway->script([['status' => 429, 'body' => '{"error":{"code":"request_limit_reached"}}', 'headers' => ['retry-after' => '25']], ['status' => 201, 'body' => ['item' => ['transactionRequestId' => 't1']]]]);
    $result = $transport->call($write, ['vaultId' => 'v1', 'amount' => '1']);
    check($result->data === ['transactionRequestId' => 't1'], 'returned');
    $requests = $gateway->requestsExcept([Keys::SIGNING_KEYS_PATH]);
    check(count($requests) === 2 && $requests[0]['nonce'] === $requests[1]['nonce'] && $requests[0]['body'] === $requests[1]['body'], 'the same nonce and body');
};

$tests['transport: a write refused with api_nonce_reused is a RequestSigningError, never retried'] = static function () use ($client, $gateway, $write): void {
    $transport = $client();
    $gateway->script([['status' => 409, 'body' => '{"error":{"code":"api_nonce_reused"}}']]);
    $error = thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), RequestSigningError::class);
    check($error->code === 'api_nonce_reused' && !$error->retryable, 'code, not retryable');
    check(count($gateway->requestsExcept([Keys::SIGNING_KEYS_PATH])) === 1, 'sent once');
};

$tests['transport: a connection refused is not sent: a read retries, a write is resent, then the transport error'] = static function () use ($full, $read, $write): void {
    $server = stream_socket_server('tcp://127.0.0.1:0');
    $name = (string) stream_socket_get_name($server, false);
    fclose($server);
    $transport = new Transport([
        'apiKey' => $full['credentials']['apiKey'], 'apiSecret' => $full['credentials']['apiSecret'], 'passphrase' => $full['credentials']['passphrase'],
        'baseUrl' => 'http://' . $name, 'sleep' => static function (int $ms): void {
        }, 'maxRequestsPerSecond' => 1000,
    ]);
    check(thrown(static fn () => $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']), TransportError::class)->sent === false, 'not sent');
    check(thrown(static fn () => $transport->call($write, ['vaultId' => 'v1']), TransportError::class)->sent === false, 'a write that never left is not outcome unknown');
};

$tests['transport: paging through a list goes page by page through the whole pipeline'] = static function () use ($client, $gateway, $vault, $tempDir): void {
    $transport = $client(['vaultKeyStore' => new MemoryVaultKeyStore()]);
    $gateway->set(['vaults' => ['main' => [$vault('m1', 'main', null), $vault('m2', 'main', null), $vault('m3', 'main', null)], 'test' => []]]);
    $ids = [];
    $generator = $transport->paginate(CoreOperations::listVaults(), ['networkType' => 'main', 'limit' => 1]);
    foreach ($generator as $item) {
        $ids[] = $item['id'];
    }
    check($ids === ['m1', 'm2', 'm3'], 'all items ' . json_encode($ids));
    check($generator->getReturn() === 'end', 'end');
    check(array_column($gateway->requests(), 'uri') === ['/vaults/main?limit=1', '/vaults/main?limit=1&startingAfter=m1', '/vaults/main?limit=1&startingAfter=m2'], 'requests');
};

$tests['transport: operations that return addresses or vault keys need a pin store; without one nothing is sent'] = static function () use ($client, $gateway, $deposit): void {
    $transport = $client();
    $error = thrown(static fn () => $transport->call($deposit, ['vaultId' => 'v1', 'blockchain' => 'bitcoin', 'network' => 'mainnet']), ConfigurationError::class);
    check(str_contains($error->getMessage(), 'vaultKeysFile'), 'says what to set');
    thrown(static fn () => $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']), ConfigurationError::class);
    check($gateway->requests() === [], 'nothing sent');
};

$tests['transport: first sight pins the vault from the signed vault list, and the deposit address verifies'] = static function () use ($client, $gateway, $deposit, $btc, $vault, $addressItem, $tempDir, $recordEvents, $eventTypes, $xpubOf): void {
    $file = $tempDir() . '/keys/vault-keys.json';
    $transport = $client(['vaultKeysFile' => $file, 'onSecurityEvent' => $recordEvents()]);
    $gateway->set(['vaults' => ['main' => [$vault('other', 'main', null), $vault('v-main', 'main', $btc['xpub'], $xpubOf('eddsa-test-depth0'))], 'test' => []]]);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)]]]);
    $result = $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet', 'label' => 'TEST']);
    check(array_column($result->meta->addressChecks, 'status') === ['verified'], 'checks ' . json_encode($result->meta->addressChecks));
    check(in_array('vault_key_pinned', $eventTypes(), true), 'pinned event');
    $pins = (new FileVaultKeyStore($file))->read($transport->origin())['vaults'];
    check(array_keys($pins) === ['v-main'] && $pins['v-main']['status'] === 'verified', 'one verified pin; the keyless vault is not pinned');
    check((fileperms($file) & 0777) === 0600, 'pin file mode');
};

$tests['transport: an address that does not derive from the pin refuses the whole answer'] = static function () use ($client, $gateway, $deposit, $listAddresses, $btc, $vault, $addressItem, $tempDir, $recordEvents, $eventTypes, $caseOf): void {
    $transport = $client(['vaultKeyStore' => new MemoryVaultKeyStore(), 'onSecurityEvent' => $recordEvents()]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
    $swapped = $addressItem($btc, ['address' => 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq']);
    $gateway->script([['status' => 201, 'body' => ['item' => $swapped]]]);
    $error = thrown(static fn () => $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']), AddressVerificationError::class);
    check($error->code === 'mismatch', 'mismatch');
    check(in_array('address_verification_failed', $eventTypes(), true), 'event');

    // One wrong address on a page refuses the page.
    $second = $caseOf('bitcoin/mainnet/P2WPKH/ecdsa-bip32-tv1-master/m/1/1/1');
    $gateway->script([['status' => 200, 'body' => ['limit' => 50, 'hasMore' => false, 'items' => [
        $addressItem($btc, ['addressId' => 'a1', 'blockchain' => 'bitcoin']),
        $addressItem($second, ['addressId' => 'a2', 'blockchain' => 'bitcoin', 'address' => $btc['address']]),
    ]]]]);
    thrown(static fn () => $transport->call($listAddresses, ['vaultId' => 'v-main', 'vaultAccountId' => 'acc']), AddressVerificationError::class);
};

$tests['transport: list addresses infers the network from the vault type; SMART vaults and rows without a path are not verifiable'] = static function () use ($client, $gateway, $listAddresses, $btc, $vault, $addressItem, $caseOf): void {
    $transport = $client(['vaultKeyStore' => new MemoryVaultKeyStore()]);
    $solana = $caseOf('solana/devnet/BASE58/eddsa-test-depth0/m/7/0/5');
    $gateway->set(['vaults' => ['main' => [], 'test' => [$vault('v-test', 'test', null, $solana['xpub']), $vault('smart', 'test', null)]]]);
    $gateway->script([
        ['status' => 200, 'body' => ['limit' => 50, 'hasMore' => false, 'items' => [
            $addressItem($solana, ['addressId' => 'a1', 'blockchain' => 'solana']),
            ['addressId' => 'a2', 'address' => 'old-row-address', 'blockchain' => 'solana'],
        ]]],
        ['status' => 200, 'body' => ['limit' => 50, 'hasMore' => false, 'items' => [$addressItem($btc, ['addressId' => 'a3', 'blockchain' => 'bitcoin'])]]],
    ]);
    $page = $transport->call($listAddresses, ['vaultId' => 'v-test', 'vaultAccountId' => 'acc']);
    check($page instanceof Page && array_column($page->meta->addressChecks, 'status') === ['verified', 'not_verifiable'], 'checks ' . json_encode($page->meta->addressChecks));
    $page = $transport->call($listAddresses, ['vaultId' => 'smart', 'vaultAccountId' => 'acc']);
    check(array_column($page->meta->addressChecks, 'status') === ['not_verifiable'], 'SMART vault ' . json_encode($page->meta->addressChecks));
};

$tests['transport: a vault in no vault list is unknown_vault; add asset must return the address sent'] = static function () use ($client, $gateway, $deposit, $addAsset, $btc, $vault, $addressItem): void {
    $transport = $client(['vaultKeyStore' => new MemoryVaultKeyStore()]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)]]]);
    check(thrown(static fn () => $transport->call($deposit, ['vaultId' => 'nowhere', 'blockchain' => 'bitcoin', 'network' => 'mainnet']), AddressVerificationError::class)->code === 'unknown_vault', 'unknown vault');

    $gateway->script([['status' => 200, 'body' => ['item' => $addressItem($btc, ['blockchain' => 'bitcoin', 'network' => 'mainnet'])]]]);
    $result = $transport->call($addAsset, ['vaultId' => 'v-main', 'vaultAccountId' => 'acc', 'assetId' => 'asset', 'address' => $btc['address']]);
    check(array_column($result->meta->addressChecks, 'status') === ['verified'], 'verified');
    $gateway->script([['status' => 200, 'body' => ['item' => $addressItem($btc, ['blockchain' => 'bitcoin', 'network' => 'mainnet'])]]]);
    check(thrown(static fn () => $transport->call($addAsset, ['vaultId' => 'v-main', 'vaultAccountId' => 'acc', 'assetId' => 'asset', 'address' => 'another']), AddressVerificationError::class)->code === 'mismatch', 'another address');
};

$tests['transport: an unsigned vault list pins unverified (TOFU); a signed one with the same xpub upgrades it'] = static function () use ($client, $make, $gateway, $deposit, $btc, $vault, $addressItem, $recordEvents, $eventTypes, $candidate): void {
    $store = new MemoryVaultKeyStore();
    $hook = $recordEvents();
    // A release candidate before production signs, then the upgrade with roots, on the same store.
    $transport = $client($candidate + ['vaultKeyStore' => $store, 'onSecurityEvent' => $hook]);
    $upgraded = $make(['vaultKeyStore' => $store, 'onSecurityEvent' => $hook]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []], 'signVaults' => 'no']);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)], 'sign' => 'no']]);
    check(array_column($transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet'])->meta->addressChecks, 'status') === ['unverified'], 'unverified, never verified');

    $gateway->set(['signVaults' => 'yes']);
    $upgraded->call(CoreOperations::listVaults(), ['networkType' => 'main']);
    check($store->read($transport->origin())['vaults']['v-main']['status'] === 'verified', 'upgraded');
    check(in_array('vault_key_verified', $eventTypes(), true), 'event');
};

$tests['transport: a changed xpub raises the alarm, refuses the answer and never re-pins'] = static function () use ($client, $gateway, $deposit, $btc, $vault, $addressItem, $xpubOf, $recordEvents, $eventTypes, $tempDir): void {
    $file = $tempDir() . '/vault-keys.json';
    $transport = $client(['vaultKeysFile' => $file]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)]]]);
    $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']);
    $before = file_get_contents($file);

    $later = $client(['vaultKeysFile' => $file, 'onSecurityEvent' => $recordEvents()]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $xpubOf('ecdsa-bip32-tv1-m0h'))], 'test' => []]]);
    $error = thrown(static fn () => $later->call(CoreOperations::listVaults(), ['networkType' => 'main']), VaultKeyChangedError::class);
    check($error->alarms[0]['reason'] === 'xpub_changed' && $error->alarms[0]['vaultId'] === 'v-main', 'alarm');
    check(!str_contains($error->getMessage(), $btc['xpub']), 'no xpub in the message');
    check($eventTypes() === ['vault_key_changed'], 'events ' . json_encode($eventTypes()));
    check(file_get_contents($file) === $before, 'pin untouched');
};

$tests['transport: pinnedVaultKeys is checked when the client is made, and never shows an xpub'] = static function () use ($full, $btc): void {
    $credentials = ['apiKey' => 'k', 'apiSecret' => $full['credentials']['apiSecret'], 'passphrase' => 'p'];
    $good = ['vaultId' => 'v-main', 'type' => 'main', 'keys' => ['ECDSA' => $btc['xpub'], 'EDDSA' => null]];
    foreach ([
        'not a list' => ['v-main' => $good],
        'a string' => $btc['xpub'],
        'an entry that is not an array' => [$btc['xpub']],
        'an unknown key' => [$good + ['status' => 'verified']],
        'no keys' => [['vaultId' => 'v-main', 'type' => 'main']],
        'an empty vault id' => [['vaultId' => ''] + $good],
        'another type' => [['type' => 'MAIN'] + $good],
        'EDDSA left out' => [['keys' => ['ECDSA' => $btc['xpub']]] + $good],
        'an unknown algorithm' => [['keys' => ['ECDSA' => $btc['xpub'], 'EDDSA' => null, 'SCHNORR' => null]] + $good],
        'an empty xpub' => [['keys' => ['ECDSA' => '', 'EDDSA' => null]] + $good],
        'no xpub at all' => [['keys' => ['ECDSA' => null, 'EDDSA' => null]] + $good],
        'a vault twice' => [$good, $good],
    ] as $what => $value) {
        $error = thrown(static fn () => new Transport($credentials + ['pinnedVaultKeys' => $value]), ConfigurationError::class);
        check(str_contains($error->getMessage(), 'pinnedVaultKeys'), $what . ': names the option');
        check(!str_contains($error->getMessage(), $btc['xpub']) && !str_contains((string) $error, $btc['xpub']), $what . ': no xpub in the error');
    }
    check(str_contains(thrown(static fn () => new Transport($credentials + ['pinnedVaultKeys' => [$good, ['vaultId' => 'v2'] + $good, ['vaultId' => ''] + $good]]), ConfigurationError::class)->getMessage(), 'pinnedVaultKeys[2]'), 'names the entry');

    $transport = new Transport($credentials + ['pinnedVaultKeys' => [$good]]);
    $dumped = print_r($transport, true) . var_export((array) [$transport], true) . var_export((array) $transport, true) . json_encode((array) $transport);
    ob_start();
    var_dump($transport);
    $dumped .= (string) ob_get_clean();
    check(!str_contains($dumped, $btc['xpub']), 'an xpub in the debug output');
    check($transport->__debugInfo()['pinnedVaultKeys'] === 1, 'a count only');
};

$tests['transport: a configured pin counts as verified, even from an unsigned list, and is never stored'] = static function () use ($client, $gateway, $deposit, $btc, $vault, $addressItem, $recordEvents, $eventTypes, $candidate): void {
    $store = new MemoryVaultKeyStore();
    $transport = $client($candidate + ['vaultKeyStore' => $store, 'onSecurityEvent' => $recordEvents(),
        'pinnedVaultKeys' => [['vaultId' => 'v-main', 'type' => 'main', 'keys' => ['ECDSA' => $btc['xpub'], 'EDDSA' => null]]]]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub']), $vault('v-other', 'main', $btc['xpub'])], 'test' => []], 'signVaults' => 'no']);
    $page = $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']);
    check($page->meta->signature === 'absent', 'unsigned');
    check($page->meta->vaultKeys === [
        ['vaultId' => 'v-main', 'status' => 'verified', 'outcome' => 'unchanged'],
        ['vaultId' => 'v-other', 'status' => 'unverified', 'outcome' => 'pinned'],
    ], 'configured verified, the other pinned as usual ' . json_encode($page->meta->vaultKeys));
    check(array_keys($store->read($transport->origin())['vaults']) === ['v-other'], 'the configured vault is not written to the store');
    check(!in_array('vault_key_verified', $eventTypes(), true) && count(array_keys($eventTypes(), 'vault_key_pinned', true)) === 1, 'no event for the configured vault ' . json_encode($eventTypes()));

    // Its addresses verify against it, without listing the vaults first.
    $transport = $client($candidate + ['vaultKeyStore' => new MemoryVaultKeyStore(),
        'pinnedVaultKeys' => [['vaultId' => 'v-main', 'type' => 'main', 'keys' => ['ECDSA' => $btc['xpub'], 'EDDSA' => null]]]]);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)], 'sign' => 'no']]);
    $result = $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']);
    check(array_column($result->meta->addressChecks, 'status') === ['verified'], 'verified ' . json_encode($result->meta->addressChecks));
    check(count($gateway->requests()) === 1, 'no vault list asked for');
};

$tests['transport: a configured pin that differs from the answer is the alarm; the stored pin of that vault is neither read nor changed'] = static function () use ($client, $make, $gateway, $deposit, $btc, $vault, $addressItem, $xpubOf, $recordEvents, $eventTypes, $caseOf, $candidate): void {
    $other = $xpubOf('ecdsa-bip32-tv1-m0h');
    $store = new MemoryVaultKeyStore();
    $configured = [['vaultId' => 'v-main', 'type' => 'main', 'keys' => ['ECDSA' => $btc['xpub'], 'EDDSA' => null]]];
    $hook = $recordEvents();
    // A release candidate for the unsigned answers, then the upgrade with roots for the signed ones, on the same store.
    $plain = $client($candidate + ['vaultKeyStore' => $store, 'onSecurityEvent' => $hook, 'pinnedVaultKeys' => $configured]);
    $transport = $make(['vaultKeyStore' => $store, 'onSecurityEvent' => $hook, 'pinnedVaultKeys' => $configured]);
    $stale = ['vaultId' => 'v-main', 'type' => 'main', 'keys' => ['ECDSA' => $other, 'EDDSA' => null], 'status' => 'unverified', 'firstSeenAt' => 1, 'verifiedAt' => null, 'verification' => null];
    $store->update($transport->origin(), static fn (array $state): array => ['vaults' => ['v-main' => $stale]] + $state);
    $before = $store->read($transport->origin());

    // A stored pin of the same vault, with another xpub: the configured one takes its place. Unsigned first, since
    // the first verified answer makes the client refuse unsigned ones.
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []], 'signVaults' => 'no']);
    check($plain->call(CoreOperations::listVaults(), ['networkType' => 'main'])->meta->vaultKeys === [['vaultId' => 'v-main', 'status' => 'verified', 'outcome' => 'unchanged']], 'compared with the configured xpub only');

    foreach (['no' => $plain, 'yes' => $transport] as $signed => $by) {
        $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $other), $vault('v-new', 'main', $btc['xpub'])], 'test' => []], 'signVaults' => $signed]);
        $error = thrown(static fn () => $by->call(CoreOperations::listVaults(), ['networkType' => 'main']), VaultKeyChangedError::class);
        check($error->alarms === [['vaultId' => 'v-main', 'algorithm' => 'ECDSA', 'reason' => 'xpub_changed', 'pinned' => substr(hash('sha256', $btc['xpub']), 0, 16), 'seen' => substr(hash('sha256', $other), 0, 16)]], $signed . ': alarm ' . json_encode($error->alarms));
        check(!str_contains($error->getMessage(), $btc['xpub']) && !str_contains($error->getMessage(), $other), $signed . ': no xpub in the message');
    }
    check(array_count_values($eventTypes())['vault_key_changed'] === 2, 'the alarm event each time');
    // (The first verified answer latched the origin: that is the only change.)
    check($store->read($transport->origin())['vaults'] === $before['vaults'], 'no pin changed: the stale pin is still there and the new vault was not pinned');

    // An address of the stale stored xpub is refused: only the configured pin counts.
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []], 'signVaults' => 'yes']);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($caseOf('bitcoin/mainnet/P2WPKH/ecdsa-bip32-tv1-m0h/m/0/0/0'))]]]);
    check(thrown(static fn () => $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']), AddressVerificationError::class)->code === 'mismatch', 'mismatch against the configured pin');

    // A configured vault that gains an algorithm, or is listed as another type, is refused too.
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'], $xpubOf('eddsa-test-depth0'))], 'test' => []]]);
    check(thrown(static fn () => $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']), VaultKeyChangedError::class)->alarms[0]['reason'] === 'xpub_added', 'xpub_added');
    $gateway->set(['vaults' => ['main' => [], 'test' => [$vault('v-main', 'test', $btc['xpub'])]]]);
    check(thrown(static fn () => $transport->call(CoreOperations::listVaults(), ['networkType' => 'test']), VaultKeyChangedError::class)->alarms[0]['reason'] === 'type_changed', 'type_changed');
};

$tests['transport: configured pins do not replace the pin store'] = static function () use ($client, $gateway, $deposit, $btc): void {
    $transport = $client(['pinnedVaultKeys' => [['vaultId' => 'v-main', 'type' => 'main', 'keys' => ['ECDSA' => $btc['xpub'], 'EDDSA' => null]]]]);
    thrown(static fn () => $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']), ConfigurationError::class);
    check($gateway->requests() === [], 'nothing sent');
};

$tests['transport: the first unsigned answer a client accepts raises unsigned_response_accepted once, then one warning; each client once'] = static function () use ($client, $gateway, $read, $recordEvents, $eventTypes, &$events, $candidate): void {
    $unsigned = ['status' => 200, 'body' => ['item' => ['n' => 1]], 'sign' => 'no'];
    $params = ['vaultId' => 'v1', 'vaultAccountId' => 'a1'];
    $logger = new RecordingLogger();
    $transport = $client($candidate + ['onSecurityEvent' => $recordEvents(), 'logger' => $logger]);
    $gateway->script([$unsigned, $unsigned, $unsigned]);
    for ($i = 0; $i < 3; $i++) {
        check($transport->call($read, $params)->meta->signature === 'absent', 'accepted');
    }
    check($events === [['type' => 'unsigned_response_accepted', 'origin' => $transport->origin(), 'operationId' => 'getVaultAccountById']], 'one event, exactly these fields ' . json_encode($events));
    check(count($logger->warnings) === 1 && str_contains($logger->warnings[0], $transport->origin()) && str_contains($logger->warnings[0], 'not signed'), 'one warning ' . json_encode($logger->warnings));

    // Another client (another PHP request) reports it again, once.
    $second = new RecordingLogger();
    $other = $client($candidate + ['onSecurityEvent' => $recordEvents(), 'logger' => $second]);
    $gateway->script([$unsigned, $unsigned]);
    $other->call($read, $params);
    $other->call($read, $params);
    check($eventTypes() === ['unsigned_response_accepted'] && count($second->warnings) === 1, 'once for the second client too');

    // A signed answer raises no such event; required refuses instead of reporting.
    $quiet = new RecordingLogger();
    $signedOnly = $client(['onSecurityEvent' => $recordEvents(), 'logger' => $quiet]);
    $gateway->script([['status' => 200, 'body' => ['item' => ['n' => 1]]]]);
    $signedOnly->call($read, $params);
    check(!in_array('unsigned_response_accepted', $eventTypes(), true) && $quiet->warnings === [], 'nothing for a signed answer');

    // A logger that is not one is refused at setup; one that throws never breaks the call.
    thrown(static fn () => $client(['logger' => new stdClass()]), ConfigurationError::class);
    $throwing = new class () {
        public function warning(string $message): void
        {
            throw new RuntimeException('logger down');
        }
    };
    $transport = $client($candidate + ['logger' => $throwing]);
    $gateway->script([$unsigned]);
    check($transport->call($read, $params)->meta->signature === 'absent', 'the call still answers');
};

$tests['transport: every vault list page says per vault what became of its pin: pinned, unchanged, upgraded, not verifiable'] = static function () use ($client, $make, $gateway, $btc, $vault, $xpubOf, $candidate): void {
    $store = new MemoryVaultKeyStore();
    // A release candidate for the unsigned lists, then the upgrade with roots, on the same store.
    $plain = $client($candidate + ['vaultKeyStore' => $store]);
    $transport = $make(['vaultKeyStore' => $store]);
    $eddsa = $xpubOf('eddsa-test-depth0');
    $gateway->set(['vaults' => ['main' => [$vault('v-a', 'main', $btc['xpub']), $vault('smart', 'main', null), $vault('v-b', 'MAIN', null, $eddsa)], 'test' => []], 'signVaults' => 'no']);
    $page = $plain->call(CoreOperations::listVaults(), ['networkType' => 'main']);
    check($page->meta->vaultKeys === [
        ['vaultId' => 'v-a', 'status' => 'unverified', 'outcome' => 'pinned'],
        ['vaultId' => 'smart', 'status' => 'not_verifiable', 'outcome' => 'not_verifiable'],
        ['vaultId' => 'v-b', 'status' => 'unverified', 'outcome' => 'pinned'],
    ], 'first sight, unsigned ' . json_encode($page->meta->vaultKeys));
    check($store->read($transport->origin())['vaults']['v-b']['type'] === 'main', 'the type is pinned lowercase');
    check(array_column($page->meta->addressChecks, 'status') === [], 'no address checks on a vault list');

    $page = $plain->call(CoreOperations::listVaults(), ['networkType' => 'main']);
    check(array_column($page->meta->vaultKeys, 'outcome') === ['unchanged', 'not_verifiable', 'unchanged'] && array_column($page->meta->vaultKeys, 'status') === ['unverified', 'not_verifiable', 'unverified'], 'again ' . json_encode($page->meta->vaultKeys));

    $gateway->set(['signVaults' => 'yes']);
    $page = $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']);
    check(array_column($page->meta->vaultKeys, 'outcome') === ['upgraded', 'not_verifiable', 'upgraded'] && array_column($page->meta->vaultKeys, 'status') === ['verified', 'not_verifiable', 'verified'], 'signed ' . json_encode($page->meta->vaultKeys));
    $page = $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']);
    check(array_column($page->meta->vaultKeys, 'status') === ['verified', 'not_verifiable', 'verified'] && array_column($page->meta->vaultKeys, 'outcome') === ['unchanged', 'not_verifiable', 'unchanged'], 'verified, unchanged');

    // Page by page: each page carries the vaults of that page.
    $page = $transport->call(CoreOperations::listVaults(), ['networkType' => 'main', 'limit' => 1]);
    check(array_column($page->meta->vaultKeys, 'vaultId') === ['v-a'], 'first page');
    $page = $transport->call(CoreOperations::listVaults(), ['networkType' => 'main', 'limit' => 1, 'startingAfter' => 'v-a']);
    check($page->meta->vaultKeys === [['vaultId' => 'smart', 'status' => 'not_verifiable', 'outcome' => 'not_verifiable']], 'second page');
};

$tests['transport: base URLs other than https (or http to this machine) are refused, and unknown options too'] = static function () use ($full): void {
    $credentials = ['apiKey' => 'k', 'apiSecret' => $full['credentials']['apiSecret'], 'passphrase' => 'p'];
    foreach (['http://rest.vaultody.com', 'https://user:pw@rest.vaultody.com', 'https://rest.vaultody.com/?a=b', 'ftp://x', 'rest.vaultody.com'] as $url) {
        thrown(static fn () => new Transport($credentials + ['baseUrl' => $url]), ConfigurationError::class);
    }
    check((new Transport($credentials + ['baseUrl' => 'https://REST.vaultody.com/']))->origin() === 'https://rest.vaultody.com', 'origin');
    check((new Transport($credentials + ['baseUrl' => 'http://localhost:8080']))->origin() === 'http://localhost:8080', 'loopback');
    // The origin pins are kept under: no default port, as Node's URL writes it.
    check((new Transport($credentials + ['baseUrl' => 'https://rest.vaultody.com:443/v2']))->origin() === 'https://rest.vaultody.com', 'https default port');
    check((new Transport($credentials + ['baseUrl' => 'http://127.0.0.1:80']))->origin() === 'http://127.0.0.1', 'http default port');
    check((new Transport($credentials + ['baseUrl' => 'https://rest.vaultody.com:8443']))->origin() === 'https://rest.vaultody.com:8443', 'another port');
    thrown(static fn () => new Transport($credentials + ['vaultKeyFile' => '/tmp/x']), ConfigurationError::class);
    thrown(static fn () => new Transport(['apiKey' => 'k', 'apiSecret' => 'not base64!', 'passphrase' => 'p']), ConfigurationError::class);
    thrown(static fn () => new Transport($credentials + ['responseSignature' => 'off']), ConfigurationError::class);
};

$tests['transport: no secret in debug output, serialisation or errors'] = static function () use ($full, $keyFile, $client, $gateway, $read): void {
    $credentials = ['apiKey' => $full['credentials']['apiKey'], 'apiSecret' => $full['credentials']['apiSecret'], 'passphrase' => $full['credentials']['passphrase']];
    $transport = new Transport($credentials + ['privateKeyFile' => $keyFile('ed25519')]);
    $dumped = print_r($transport, true) . var_export((array) [$transport], true);
    ob_start();
    var_dump($transport);
    $dumped .= (string) ob_get_clean();
    foreach ($credentials as $secret) {
        check(!str_contains($dumped, $secret), 'a credential in the debug output');
    }
    thrown(static fn () => serialize($transport), LogicException::class);
    $error = thrown(static fn () => new Transport(['apiKey' => 'k', 'apiSecret' => 'secret with spaces', 'passphrase' => 'p']), ConfigurationError::class);
    check(!str_contains($error->getMessage(), 'secret with spaces'), 'the secret in an error');
    check(!str_contains((string) $error, 'secret with spaces'), 'the secret in a stack trace');
};

$tests['transport: the events of one run have exactly the catalogued fields and values; address checks are {vaultId, address, status}'] = static function () use ($client, $make, $gateway, $deposit, $btc, $vault, $addressItem, $recordEvents, &$events, $candidate): void {
    $store = new MemoryVaultKeyStore();
    $hook = $recordEvents();
    // A release candidate before production signs, then the upgrade with roots, on the same store.
    $plain = $client($candidate + ['vaultKeyStore' => $store, 'onSecurityEvent' => $hook]);
    $transport = $make(['vaultKeyStore' => $store, 'onSecurityEvent' => $hook]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []], 'signVaults' => 'no']);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)], 'sign' => 'no']]);
    $first = $plain->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']);
    check($first->meta->addressChecks === [['vaultId' => 'v-main', 'address' => $btc['address'], 'status' => 'unverified']], 'address checks ' . json_encode($first->meta->addressChecks));

    // Signed from now on: the latch, then the pin confirmed.
    $gateway->set(['signVaults' => 'yes']);
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)]]]);
    $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']);
    $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']);
    // A swapped address.
    $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc, ['address' => 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'])]]]);
    thrown(static fn () => $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']), AddressVerificationError::class);

    $byType = [];
    foreach ($events as $event) {
        $byType[$event['type']] ??= $event;
    }
    foreach (['unsigned_response_accepted', 'vault_key_pinned', 'response_signature_latched', 'vault_key_verified', 'address_verification_failed'] as $type) {
        check(isset($byType[$type]), 'no ' . $type . ' in ' . json_encode(array_keys($byType)));
    }
    $origin = $transport->origin();
    check($byType['unsigned_response_accepted'] === ['type' => 'unsigned_response_accepted', 'origin' => $origin, 'operationId' => 'generateDepositAddress'], 'unsigned ' . json_encode($byType['unsigned_response_accepted']));
    check($byType['vault_key_pinned'] === ['type' => 'vault_key_pinned', 'origin' => $origin, 'vaultId' => 'v-main', 'status' => 'unverified'], 'pinned');
    $latched = $byType['response_signature_latched'];
    check(array_keys($latched) === ['type', 'origin', 'rootId', 'latchedAt'] && is_string($latched['rootId']) && $latched['rootId'] !== '' && is_int($latched['latchedAt']), 'latched ' . json_encode($latched));
    check($byType['vault_key_verified'] === ['type' => 'vault_key_verified', 'origin' => $origin, 'vaultId' => 'v-main', 'status' => 'verified'], 'verified');
    check($byType['address_verification_failed'] === ['type' => 'address_verification_failed', 'origin' => $origin, 'operationId' => 'generateDepositAddress', 'vaultId' => 'v-main', 'code' => 'mismatch'], 'address ' . json_encode($byType['address_verification_failed']));
};

$tests['transport: a vault listed under the other type is refused (ApiError), as in Node and Python, and nothing is pinned'] = static function () use ($client, $gateway, $btc, $vault): void {
    $store = new MemoryVaultKeyStore();
    $transport = $client(['vaultKeyStore' => $store]);
    $gateway->set(['vaults' => ['main' => [$vault('v-test', 'test', $btc['xpub'])], 'test' => []]]);
    $error = thrown(static fn () => $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']), ApiError::class);
    check($error->code === null && $error->status === 200, 'an ApiError without a code');
    check($store->read($transport->origin())['vaults'] === [], 'nothing pinned');
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'MAIN', $btc['xpub'])], 'test' => []]]);
    check(array_column($transport->call(CoreOperations::listVaults(), ['networkType' => 'main'])->meta->vaultKeys, 'outcome') === ['pinned'], 'the type is compared case-insensitively');
};

$tests['transport: an item on another network than asked is network_mismatch, on another chain mismatch, as in Node and Python'] = static function () use ($client, $gateway, $deposit, $btc, $vault, $addressItem, $recordEvents, &$events): void {
    $codes = array_column(vectors('security-events-v1.json')['addressCodes'], 'code');
    foreach ([[['network' => 'testnet'], 'network_mismatch'], [['blockchain' => 'litecoin'], 'mismatch'], [['network' => 'mainnet', 'blockchain' => 'bitcoin'], null]] as [$extra, $code]) {
        $transport = $client(['vaultKeyStore' => new MemoryVaultKeyStore(), 'onSecurityEvent' => $recordEvents()]);
        $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
        $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc, $extra)]]]);
        $call = static fn () => $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']);
        if ($code === null) {
            check(array_column($call()->meta->addressChecks, 'status') === ['verified'], 'the requested chain and network pass');
            continue;
        }
        check(thrown($call, AddressVerificationError::class)->code === $code, $code);
        check(in_array($code, $codes, true), $code . ' in the vector');
        $failed = array_values(array_filter($events, static fn (array $event): bool => $event['type'] === 'address_verification_failed'));
        check(count($failed) === 1 && $failed[0]['code'] === $code, 'event ' . json_encode($failed));
    }
};

$tests['transport: with no hook every security event is logged once as a warning, its JSON; with a hook nothing is; a hook that throws is logged'] = static function () use ($client, $gateway, $deposit, $btc, $vault, $addressItem): void {
    // [hook, events logged, 'hook raised' lines]; the run raises response_signature_latched and vault_key_pinned.
    foreach ([[null, true, 0], [static function (array $event): void {
    }, false, 0], [static function (array $event): void {
        throw new RuntimeException('hook down');
    }, false, 2]] as [$hook, $expectLines, $expectRaised]) {
        $logger = new RecordingLogger();
        $transport = $client(['vaultKeyStore' => new MemoryVaultKeyStore(), 'logger' => $logger] + ($hook === null ? [] : ['onSecurityEvent' => $hook]));
        $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
        $gateway->script([['status' => 201, 'body' => ['item' => $addressItem($btc)]]]);
        $transport->call($deposit, ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet']);
        $prefix = 'Vaultody security event: ';
        $lines = array_values(array_filter($logger->warnings, static fn (string $line): bool => str_starts_with($line, $prefix)));
        $raised = array_filter($logger->warnings, static fn (string $line): bool => str_starts_with($line, 'the security event hook raised on '));
        if ($expectLines) {
            $logged = array_map(static fn (string $line): array => json_decode(substr($line, strlen($prefix)), true, 16, JSON_THROW_ON_ERROR), $lines);
            check(array_column($logged, 'type') === ['response_signature_latched', 'vault_key_pinned'], 'logged ' . json_encode($logged));
            check(array_keys($logged[1]) === ['type', 'origin', 'vaultId', 'status'], 'fields');
            check(!str_contains(implode("\n", $lines), $btc['xpub']), 'no xpub logged');
        } else {
            check($lines === [], 'nothing logged with a hook');
        }
        check(count($raised) === $expectRaised, 'hook raised ' . count($raised));
    }
};

$tests['transport: a store that does not keep the pin just written is store_conflict, as in Node and Python'] = static function () use ($client, $gateway, $btc, $vault): void {
    $forgetful = new class implements \Vaultody\Sdk\VaultKeys\VaultKeyStore {
        public function read(string $origin): array
        {
            return ['responseSignature' => null, 'vaults' => [], 'audit' => []];
        }

        public function update(string $origin, callable $change): array
        {
            $change($this->read($origin));

            return $this->read($origin);
        }
    };
    $transport = $client(['vaultKeyStore' => $forgetful]);
    $gateway->set(['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub'])], 'test' => []]]);
    $error = thrown(static fn () => $transport->call(CoreOperations::listVaults(), ['networkType' => 'main']), \Vaultody\Sdk\Exception\VaultKeyStoreError::class);
    check($error->code === 'store_conflict', 'code ' . $error->code);
};

$tests['transport: no roots and a signing gateway: ConfigurationError, and the origin latches with rootId null, so a stripped signature is refused from then on'] = static function () use ($client, $make, $gateway, $read, $ok, $recordEvents, &$events, $candidate): void {
    // A release candidate without an embedded root once production signs: it has no root to check a signature with.
    $store = new MemoryVaultKeyStore();
    $transport = $client($candidate + ['embeddedRoots' => [], 'vaultKeyStore' => $store, 'onSecurityEvent' => $recordEvents()]);
    $params = ['vaultId' => 'v1', 'vaultAccountId' => 'a1'];
    $unsigned = ['status' => 200, 'body' => ['item' => ['n' => 1]], 'sign' => 'no'];
    $gateway->script([$ok(), $unsigned, $unsigned]);
    check(thrown(static fn () => $transport->call($read, $params), ConfigurationError::class)->code === 'no_root_keys', 'code no_root_keys');
    $latch = $store->read($transport->origin())['responseSignature'];
    check(is_array($latch) && array_keys($latch) === ['latchedAt', 'rootId'] && $latch['rootId'] === null && is_int($latch['latchedAt']), 'latched without a root ' . json_encode($latch));
    check($events === [['type' => 'response_signature_latched', 'origin' => $transport->origin(), 'rootId' => null, 'latchedAt' => $latch['latchedAt']]], 'the latch, as stored; no refused answer for a setup error ' . json_encode($events));

    // The signature stripped from the next answer on the way.
    check(thrown(static fn () => $transport->call($read, $params), ResponseVerificationError::class)->reason === 'missing', 'refused as missing');
    // A new client on the same store (the next PHP request) is strict from its first call.
    $later = $make($candidate + ['vaultKeyStore' => $store]);
    check(thrown(static fn () => $later->call($read, $params), ResponseVerificationError::class)->reason === 'missing', 'a new client is strict at once');
    check(count($gateway->requests()) === 3, 'none retried');
};

$tests['transport: roots and a gateway that does not sign: a read is refused as missing, sent once; a write is never sent, refused by the signed read before it'] = static function () use ($client, $gateway, $read, $write, $recordEvents, $eventTypes): void {
    $store = new MemoryVaultKeyStore();
    $transport = $client(['vaultKeyStore' => $store, 'onSecurityEvent' => $recordEvents()]);
    check($transport->responseSignature() === 'required', 'roots make it strict');
    $gateway->set(['signSigningKeys' => 'no']);
    $gateway->script([['status' => 200, 'body' => ['item' => []], 'sign' => 'no'], ['status' => 201, 'body' => ['item' => []], 'sign' => 'no']]);
    check(thrown(static fn () => $transport->call($read, ['vaultId' => 'v1', 'vaultAccountId' => 'a1']), ResponseVerificationError::class)->reason === 'missing', 'the read');
    check(count($gateway->requests()) === 1, 'one request, not retried');

    check(thrown(static fn () => $transport->call($write, ['vaultId' => 'v1', 'amount' => '1']), ResponseVerificationError::class)->reason === 'missing', 'the write');
    check(array_column($gateway->requests(), 'path') === ['/vaults/v1/vault-accounts/a1', Keys::SIGNING_KEYS_PATH], 'only the signed read went out, the write never did: ' . json_encode(array_column($gateway->requests(), 'path')));
    check($store->read($transport->origin())['responseSignature'] === null, 'nothing latched: no answer carried a signature');
    check($eventTypes() === ['response_verification_failed', 'response_verification_failed'], 'events ' . json_encode($eventTypes()));
};

$tests['transport: with roots, the first write is preceded by exactly one signed read; later writes, and a client whose origin is latched, by none'] = static function () use ($client, $gateway, $write, $ok, $recordEvents, $eventTypes, $candidate): void {
    $store = new MemoryVaultKeyStore();
    $transport = $client(['vaultKeyStore' => $store, 'onSecurityEvent' => $recordEvents()]);
    $gateway->script([$ok(), $ok()]);
    $transport->call($write, ['vaultId' => 'v1', 'amount' => '1']);
    $transport->call($write, ['vaultId' => 'v1', 'amount' => '2']);
    $requests = $gateway->requests();
    check(array_column($requests, 'path') === [Keys::SIGNING_KEYS_PATH, '/vaults/v1/transactions/single', '/vaults/v1/transactions/single'] && $requests[0]['method'] === 'GET', 'one signed read, first: ' . json_encode(array_column($requests, 'path')));
    check($eventTypes() === ['response_signature_latched'], 'the read latched the origin ' . json_encode($eventTypes()));

    // A new client on that store: the origin is latched already, so it writes at once.
    $later = $client(['vaultKeyStore' => $store]);
    $gateway->script([$ok()]);
    $later->call($write, ['vaultId' => 'v1', 'amount' => '3']);
    check(array_column($gateway->requests(), 'path') === ['/vaults/v1/transactions/single'], 'no read');

    // A client without roots makes none: it has nothing to check a signature with.
    $transport = $client($candidate);
    $gateway->script([['status' => 201, 'body' => ['item' => ['ok' => true]], 'sign' => 'no']]);
    $transport->call($write, ['vaultId' => 'v1', 'amount' => '4']);
    check(array_column($gateway->requests(), 'path') === ['/vaults/v1/transactions/single'], 'no read without roots');
};

$tests['transport: the signed read before a write: a verified error answer settles it; a network failure leaves it open and the write goes ahead'] = static function () use ($make, $gateway, $write, $ok): void {
    // An error answer that passed its signature check: the origin signs.
    $gateway->reset();
    $gateway->set(['routes' => [Keys::SIGNING_KEYS_PATH => [['status' => 403, 'body' => '{"error":{"code":"forbidden","message":"TEST"}}']]]]);
    $gateway->script([$ok(), $ok()]);
    $transport = $make();
    $transport->call($write, ['vaultId' => 'v1', 'amount' => '1']);
    $transport->call($write, ['vaultId' => 'v1', 'amount' => '2']);
    check(array_column($gateway->requests(), 'path') === [Keys::SIGNING_KEYS_PATH, '/vaults/v1/transactions/single', '/vaults/v1/transactions/single'], 'one read, answered 403: ' . json_encode(array_column($gateway->requests(), 'path')));

    // The read never reaches the gateway: not settled, and the write's own answer is checked as always.
    $refusing = new class () implements HttpClient {
        public int $refused = 0;
        private CurlHttpClient $inner;

        public function __construct()
        {
            $this->inner = new CurlHttpClient(5000, 5000);
        }

        public function send(HttpRequest $request): HttpResponse
        {
            if (str_contains($request->url, Keys::SIGNING_KEYS_PATH)) {
                $this->refused++;
                throw new TransportError('TEST connection refused', false);
            }

            return $this->inner->send($request);
        }
    };
    $gateway->reset();
    $gateway->script([$ok(['id' => 'w1']), $ok(['id' => 'w2'])]);
    $transport = $make(['httpClient' => $refusing]);
    check($transport->call($write, ['vaultId' => 'v1', 'amount' => '1'])->data === ['id' => 'w1'], 'the write went ahead, verified');
    check($refusing->refused > 0 && array_column($gateway->requests(), 'path') === ['/vaults/v1/transactions/single'], 'the read never arrived');
    $refused = $refusing->refused;
    $transport->call($write, ['vaultId' => 'v1', 'amount' => '2']);
    check($refusing->refused === $refused, 'the write\'s signed answer latched the origin: no read after it');
};

$tests['transport: requireAddressPaths: a new deposit address without its path is path_missing for a vault with MPC keys; not verifiable for a SMART vault, a list, an unknown chain, or with the option off'] = static function () use ($client, $gateway, $deposit, $listAddresses, $btc, $vault, $recordEvents, &$events): void {
    $pathless = ['address' => $btc['address'], 'label' => 'TEST'];
    $params = ['vaultId' => 'v-main', 'blockchain' => 'bitcoin', 'network' => 'mainnet'];
    $vaults = ['vaults' => ['main' => [$vault('v-main', 'main', $btc['xpub']), $vault('smart', 'main', null)], 'test' => []]];
    $transport = $client(['vaultKeyStore' => new MemoryVaultKeyStore(), 'onSecurityEvent' => $recordEvents(), 'requireAddressPaths' => true]);
    $gateway->set($vaults);
    $gateway->script([
        ['status' => 201, 'body' => ['item' => $pathless]],
        ['status' => 201, 'body' => ['item' => $pathless]],
        ['status' => 201, 'body' => ['item' => $pathless]],
        ['status' => 200, 'body' => ['limit' => 50, 'hasMore' => false, 'items' => [['addressId' => 'a1', 'blockchain' => 'bitcoin'] + $pathless]]],
    ]);
    check(thrown(static fn () => $transport->call($deposit, $params), AddressVerificationError::class)->code === 'path_missing', 'path_missing');
    $failed = array_values(array_filter($events, static fn (array $event): bool => $event['type'] === 'address_verification_failed'));
    check($failed === [['type' => 'address_verification_failed', 'origin' => $transport->origin(), 'operationId' => 'generateDepositAddress', 'vaultId' => 'v-main', 'code' => 'path_missing']], 'the event first ' . json_encode($failed));
    check(in_array('path_missing', array_column(vectors('security-events-v1.json')['addressCodes'], 'code'), true), 'a catalogued code');

    $result = $transport->call($deposit, ['vaultId' => 'smart'] + $params);
    check(array_column($result->meta->addressChecks, 'status') === ['not_verifiable'], 'a SMART vault has nothing to derive');
    $result = $transport->call($deposit, ['blockchain' => 'not-a-chain-this-sdk-knows'] + $params);
    check(array_column($result->meta->addressChecks, 'status') === ['not_verifiable'], 'a chain this SDK does not derive');
    $page = $transport->call($listAddresses, ['vaultId' => 'v-main', 'vaultAccountId' => 'acc']);
    check(array_column($page->meta->addressChecks, 'status') === ['not_verifiable'], 'a list may hold older rows without a path');

    // Off: not verifiable, and no vault list is read for it. The default is the build's ADDRESS_PATHS_PUBLIC.
    foreach ([['requireAddressPaths' => false], []] as $option) {
        $off = $client($option + ['vaultKeyStore' => new MemoryVaultKeyStore()]);
        $gateway->set($vaults);
        $gateway->script([['status' => 201, 'body' => ['item' => $pathless]]]);
        $call = static fn () => $off->call($deposit, $params);
        if (($option['requireAddressPaths'] ?? Transport::ADDRESS_PATHS_PUBLIC) === false) {
            check(array_column($call()->meta->addressChecks, 'status') === ['not_verifiable'], 'off: not verifiable ' . json_encode($option));
            check(array_column($gateway->requests(), 'path') === [Keys::SIGNING_KEYS_PATH, '/vaults/v-main/bitcoin/mainnet/addresses'], 'no vault list read');
        } else {
            check(thrown($call, AddressVerificationError::class)->code === 'path_missing', 'on by default');
        }
    }

    foreach (['yes', 1, 'true'] as $value) {
        check(str_contains(thrown(static fn () => $client(['requireAddressPaths' => $value]), ConfigurationError::class)->getMessage(), 'requireAddressPaths'), 'not a bool: ' . json_encode($value));
    }
};

$tests['transport: p1363-der-v1.json p1363_starts_like_der through the signer path: 64 bytes from a P-256 signer are P1363, even when they start like DER'] = static function () use ($full): void {
    $vectors = vectors('p1363-der-v1.json');
    $case = array_values(array_filter($vectors['cases'], static fn (array $case): bool => $case['name'] === 'p1363_starts_like_der'))[0];
    $message = (string) base64_decode($case['messageBase64'], true);
    $p1363 = (string) hex2bin($case['p1363Hex']);
    check($p1363[0] === "\x30" && ord($p1363[1]) === strlen($p1363) - 2, 'the case starts like a DER sequence of its length');
    $publicKey = spki_pem($vectors['publicKeySpkiDerBase64']);
    $calls = 0;
    $signer = new CallableSigner('p-256', $publicKey, static function (string $input) use ($message, $p1363, &$calls): string {
        $calls++;
        check($input === $message, 'the signer is given the message');

        return $p1363;
    }, digestOnly: false);
    $transport = new Transport(['apiKey' => 'k', 'apiSecret' => $full['credentials']['apiSecret'], 'passphrase' => 'p', 'signer' => $signer]);
    // The key-pair step of signing a request, given the vector's message: the signer called, its answer converted
    // and checked against the public key (verifySignerSignatures is on), then base64 into x-api-keypair-sign.
    $signature = (fn (string $message): string => $this->keypairSignature($message))->call($transport, $message);
    check($calls === 1, 'signed once');
    check(bin2hex($signature) === $case['expected']['derHex'], 'the DER sent ' . bin2hex($signature));
    check(SigningKey::read($publicKey, 'public')->verifyBytes($message, $signature), 'the DER verifies');
};

$tests['transport: every security event these tests saw had a catalogued type and exactly its fields'] = static function () use (&$strayEvents): void {
    check($strayEvents === [], 'stray events ' . json_encode($strayEvents));
};

$tests['transport: the mock gateway is stopped'] = static function () use ($gateway): void {
    $gateway->stop();
    check(true, '');
};

return $tests;
