<?php

declare(strict_types=1);

// test-vectors/response-mode-v1.json: which response-signature mode is in force (config), and what one answer does
// to a client in its mode (answers): the result, the latch stored for the origin, the security events in order. The
// config cases run through the pure decision and through real clients; the answers through the transport's own
// verification step, on clients built from their configuration.

require_once __DIR__ . '/support/RecordingLogger.php';

use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\ResponseVerificationError;
use Vaultody\Sdk\Http\HttpResponse;
use Vaultody\Sdk\Transport\Operation;
use Vaultody\Sdk\Transport\Transport;
use Vaultody\Sdk\VaultKeys\MemoryVaultKeyStore;
use Vaultody\Sdk\Vaultody;
use Vaultody\Sdk\Verify\Keys;

$vectors = vectors('response-mode-v1.json');
$credentials = ['apiKey' => 'TEST-ONLY-key', 'apiSecret' => base64_encode('TEST-ONLY secret'), 'passphrase' => 'TEST-ONLY passphrase'];
$origin = 'https://rest.example.test';
$ignored = '\'responseSignature\' => \'when-present\' is ignored: response-signing roots are configured, so every response must be signed';
$tests = [];

/** Runs $run with VAULTODY_RESPONSE_SIGNATURE set to $value (false: not set), and puts it back after. */
$withEnvironment = static function (string|false $value, callable $run): mixed {
    $before = getenv('VAULTODY_RESPONSE_SIGNATURE');
    putenv($value === false ? 'VAULTODY_RESPONSE_SIGNATURE' : 'VAULTODY_RESPONSE_SIGNATURE=' . $value);
    try {
        return $run();
    } finally {
        putenv($before === false ? 'VAULTODY_RESPONSE_SIGNATURE' : 'VAULTODY_RESPONSE_SIGNATURE=' . $before);
    }
};

// The TEST-ONLY roots of v1.json, current and next.
$testRoots = static fn (): array => [root_pem('current'), root_pem('next')];

$tests['response-mode-v1.json: the build default is one of the two modes'] = static function (): void {
    check(in_array(Transport::DEFAULT_RESPONSE_SIGNATURE, Transport::RESPONSE_SIGNATURE_MODES, true), 'DEFAULT_RESPONSE_SIGNATURE');
};

foreach ($vectors['config'] as $case) {
    $expected = [$case['expected']['mode'], $case['expected']['warning']];
    $tests['response-mode-v1.json config ' . $case['name']] = static function () use ($case, $expected): void {
        $actual = Transport::responseSignatureConfig($case['option'], $case['rootsOption'], $case['embeddedRoots'], $case['version'], $case['buildDefault']);
        check($actual === $expected, 'got ' . json_encode($actual));
    };
    // A real client always takes its build's default: a case with another one runs through the decision only.
    if ($case['buildDefault'] !== Transport::DEFAULT_RESPONSE_SIGNATURE) {
        continue;
    }
    $tests['response-mode-v1.json config ' . $case['name'] . ' (clients)'] = static function () use ($case, $credentials, $withEnvironment, $testRoots, $ignored): void {
        ['mode' => $mode, 'warning' => $warning] = $case['expected'];
        $options = static fn (RecordingLogger $logger): array => $credentials + ['logger' => $logger, 'sdkVersion' => $case['version']]
            + ($case['rootsOption'] ? ['roots' => $testRoots()] : [])
            + ($case['embeddedRoots'] ? ['embeddedRoots' => $testRoots()] : ['embeddedRoots' => []])
            + ($case['option'] !== null ? ['responseSignature' => $case['option']] : []);

        $logger = new RecordingLogger();
        $transport = $withEnvironment(false, static fn (): Transport => new Transport($options($logger)));
        check($transport->responseSignature() === $mode && $transport->__debugInfo()['responseSignature'] === $mode, 'the transport reports ' . $transport->responseSignature());
        check($logger->warnings === ($warning ? [$ignored] : []), 'warnings ' . json_encode($logger->warnings));

        $logger = new RecordingLogger();
        $vaultody = $withEnvironment(false, static fn (): Vaultody => new Vaultody($options($logger)));
        check($vaultody->responseSignature() === $mode && $vaultody->__debugInfo()['transport']['responseSignature'] === $mode, 'the client reports ' . $vaultody->responseSignature());
        check(count($logger->warnings) === ($warning ? 1 : 0), 'one warning when the client is made');
    };
}

$tests['response-mode-v1.json: VAULTODY_RESPONSE_SIGNATURE stands for the option when it is not given; empty is not given'] = static function () use ($credentials, $withEnvironment, $testRoots, $ignored): void {
    $make = static function (string|false $environment, array $options) use ($credentials, $withEnvironment): array {
        $logger = new RecordingLogger();
        $transport = $withEnvironment($environment, static fn (): Transport => new Transport($credentials + $options + ['logger' => $logger, 'embeddedRoots' => []]));

        return [$transport->responseSignature(), $logger->warnings];
    };
    check($make('required', []) === ['required', []], 'required from the environment');
    check($make('when-present', ['roots' => $testRoots()]) === ['required', [$ignored]], 'when-present from the environment, with roots: ignored, one warning');
    check($make('required', ['responseSignature' => 'when-present']) === ['when-present', []], 'the option comes first');
    check($make('', [])[0] === Transport::DEFAULT_RESPONSE_SIGNATURE, 'empty: the build default');
    foreach (['off', 'REQUIRED'] as $value) {
        thrown(static fn () => $make($value, []), ConfigurationError::class);
        thrown(static fn () => $make(false, ['responseSignature' => $value]), ConfigurationError::class);
    }
    thrown(static fn () => $make(false, ['sdkVersion' => 1]), ConfigurationError::class);
};

/** @return array<string, mixed> the v1.json case of that name */
$answerCase = static function (string $name): array {
    foreach (vectors('v1.json')['cases'] as $case) {
        if ($case['name'] === $name) {
            return $case;
        }
    }
    throw new RuntimeException('no v1.json case ' . $name);
};

foreach ($vectors['answers'] as $case) {
    $tests['response-mode-v1.json answers ' . $case['name']] = static function () use ($case, $vectors, $credentials, $origin, $withEnvironment, $answerCase): void {
        $verify = $answerCase($case['answer'] === 'unsigned' ? 'missing_all' : $case['answer'])['verify'];
        $roots = array_map('root_pem', $verify['pinnedRoots']);
        // The client its configuration makes. when-present is given explicitly where the vector's mode needs it, so
        // the cases hold whatever the build default is; embeddedRoots [] is a build that embeds no root.
        $configuration = match ([$case['mode'], $case['roots']]) {
            ['required', true] => ['roots' => $roots],
            ['when-present', true] => ['embeddedRoots' => $roots, 'sdkVersion' => '0.9.0-rc.1', 'responseSignature' => 'when-present'],
            ['required', false] => ['embeddedRoots' => [], 'responseSignature' => 'required'],
            ['when-present', false] => ['embeddedRoots' => [], 'responseSignature' => 'when-present'],
        };
        $store = new MemoryVaultKeyStore();
        if ($case['latchedBefore']) {
            $store->update($origin, static fn (array $state): array => ['responseSignature' => $vectors['previousLatch']] + $state);
        }
        $types = [];
        $options = $credentials + $configuration + [
            'baseUrl' => $origin,
            'vaultKeyStore' => $store,
            'clock' => static fn (): int => $verify['now'],
            'logger' => new RecordingLogger(),
            'onSecurityEvent' => static function (array $event) use (&$types): void {
                $types[] = $event['type'];
            },
        ];
        $transport = $withEnvironment(false, static fn (): Transport => new Transport($options));
        check($transport->responseSignature() === $case['mode'], 'the mode in force ' . $transport->responseSignature());

        $request = $verify['request'];
        $response = response_of($verify['response']);
        // The transport hands its verification step the headers as lists under lower-case names.
        $headers = [];
        foreach ($response['headers'] as $name => $value) {
            $headers[strtolower($name)][] = $value;
        }
        $step = fn (): array => $this->verifyResponse(
            new Operation('responseModeCase', $request['method'], $request['path'], 'read'),
            $request['query'] === '' ? $request['path'] : $request['path'] . '?' . $request['query'],
            (string) base64_decode($request['bodyBase64'], true),
            [Keys::HEADERS['sign'] => $request['apiSign'], Keys::HEADERS['keypairSign'] => $request['keypairSign']],
            new HttpResponse($response['status'], $headers, $response['body']),
        );
        try {
            $result = $step->call($transport)['verified'] ? 'verified' : 'absent';
        } catch (ResponseVerificationError $error) {
            $result = ['error' => $error->reason];
        } catch (ConfigurationError) {
            $result = ['configurationError' => true];
        }
        check($result === $case['expected']['result'], 'result ' . json_encode($result));
        check($store->read($origin)['responseSignature'] === $case['expected']['latch'], 'latch ' . json_encode($store->read($origin)['responseSignature']));
        check($types === $case['expected']['events'], 'events ' . json_encode($types));
    };
}

return $tests;
