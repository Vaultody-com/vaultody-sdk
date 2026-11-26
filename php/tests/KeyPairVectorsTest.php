<?php

declare(strict_types=1);

// test-vectors/request-keypair-v1.json and keypair-challenge-v1.json: the keys and fingerprints, public keys
// as pasted, the signed strings built, the signatures made and the verdicts given.

use Vaultody\Sdk\Verify\Keys;
use Vaultody\Sdk\Verify\SigningKey;
use Vaultody\Sdk\Verify\SigningKeyError;
use Vaultody\Sdk\Verify\UsageError;

$request = vectors('request-keypair-v1.json');
$challenge = vectors('keypair-challenge-v1.json');
$tests = [];

// The registration's error codes and the module's own for the same refusal
$keyErrorOf = [
    'api_key_public_key_invalid' => SigningKeyError::INVALID,
    'api_key_public_key_is_private' => SigningKeyError::PRIVATE,
    'api_key_public_key_unsupported_algorithm' => SigningKeyError::UNSUPPORTED_ALGORITHM,
];
$publicNamed = static fn (array $vectors, string $name): SigningKey => SigningKey::read($vectors['keys'][$name]['publicKeySpkiPem'], 'public');
$privateNamed = static fn (array $vectors, string $name): SigningKey => SigningKey::read($vectors['keys'][$name]['privateKeyPkcs8Pem'], 'private');

$tests['request-keypair-v1.json is the v1 format with both algorithms'] = static function () use ($request): void {
    check($request['format'] === 'vaultody request key-pair signatures, v1', 'format');
    check(str_contains($request['warning'], 'TEST-ONLY'), 'warning');
};

foreach ($request['keys'] as $name => $vectorKey) {
    $tests['request-keypair-v1.json key ' . $name . ': both halves, algorithm and fingerprint'] = static function () use ($request, $name, $vectorKey, $publicNamed, $privateNamed): void {
        $fromPrivate = $privateNamed($request, $name);
        $fromPublic = $publicNamed($request, $name);
        foreach ([$fromPrivate, $fromPublic] as $key) {
            check($key->algorithm === $vectorKey['algorithm'], 'algorithm');
            check($key->fingerprint === $vectorKey['fingerprint'], 'fingerprint ' . $key->fingerprint);
            check(strlen($key->fingerprint) === 50, 'fingerprint length');
            check(base64_encode($key->spkiDer) === $vectorKey['publicKeySpkiDerBase64'], 'canonical SPKI');
            check($key->publicKeyPem() === $vectorKey['publicKeySpkiPem'], 'canonical PEM');
        }
        check($fromPrivate->kind === 'private' && $fromPrivate->hasPrivateKey(), 'private');
        check($fromPublic->kind === 'public' && !$fromPublic->hasPrivateKey(), 'public');
    };
}

foreach ($request['publicKeys'] as $keyCase) {
    $tests['request-keypair-v1.json public key as pasted: ' . $keyCase['name']] = static function () use ($keyCase, $keyErrorOf): void {
        try {
            $key = SigningKey::inspectPublicKey($keyCase['publicKeyPem']);
            $actual = ['algorithm' => $key->algorithm, 'canonicalSpkiDerBase64' => base64_encode($key->spkiDer), 'fingerprint' => $key->fingerprint];
            check($actual === $keyCase['expected'], 'got ' . json_encode($actual));
        } catch (SigningKeyError $error) {
            check(isset($keyCase['expected']['error']) && $error->code === $keyErrorOf[$keyCase['expected']['error']], 'refused with ' . $error->code);
        }
    };
}

$tests['request-keypair-v1.json: the fingerprint of a pasted private key is its public key\'s'] = static function () use ($request): void {
    foreach ($request['publicKeys'] as $keyCase) {
        if ($keyCase['name'] === 'ed25519_private_key') {
            check(SigningKey::read($keyCase['publicKeyPem'], 'any')->fingerprint === $request['keys']['ed25519']['fingerprint'], 'fingerprint');
        }
    }
};

foreach ($request['cases'] as $vector) {
    $label = $vector['expected']['valid'] ? 'valid' : $vector['expected']['reason'];
    $tests['request-keypair-v1.json ' . $vector['name'] . ' -> ' . $label] = static function () use ($vector, $request, $publicNamed): void {
        ['signed' => $signed, 'verify' => $verify] = $vector;
        $built = Keys::keypairRequestMessage($signed['request']);
        if ($vector['category'] === 'signed_string') {
            check(base64_encode($built) !== $signed['signedStringBase64'], 'what was signed is another string');
        } else {
            check(base64_encode($built) === $signed['signedStringBase64'], 'signed string bytes');
            check($built === $signed['signedString'], 'signed string');
            check($publicNamed($request, $signed['key'])->verify($built, $signed['signature']), 'the signer signed it');
        }
        $registered = array_map(static fn (string $name): SigningKey => $publicNamed($request, $name), $verify['registeredKeys']);
        $verdict = Keys::verifyKeypairRequest($registered, $verify['request'], $verify['headers']['x-api-keypair-id'], $verify['headers']['x-api-keypair-sign']);
        check($verdict === $vector['expected'], 'got ' . json_encode($verdict));
    };
}

$tests['request-keypair-v1.json: an API key that is not one line of text is refused before signing; the HMAC v2 string has no API key'] = static function () use ($request, $privateNamed): void {
    $signed = $request['cases'][0]['signed'];
    $fields = $signed['request'];
    unset($fields['apiKey']);
    thrown(static fn () => Keys::keypairRequestMessage($fields), UsageError::class);
    foreach (['', "key\nline", "key\rline", "key\r\n", 7] as $apiKey) {
        thrown(static fn () => Keys::keypairRequestMessage(['apiKey' => $apiKey] + $fields), UsageError::class);
        thrown(static fn () => Keys::signApiRequest($privateNamed($request, $signed['key']), ['apiKey' => $apiKey, 'apiSecret' => base64_encode('TEST-ONLY secret'), 'passphrase' => $fields['passphrase']], $fields), UsageError::class);
    }
    check(explode("\n", Keys::keypairRequestMessage($signed['request']))[1] === $signed['request']['apiKey'], 'the API key on line 2');
    check(Keys::hmacV2RequestMessage($signed['request']) === Keys::hmacV2RequestMessage($fields), 'x-api-sign does not change');
};

$tests['request-keypair-v1.json: the HMAC v2 string is the same fields under "v2"'] = static function () use ($request): void {
    foreach ($request['cases'] as $vector) {
        if ($vector['name'] === 'hmac_v2_string_signed') {
            check(base64_encode(Keys::hmacV2RequestMessage($vector['signed']['request'])) === $vector['signed']['signedStringBase64'], 'v2 string');
        }
    }
};

foreach ($request['cases'] as $vector) {
    if ($vector['category'] !== 'valid') {
        continue;
    }
    $tests['request-keypair-v1.json signing ' . $vector['name']] = static function () use ($vector, $request, $publicNamed, $privateNamed): void {
        $signed = $vector['signed'];
        $headers = Keys::signApiRequest($privateNamed($request, $signed['key']), [
            'apiKey' => $signed['request']['apiKey'],
            'apiSecret' => base64_encode('TEST-ONLY secret'),
            'passphrase' => $signed['request']['passphrase'],
        ], $signed['request']);
        check($headers['x-api-keypair-id'] === $request['keys'][$signed['key']]['fingerprint'], 'key id');
        if ($signed['algorithm'] === 'ed25519') {
            check($headers['x-api-keypair-sign'] === $signed['signature'], 'Ed25519 is deterministic');
        } else {
            $der = base64_decode($headers['x-api-keypair-sign'], true);
            check(ord($der[0]) === 0x30 && ord($der[1]) === strlen($der) - 2, 'one DER SEQUENCE');
            check(Keys::verifyKeypairRequest([$publicNamed($request, $signed['key'])], $signed['request'], $headers['x-api-keypair-id'], $headers['x-api-keypair-sign']) === ['valid' => true], 'verifies');
        }
        check($headers['x-api-key'] === $signed['request']['apiKey'], 'the API key signed is the one sent');
        check($headers['x-api-sign-version'] === '2', 'v2');
        check($headers['x-api-nonce'] === $signed['request']['nonce'], 'nonce');
        check(($headers['x-api-version'] ?? '') === $signed['request']['apiVersion'], 'api version');
    };
}

$tests['keypair-challenge-v1.json shares the request vectors\' keys'] = static function () use ($request, $challenge): void {
    check($challenge['format'] === 'vaultody key-pair proof of possession, challenge v1', 'format');
    check($challenge['keys'] === $request['keys'], 'keys');
};

foreach ($challenge['cases'] as $vector) {
    $label = $vector['expected']['valid'] ? 'valid' : $vector['expected']['reason'];
    $tests['keypair-challenge-v1.json ' . $vector['name'] . ' -> ' . $label] = static function () use ($vector, $challenge, $publicNamed): void {
        ['signed' => $signed, 'verify' => $verify] = $vector;
        $built = Keys::challengeProofMessage($signed);
        if ($vector['category'] === 'signed_string') {
            check(base64_encode($built) !== $signed['proofStringBase64'], 'another string was signed');
        } else {
            check(base64_encode($built) === $signed['proofStringBase64'], 'proof bytes');
            check($built === $signed['proofString'], 'proof string');
        }
        $ok = Keys::verifyChallengeProof($publicNamed($challenge, $verify['publicKey']), $verify['apiKeyId'], $verify['challenge'], $verify['signature']);
        $verdict = $ok ? ['valid' => true] : ['valid' => false, 'reason' => 'api_key_public_key_proof_invalid'];
        check($verdict === $vector['expected'], 'got ' . json_encode($verdict));
    };
}

foreach ($challenge['cases'] as $vector) {
    if ($vector['category'] !== 'valid') {
        continue;
    }
    $tests['keypair-challenge-v1.json signing ' . $vector['name']] = static function () use ($vector, $challenge, $publicNamed, $privateNamed): void {
        $signed = $vector['signed'];
        $signature = Keys::signChallengeProof($privateNamed($challenge, $signed['key']), $signed['apiKeyId'], $signed['challenge']);
        if ($signed['algorithm'] === 'ed25519') {
            check($signature === $signed['signature'], 'Ed25519 proof byte for byte');
        }
        check(Keys::verifyChallengeProof($publicNamed($challenge, $signed['key']), $signed['apiKeyId'], $signed['challenge'], $signature), 'verifies');
    };
}

foreach ($challenge['challengeFormat'] as $formatCase) {
    $tests['keypair-challenge-v1.json challenge format ' . json_encode($formatCase['challenge'])] = static function () use ($formatCase, $challenge, $privateNamed): void {
        check(Keys::isChallenge($formatCase['challenge']) === $formatCase['valid'], 'isChallenge');
        $prove = static fn () => Keys::signChallengeProof($privateNamed($challenge, 'ed25519'), '6630f1c2a9e4b5d7c8e9f0d4', $formatCase['challenge']);
        if ($formatCase['valid']) {
            check(preg_match('/^[A-Za-z0-9+\/]{86}==$/D', $prove()) === 1, 'proof shape');
        } else {
            thrown($prove, UsageError::class);
        }
    };
}

return $tests;
