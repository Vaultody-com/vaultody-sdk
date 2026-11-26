<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * Request signing for Vaultody API keys: the HMAC v2 signature (x-api-sign) every request carries, the
 * customer key-pair signature (x-api-keypair-sign) next to it once the API key holds a public key, and the
 * proof of possession asked for when a key is registered.
 *
 * The wire formats are shared with the API gateway, the Node and Python modules and the docs
 * (test-vectors/request-hmac-v2.json, request-full-v1.json, request-keypair-v1.json, keypair-challenge-v1.json),
 * so every format constant is here. Nothing here logs, and no error carries key material, the API secret,
 * the passphrase or the API key.
 */
final class Keys
{
    public const ALGORITHMS = [SigningKey::ED25519, SigningKey::P256];

    /** The proof of possession: this tag, the API key id, the fingerprint and the challenge, "\n"-joined, no trailing "\n". */
    public const CHALLENGE_TAG = 'vaultody-keypair-challenge-v1';
    /** "vk-chal-" + 64 lowercase hex characters (32 random bytes), issued by the dashboard. */
    public const CHALLENGE_PATTERN = '/^vk-chal-[0-9a-f]{64}$/D';
    /** The string signed for x-api-keypair-sign: this tag, the x-api-key, then the HMAC v2 fields in the same order. */
    public const REQUEST_TAG = 'vaultody-request-keypair-v1';
    /** The tag of the HMAC v2 string (x-api-sign with x-api-sign-version: 2). */
    public const HMAC_V2_TAG = 'v2';
    /** x-api-nonce: printable ASCII without spaces, 1 to 128 characters. */
    public const NONCE_PATTERN = '/^[\x21-\x7e]{1,128}$/D';
    /** An API version as x-api-version names it: a date, YYYY-MM-DD. */
    public const API_VERSION_PATTERN = '/^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$/D';

    public const HEADERS = [
        'apiKey' => 'x-api-key',
        'passphrase' => 'x-api-passphrase',
        'timestamp' => 'x-api-timestamp',
        'sign' => 'x-api-sign',
        'signVersion' => 'x-api-sign-version',
        'nonce' => 'x-api-nonce',
        'apiVersion' => 'x-api-version',
        'keypairSign' => 'x-api-keypair-sign',
        'keypairId' => 'x-api-keypair-id',
    ];

    /** The public endpoint that lists the signing keys of the API key that calls it. */
    public const SIGNING_KEYS_PATH = '/api-keys/current/signing-keys';

    // Standard base64, padding optional: how Vaultody issues API secrets.
    private const API_SECRET_SHAPE = '/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}(?:==)?|[A-Za-z0-9+\/]{3}=?)?$/D';
    private const P1363_SIGNATURE_BYTES = 64;

    /** Whether text is a challenge exactly as the dashboard issues one. */
    public static function isChallenge(mixed $text): bool
    {
        return is_string($text) && preg_match(self::CHALLENGE_PATTERN, $text) === 1;
    }

    /** Whether text is an API version as x-api-version names it (YYYY-MM-DD). */
    public static function isApiVersion(mixed $text): bool
    {
        return is_string($text) && preg_match(self::API_VERSION_PATTERN, $text) === 1;
    }

    /**
     * The UTF-8 bytes of the proof string.
     *
     * @param array{apiKeyId: string, fingerprint: string, challenge: string} $fields
     */
    public static function challengeProofMessage(array $fields): string
    {
        return implode("\n", [self::CHALLENGE_TAG, $fields['apiKeyId'], $fields['fingerprint'], $fields['challenge']]);
    }

    /**
     * Signs the proof of possession for a key being registered on an API key.
     *
     * @return string the signature, standard base64 with padding
     * @throws UsageError a malformed API key id or challenge
     */
    public static function signChallengeProof(SigningKey $key, string $apiKeyId, string $challenge): string
    {
        if ($apiKeyId === '' || preg_match('/^[\x21-\x7e]+$/D', $apiKeyId) !== 1) {
            throw new UsageError('the API key id must be the id the dashboard shows, with no spaces or line breaks');
        }
        if (!self::isChallenge($challenge)) {
            throw new UsageError('the challenge must be "vk-chal-" followed by 64 lowercase hex characters, exactly as the dashboard shows it');
        }

        return base64_encode($key->sign(self::challengeProofMessage(['apiKeyId' => $apiKeyId, 'fingerprint' => $key->fingerprint, 'challenge' => $challenge])));
    }

    /**
     * Checks a proof of possession the way a registration does: over the proof string built from the API key
     * id, the fingerprint of the key given and the challenge.
     */
    public static function verifyChallengeProof(SigningKey $key, mixed $apiKeyId, mixed $challenge, mixed $signature): bool
    {
        if (!is_string($apiKeyId) || $apiKeyId === '' || preg_match('/\s/', $apiKeyId) === 1 || !self::isChallenge($challenge)) {
            return false;
        }

        return $key->verify(self::challengeProofMessage(['apiKeyId' => $apiKeyId, 'fingerprint' => $key->fingerprint, 'challenge' => $challenge]), $signature);
    }

    /**
     * The fields both request signatures cover, newline-joined under a tag. Header values, the nonce and the
     * query string can't hold a raw newline; the raw body can, so it goes last.
     *
     * @param array{timestamp: string, method: string, path: string, apiVersion?: ?string, passphrase: string, nonce?: ?string, query?: ?string, body?: ?string} $fields
     *        path without the query (with the /v2 prefix if the request uses it); query the raw text after "?";
     *        body the raw body as sent; apiVersion the x-api-version header, if sent
     */
    public static function taggedRequestMessage(string $tag, #[\SensitiveParameter] array $fields): string
    {
        return implode("\n", [$tag, ...self::requestLines($fields)]);
    }

    /**
     * The request fields both signatures cover, one per line, in the order of taggedRequestMessage.
     *
     * @param array<string, mixed> $fields
     * @return list<string>
     */
    private static function requestLines(#[\SensitiveParameter] array $fields): array
    {
        return [
            $fields['timestamp'],
            $fields['method'],
            $fields['path'],
            $fields['apiVersion'] ?? '',
            $fields['passphrase'],
            $fields['nonce'] ?? '',
            $fields['query'] ?? '',
            $fields['body'] ?? '',
        ];
    }

    /** The string signed with the API secret for x-api-sign, version 2. */
    public static function hmacV2RequestMessage(#[\SensitiveParameter] array $fields): string
    {
        return self::taggedRequestMessage(self::HMAC_V2_TAG, $fields);
    }

    /**
     * The string signed with the private key for x-api-keypair-sign: the tag, the x-api-key the request is sent with,
     * then the fields of taggedRequestMessage. The API key binds the signature to it: a request signed for one API
     * key can't be sent under another that holds the same public key and passphrase.
     *
     * @param array<string, mixed> $fields as for taggedRequestMessage, and apiKey
     * @throws UsageError an API key that is not one line of text
     */
    public static function keypairRequestMessage(#[\SensitiveParameter] array $fields): string
    {
        $apiKey = $fields['apiKey'] ?? null;
        if (!is_string($apiKey) || $apiKey === '' || preg_match('/[\r\n]/', $apiKey) === 1) {
            throw new UsageError('the API key must be one line of text');
        }

        return implode("\n", [self::REQUEST_TAG, $apiKey, ...self::requestLines($fields)]);
    }

    /**
     * Checks x-api-keypair-sign the way the gateway does: x-api-keypair-id must name one of the registered
     * keys, and the signature must verify with it over the request as received, under the x-api-key it was
     * received with (apiKey in the fields).
     *
     * @param list<SigningKey> $registeredKeys
     * @param array<string, mixed> $fields as for keypairRequestMessage
     * @return array{valid: true}|array{valid: false, reason: string}
     * @throws UsageError an API key that is not one line of text
     */
    public static function verifyKeypairRequest(array $registeredKeys, #[\SensitiveParameter] array $fields, mixed $keypairId, mixed $keypairSign): array
    {
        foreach ($registeredKeys as $key) {
            if ($key->fingerprint === $keypairId) {
                return $key->verify(self::keypairRequestMessage($fields), $keypairSign)
                    ? ['valid' => true]
                    : ['valid' => false, 'reason' => 'invalid_api_keypair_sign'];
            }
        }

        return ['valid' => false, 'reason' => 'unknown_api_keypair_id'];
    }

    /**
     * The HMAC key of an API secret. Only standard base64 is taken (padding optional), decoding to at least
     * one byte: anything else is refused rather than decoded leniently, so every language derives the same
     * key from the same text or refuses it.
     *
     * @throws UsageError code 'invalid_api_secret'; the message never holds the secret
     */
    public static function decodeApiSecret(#[\SensitiveParameter] mixed $apiSecret): string
    {
        $refused = new UsageError('the API secret must be the base64 text the dashboard shows', 'invalid_api_secret');
        if (!is_string($apiSecret) || $apiSecret === '' || preg_match(self::API_SECRET_SHAPE, $apiSecret) !== 1) {
            throw $refused;
        }
        // PHP's decoder wants the padding; the shape above allows it to be left out.
        $padded = $apiSecret . str_repeat('=', (4 - strlen($apiSecret) % 4) % 4);
        $key = base64_decode($padded, true);
        if (!is_string($key) || $key === '') {
            throw $refused;
        }

        return $key;
    }

    /**
     * x-api-sign, version 2: base64 HMAC-SHA256 keyed with the decoded API secret over hmacV2RequestMessage.
     *
     * @param array<string, mixed> $fields as for hmacV2RequestMessage
     */
    public static function hmacV2Signature(#[\SensitiveParameter] mixed $apiSecret, #[\SensitiveParameter] array $fields): string
    {
        return base64_encode(hash_hmac('sha256', self::hmacV2RequestMessage($fields), self::decodeApiSecret($apiSecret), true));
    }

    /**
     * The fields both request signatures cover, with the timestamp and nonce filled in when not given: the
     * clock now, and a fresh 16-byte CSPRNG nonce, so the gateway's replay protection can tell a resend from
     * a new request.
     *
     * @param array<string, mixed> $request
     * @return array<string, mixed>
     * @throws UsageError
     */
    public static function requestFields(#[\SensitiveParameter] string $passphrase, array $request): array
    {
        $timestamp = $request['timestamp'] ?? null;
        $nonce = $request['nonce'] ?? null;
        $timestamp = $timestamp === null || $timestamp === '' ? (string) time() : $timestamp;
        $nonce = $nonce === null || $nonce === '' ? bin2hex(random_bytes(16)) : $nonce;
        if (!is_string($nonce) || preg_match(self::NONCE_PATTERN, $nonce) !== 1) {
            throw new UsageError('the nonce must be 1 to 128 printable ASCII characters without spaces');
        }

        return ['timestamp' => (string) $timestamp, 'nonce' => $nonce, 'passphrase' => $passphrase] + $request;
    }

    /**
     * @param array{apiKey?: mixed, apiSecret?: mixed, passphrase?: mixed} $credentials
     * @throws UsageError
     */
    public static function requireCredentials(#[\SensitiveParameter] array $credentials): void
    {
        foreach (['apiKey', 'passphrase'] as $name) {
            if (!is_string($credentials[$name] ?? null) || $credentials[$name] === '') {
                throw new UsageError(sprintf('the %s is missing', $name));
            }
        }
        self::decodeApiSecret($credentials['apiSecret'] ?? null);
    }

    /**
     * The authentication headers of one API request signed with the API secret only (HMAC v2).
     *
     * @param array{apiKey: string, apiSecret: string, passphrase: string} $credentials
     * @param array{method: string, path: string, query?: ?string, body?: ?string, apiVersion?: ?string, timestamp?: ?string, nonce?: ?string} $request
     * @return array<string, string> header name => value
     * @throws UsageError
     */
    public static function signHmacV2Request(#[\SensitiveParameter] array $credentials, array $request): array
    {
        self::requireCredentials($credentials);
        $fields = self::requestFields($credentials['passphrase'], $request);
        $headers = [
            self::HEADERS['apiKey'] => $credentials['apiKey'],
            self::HEADERS['passphrase'] => $credentials['passphrase'],
            self::HEADERS['timestamp'] => $fields['timestamp'],
            self::HEADERS['sign'] => self::hmacV2Signature($credentials['apiSecret'], $fields),
            self::HEADERS['signVersion'] => '2',
            self::HEADERS['nonce'] => $fields['nonce'],
        ];
        if (($request['apiVersion'] ?? '') !== '') {
            $headers[self::HEADERS['apiVersion']] = $request['apiVersion'];
        }

        return $headers;
    }

    /**
     * The authentication headers of one API request, signed both ways: x-api-sign with the API secret (HMAC
     * v2) and x-api-keypair-sign with the private key.
     *
     * @param array{apiKey: string, apiSecret: string, passphrase: string} $credentials
     * @param array{method: string, path: string, query?: ?string, body?: ?string, apiVersion?: ?string, timestamp?: ?string, nonce?: ?string} $request
     * @return array<string, string>
     * @throws UsageError|SigningKeyError
     */
    public static function signApiRequest(SigningKey $key, #[\SensitiveParameter] array $credentials, array $request): array
    {
        if (!$key->hasPrivateKey()) {
            throw new SigningKeyError(SigningKeyError::PUBLIC, 'This is a public key. Signing needs the private key (private.pem).');
        }
        self::requireCredentials($credentials);
        $fields = self::requestFields($credentials['passphrase'], $request);
        // In the order of test-vectors/request-full-v1.json: the HMAC v2 headers, then the key-pair ones.
        $headers = self::signHmacV2Request($credentials, $fields);
        $headers[self::HEADERS['keypairSign']] = base64_encode($key->sign(self::keypairRequestMessage(['apiKey' => $credentials['apiKey']] + $fields)));
        $headers[self::HEADERS['keypairId']] = $key->fingerprint;

        return $headers;
    }

    /**
     * A P-256 signature as IEEE P1363 (r || s, 32 bytes each, as Web Crypto, Azure Key Vault and some KMS APIs
     * return it) in the DER form the gateway requires for x-api-keypair-sign.
     *
     * @throws SignatureFormatError invalid_length unless 64 bytes; zero_integer when r or s is zero
     */
    public static function p1363ToDer(mixed $signature): string
    {
        if (!is_string($signature) || strlen($signature) !== self::P1363_SIGNATURE_BYTES) {
            throw new SignatureFormatError(SignatureFormatError::INVALID_LENGTH, sprintf('a P1363 P-256 signature is %d bytes', self::P1363_SIGNATURE_BYTES));
        }
        $r = substr($signature, 0, 32);
        $s = substr($signature, 32);
        if (ltrim($r, "\0") === '' || ltrim($s, "\0") === '') {
            throw new SignatureFormatError(SignatureFormatError::ZERO_INTEGER, 'r and s of a signature are never zero');
        }

        return Der::encode(Der::SEQUENCE, self::derInteger($r) . self::derInteger($s));
    }

    private static function derInteger(string $bytes): string
    {
        $body = ltrim($bytes, "\0");
        if (ord($body[0]) & 0x80) {
            $body = "\0" . $body;
        }

        return Der::encode(Der::INTEGER, $body);
    }
}
