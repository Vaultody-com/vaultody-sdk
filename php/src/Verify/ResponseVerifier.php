<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * Checks that a Vaultody API response came unchanged from the Vaultody API gateway.
 *
 * TLS for the API ends at a CDN in front of the gateway, so a valid TLS connection only proves that the CDN
 * answered. The gateway therefore signs every response itself, and this class checks that signature against
 * pinned root keys. A response changed anywhere on the way, or moved onto a different request, is refused.
 *
 * Two keys are involved. A P-256 root key, kept in an HSM, signs a short certificate for each gateway
 * instance's own Ed25519 key, valid for about an hour. The instance signs each response with that key, over
 * the status, the body bytes and the request being answered: method, path, query, a hash of the request
 * body, the client's x-api-sign and its x-api-keypair-sign.
 *
 * The checks run in a fixed order, shared with the gateway's reference verifier and the Node and Python
 * modules (test-vectors/v1.json). The order decides which reason a caller sees:
 *  1. all four signature headers present and non-empty, else `missing`;
 *  2. x-api-response-sign-version is exactly "1", else `unsupported_version`;
 *  3. x-api-response-cert is base64(CERT) "." base64(root signature), CERT is ASCII, its first line is the
 *     tag and its second a lowercase hex root id, else `invalid`;
 *  4. the root id names a trusted root, else `unknown_root`;
 *  5. the root's ECDSA P-256 / SHA-256 signature (DER) verifies over the CERT bytes, else `invalid`;
 *  6. CERT is canonical: 6 lines, canonical base64 key of 32 bytes, keyId matching the key, canonical
 *     decimal times, and valid for at most MAX_CERT_LIFETIME_SECONDS (notAfter - notBefore), else `invalid`;
 *  7. x-api-response-timestamp is a canonical decimal, else `invalid`;
 *  8. notBefore <= timestamp <= notAfter and now <= notAfter + skew, else `expired`;
 *  9. the Ed25519 signature verifies over the message rebuilt from the request as sent and the response as
 *     received. If it only verifies with the body hash "unread" (the gateway did not read the request body),
 *     the reason is `request_unbound`; otherwise `invalid`.
 */
final class ResponseVerifier
{
    public const SIGN_VERSION = '1';

    /** The four headers a signed response carries; a response with none of them was not signed. */
    public const HEADERS = [
        'sign' => 'x-api-response-sign',
        'timestamp' => 'x-api-response-timestamp',
        'version' => 'x-api-response-sign-version',
        'cert' => 'x-api-response-cert',
    ];

    public const DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300;

    /**
     * The longest a certificate may be valid, notAfter - notBefore: the gateway certifies an instance key for about an
     * hour, so a longer one was not made by it, and a stolen instance key must not stay usable for longer.
     */
    public const MAX_CERT_LIFETIME_SECONDS = 3600;

    private const CERT_TAG = 'vaultody-response-key-v1';
    private const MESSAGE_TAG = 'vaultody-response-v1';
    private const CERT_LINES = 6;
    // Signed in place of the request body hash when the gateway did not read the whole request body.
    private const UNREAD_BODY = 'unread';
    private const ROOT_ID = '/^[0-9a-f]{64}$/D';
    private const KEY_ID = '/^[0-9a-f]{32}$/D';
    private const CERT_TEXT = '/^[\x20-\x7e\n]+$/D';
    // The request fields sit on their own lines in the signed message, so they must stay printable ASCII.
    private const PRINTABLE_ASCII = '/^[\x20-\x7e]*$/D';
    private const ED25519_SIGNATURE_BYTES = 64;
    private const ED25519_PUBLIC_KEY_BYTES = 32;
    // Unix seconds stay below this for thousands of years, while milliseconds are far above it.
    private const LARGEST_PLAUSIBLE_SECONDS = 100000000000;

    /**
     * Whether a response carries any of the signature headers.
     *
     * @param array<array-key, mixed> $headers
     */
    public static function isSigned(array $headers): bool
    {
        foreach (self::HEADERS as $name) {
            foreach (Encoding::headerValues($headers, $name) as $value) {
                if ($value !== '') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Verifies one signed API response, before its body is parsed.
     *
     * @param array{method: string, url: string, body?: ?string, apiSign?: ?string, keypairSign?: ?string} $request
     *        the request exactly as sent: url is the path plus query from the request line, body the raw bytes
     *        sent, apiSign / keypairSign the x-api-sign / x-api-keypair-sign headers sent, if any
     * @param array{status: int, headers?: array<array-key, mixed>, body?: ?string} $response the response as
     *        received, body the raw bytes after any Content-Encoding is removed
     * @param array{requireResponseSignature?: bool, roots?: mixed, now?: int|\DateTimeInterface|null, maxClockSkewSeconds?: int} $options
     *        requireResponseSignature (default true): when false, a response with no signature header at all
     *        is returned as ['verified' => false, 'reason' => 'missing']; every other failure still throws.
     *        roots: the root keys to trust instead of the embedded ones. now: Unix seconds or a date.
     * @return array{verified: true, keyId: string, rootId: string, timestamp: int}|array{verified: false, reason: string}
     * @throws ResponseSignatureError the response fails verification
     * @throws ConfigurationError a given root is unusable, or the response is signed and no root is configured
     * @throws \InvalidArgumentException an argument of the wrong shape
     */
    public static function verify(array $request, array $response, array $options = []): array
    {
        $settings = self::readOptions($options);
        [$method, $path, $query, $requestBody, $apiSign, $keypairSign] = self::readRequest($request);
        [$status, $headers, $body] = self::readResponse($response);

        // 1. Headers. A response with none of them was never signed (or had the signature stripped as a
        // whole), the one failure a non-strict caller may accept. A partial set means something removed
        // some of them, which is never accepted.
        $found = [];
        $allEmpty = true;
        foreach (self::HEADERS as $field => $name) {
            $found[$field] = Encoding::headerValues($headers, $name);
            foreach ($found[$field] as $value) {
                if ($value !== '') {
                    $allEmpty = false;
                }
            }
        }
        if ($allEmpty) {
            if (!$settings['requireResponseSignature']) {
                return ['verified' => false, 'reason' => ResponseSignatureError::MISSING];
            }
            throw new ResponseSignatureError(ResponseSignatureError::MISSING, 'the response has no signature headers');
        }

        $raw = [];
        foreach (self::HEADERS as $field => $name) {
            $values = $found[$field];
            if ($values === [] || $values[0] === '') {
                throw new ResponseSignatureError(ResponseSignatureError::MISSING, $name . ' is missing or empty');
            }
            if (count($values) > 1) {
                throw new ResponseSignatureError(ResponseSignatureError::INVALID, $name . ' appears more than once');
            }
            if (!is_string($values[0])) {
                throw new ResponseSignatureError(ResponseSignatureError::INVALID, $name . ' is not a string');
            }
            $raw[$field] = $values[0];
        }

        if ($raw['version'] !== self::SIGN_VERSION) {
            throw new ResponseSignatureError(ResponseSignatureError::UNSUPPORTED_VERSION, sprintf('signature version "%s" is not supported; this verifier understands "%s"', $raw['version'], self::SIGN_VERSION));
        }

        // 2. Find the root the certificate names and check its signature, before trusting anything else the
        // certificate says.
        $certParts = explode('.', $raw['cert']);
        if (count($certParts) !== 2) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, self::HEADERS['cert'] . ' must be two base64 parts joined by "."');
        }
        $certBytes = Encoding::strictBase64($certParts[0]);
        $rootSignature = Encoding::strictBase64($certParts[1]);
        if ($certBytes === null || $rootSignature === null) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, self::HEADERS['cert'] . ' is not canonical base64');
        }
        if (preg_match('/[\x80-\xff]/', $certBytes) === 1) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the certificate is not ASCII');
        }
        $lines = explode("\n", $certBytes);
        if (count($lines) < 2 || $lines[0] !== self::CERT_TAG || preg_match(self::ROOT_ID, $lines[1]) !== 1) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the certificate does not start with the v1 tag and a root id');
        }
        $rootId = $lines[1];

        // The roots are looked up only now that the response carries a signature: with none configured, a
        // signed response fails closed here, while an unsigned one was decided above without them.
        $root = null;
        foreach (Roots::require($settings['roots']) as $candidate) {
            if ($candidate->rootId === $rootId) {
                $root = $candidate;
                break;
            }
        }
        if ($root === null) {
            throw new ResponseSignatureError(ResponseSignatureError::UNKNOWN_ROOT, sprintf('the certificate names root %s, which is not trusted', $rootId));
        }

        Encoding::clearOpensslErrors();
        $rootSignatureOk = openssl_verify($certBytes, $rootSignature, $root->key, OPENSSL_ALGO_SHA256) === 1;
        Encoding::clearOpensslErrors();
        if (!$rootSignatureOk) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the root signature on the certificate does not verify');
        }

        // 3. The certificate must be in the one form the gateway writes, so it means the same to every verifier.
        if (count($lines) !== self::CERT_LINES || preg_match(self::CERT_TEXT, $certBytes) !== 1) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, sprintf('the certificate must be %d lines of printable ASCII', self::CERT_LINES));
        }
        [, , $publicKeyText, $keyId, $notBeforeText, $notAfterText] = $lines;
        $publicKey = Encoding::strictBase64($publicKeyText);
        if ($publicKey === null || strlen($publicKey) !== self::ED25519_PUBLIC_KEY_BYTES) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the certificate public key is not canonical base64 of 32 bytes');
        }
        if (preg_match(self::KEY_ID, $keyId) !== 1 || $keyId !== substr(hash('sha256', $publicKey), 0, 32)) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the certificate keyId does not match its public key');
        }
        $notBefore = Encoding::strictSeconds($notBeforeText);
        $notAfter = Encoding::strictSeconds($notAfterText);
        if ($notBefore === null || $notAfter === null) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the certificate validity times are not canonical decimals');
        }
        if ($notAfter - $notBefore > self::MAX_CERT_LIFETIME_SECONDS) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, sprintf('the certificate is valid for more than %d seconds', self::MAX_CERT_LIFETIME_SECONDS));
        }

        // 4. Time. The signing time must fall inside the certificate's window, and this machine's clock may
        // run at most the allowed skew past its end, so an old certificate can't be reused indefinitely.
        $timestamp = Encoding::strictSeconds($raw['timestamp']);
        if ($timestamp === null) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, self::HEADERS['timestamp'] . ' is not a canonical decimal');
        }
        if ($timestamp < $notBefore || $timestamp > $notAfter) {
            throw new ResponseSignatureError(ResponseSignatureError::EXPIRED, sprintf('the response was signed at %d, outside the certificate window %d..%d', $timestamp, $notBefore, $notAfter));
        }
        if ($settings['now'] > $notAfter + $settings['maxClockSkewSeconds']) {
            throw new ResponseSignatureError(ResponseSignatureError::EXPIRED, sprintf('the certificate expired at %d; the clock here reads %d', $notAfter, $settings['now']));
        }

        // 5. The response signature, over the request as sent and the response as received.
        $signature = Encoding::strictBase64($raw['sign']);
        if ($signature === null || strlen($signature) !== self::ED25519_SIGNATURE_BYTES) {
            throw new ResponseSignatureError(ResponseSignatureError::INVALID, self::HEADERS['sign'] . ' is not canonical base64 of 64 bytes');
        }
        foreach ([$method, $path, $query, $apiSign, $keypairSign] as $value) {
            if (preg_match(self::PRINTABLE_ASCII, $value) !== 1) {
                throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the request method, url, apiSign and keypairSign must be printable ASCII exactly as sent; '
                    . 'non-ASCII characters are percent-encoded on the wire');
            }
        }

        $messageWith = static fn (string $bodyHash): string => implode("\n", [
            self::MESSAGE_TAG, $raw['timestamp'], (string) $status, $method, $path, $query, $bodyHash, $apiSign, $keypairSign,
        ]) . "\n" . $body;
        $verifies = static function (string $message) use ($signature, $publicKey): bool {
            try {
                return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
            } catch (\SodiumException) {
                return false;
            }
        };

        if ($verifies($messageWith(hash('sha256', $requestBody)))) {
            return ['verified' => true, 'keyId' => $keyId, 'rootId' => $rootId, 'timestamp' => $timestamp];
        }
        if ($verifies($messageWith(self::UNREAD_BODY))) {
            throw new ResponseSignatureError(ResponseSignatureError::REQUEST_UNBOUND, 'the response is genuine, but the gateway did not read the request body, '
                . 'so it is not tied to the body that was sent');
        }

        throw new ResponseSignatureError(ResponseSignatureError::INVALID, 'the signature does not match this request and response');
    }

    /**
     * @param array<string, mixed> $options
     * @return array{requireResponseSignature: bool, roots: list<Root>|null, now: int, maxClockSkewSeconds: int}
     */
    private static function readOptions(array $options): array
    {
        $require = $options['requireResponseSignature'] ?? true;
        if (!is_bool($require)) {
            throw new \InvalidArgumentException('requireResponseSignature must be true or false');
        }
        $skew = $options['maxClockSkewSeconds'] ?? self::DEFAULT_MAX_CLOCK_SKEW_SECONDS;
        if (!is_int($skew) || $skew < 0) {
            throw new \InvalidArgumentException('maxClockSkewSeconds must be a non-negative number of seconds');
        }

        $now = $options['now'] ?? null;
        if ($now === null) {
            $nowSeconds = time();
        } elseif ($now instanceof \DateTimeInterface) {
            $nowSeconds = $now->getTimestamp();
        } elseif (is_int($now)) {
            if ($now > self::LARGEST_PLAUSIBLE_SECONDS) {
                throw new \InvalidArgumentException('now must be Unix seconds; this looks like milliseconds');
            }
            $nowSeconds = $now;
        } else {
            throw new \InvalidArgumentException('now must be Unix seconds (an int) or a DateTimeInterface');
        }

        return [
            'requireResponseSignature' => $require,
            // Parsed now, so a malformed root is reported at once; a root is required only once the response
            // turns out to be signed.
            'roots' => Roots::parse($options['roots'] ?? null),
            'now' => $nowSeconds,
            'maxClockSkewSeconds' => $skew,
        ];
    }

    /**
     * @param array<string, mixed> $request
     * @return array{string, string, string, string, string, string}
     */
    private static function readRequest(array $request): array
    {
        $method = $request['method'] ?? null;
        $url = $request['url'] ?? null;
        if (!is_string($method) || $method === '') {
            throw new \InvalidArgumentException('request method must be the HTTP method exactly as sent, for example "POST"');
        }
        if (!is_string($url) || !str_starts_with($url, '/')) {
            throw new \InvalidArgumentException('request url must be the path and query exactly as sent on the request line, starting with "/" (not a full URL)');
        }
        $apiSign = $request['apiSign'] ?? '';
        $keypairSign = $request['keypairSign'] ?? '';
        if (!is_string($apiSign)) {
            throw new \InvalidArgumentException('request apiSign must be the x-api-sign header value that was sent, or empty');
        }
        if (!is_string($keypairSign)) {
            throw new \InvalidArgumentException('request keypairSign must be the x-api-keypair-sign header value that was sent, or empty');
        }

        // Split at the first "?" only. Both halves are kept exactly as sent, because the gateway signs them as
        // it received them, percent-encoding and all.
        $queryAt = strpos($url, '?');

        return [
            $method,
            $queryAt === false ? $url : substr($url, 0, $queryAt),
            $queryAt === false ? '' : substr($url, $queryAt + 1),
            Encoding::bytes($request['body'] ?? null, 'request body'),
            $apiSign,
            $keypairSign,
        ];
    }

    /**
     * @param array<string, mixed> $response
     * @return array{int, array<array-key, mixed>, string}
     */
    private static function readResponse(array $response): array
    {
        $status = $response['status'] ?? null;
        if (!is_int($status)) {
            throw new \InvalidArgumentException('response status must be the HTTP status code as an int');
        }
        $headers = $response['headers'] ?? [];
        if (!is_array($headers)) {
            throw new \InvalidArgumentException('response headers must be an array of name => value or name => list of values');
        }

        return [$status, $headers, Encoding::bytes($response['body'] ?? null, 'response body')];
    }
}
