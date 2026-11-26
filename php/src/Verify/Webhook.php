<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * Checks the X-Signature Vaultody puts on every webhook delivery: lowercase hex HMAC-SHA256, keyed with the
 * webhook's signing secret, over the raw body bytes (test-vectors/webhook-v1.json).
 *
 * The scheme has no timestamp, and Vaultody may deliver the same event more than once, so a valid signature
 * does not prove a delivery is new: before acting on an event, check whether it was acted on already, keyed on
 * what the event is about (the docs' Webhook Notifications page names the fields). Several secrets can be
 * given, to keep accepting deliveries while a secret is rotated.
 */
final class Webhook
{
    public const SIGNATURE_HEADER = 'x-signature';
    // Exactly what the signer writes: no prefix, no whitespace, lowercase.
    private const SIGNATURE_FORMAT = '/^[0-9a-f]{64}$/D';

    /**
     * Verifies one webhook delivery before its body is parsed.
     *
     * @param string $rawBody the body exactly as received (php://input), not decoded JSON
     * @param array<array-key, mixed> $headers the request headers; X-Signature is matched case-insensitively
     * @param string|list<string> $secrets the signing secret, or the secrets accepted during a rotation, in order
     * @return array{valid: true, secretIndex: int} the index of the first secret that matches
     * @throws WebhookSignatureError the signature is missing, malformed or matches no secret
     * @throws ConfigurationError no usable secret is given
     */
    public static function verifySignature(mixed $rawBody, array $headers, #[\SensitiveParameter] mixed $secrets): array
    {
        $list = is_array($secrets) ? $secrets : [$secrets];
        if ($list === [] || !array_is_list($list)) {
            throw new ConfigurationError('the webhook signing secret must be a non-empty string, or a non-empty list of them during a rotation');
        }
        foreach ($list as $secret) {
            if (!is_string($secret) || $secret === '') {
                throw new ConfigurationError('the webhook signing secret must be a non-empty string, or a non-empty list of them during a rotation');
            }
        }
        if (!is_string($rawBody)) {
            throw new \InvalidArgumentException('rawBody must be the raw body as received (a string); verify before decoding the JSON');
        }

        $values = Encoding::headerValues($headers, self::SIGNATURE_HEADER);
        $nonEmpty = array_filter($values, static fn (mixed $value): bool => $value !== '');
        if ($nonEmpty === []) {
            throw new WebhookSignatureError(WebhookSignatureError::MISSING, 'the delivery has no X-Signature header');
        }
        if (count($values) > 1 || !is_string($values[0]) || preg_match(self::SIGNATURE_FORMAT, $values[0]) !== 1) {
            throw new WebhookSignatureError(WebhookSignatureError::MALFORMED, 'X-Signature must be one value of 64 lowercase hex characters');
        }
        $received = $values[0];

        // Every secret is tried, so the time taken does not tell which one matched.
        $secretIndex = -1;
        foreach ($list as $index => $secret) {
            if (hash_equals(hash_hmac('sha256', $rawBody, $secret), $received) && $secretIndex === -1) {
                $secretIndex = $index;
            }
        }
        if ($secretIndex === -1) {
            throw new WebhookSignatureError(WebhookSignatureError::MISMATCH, 'no configured secret produces this signature over the body received');
        }

        return ['valid' => true, 'secretIndex' => $secretIndex];
    }
}
