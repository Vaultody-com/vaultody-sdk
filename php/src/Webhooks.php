<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\WebhookPayloadError;
use Vaultody\Sdk\Exception\WebhookSignatureError;
use Vaultody\Sdk\Verify\ConfigurationError as VerifyConfigurationError;
use Vaultody\Sdk\Verify\Webhook;
use Vaultody\Sdk\Verify\WebhookSignatureError as VerifyWebhookSignatureError;

/**
 * Verifying webhook deliveries: X-Signature first, over the raw body, then the body is parsed.
 *
 *   $event = $vaultody->webhooks->verify(file_get_contents('php://input'), getallheaders(), $secret);
 */
final class Webhooks
{
    /**
     * @param string $rawBody the body exactly as received, never a decoded array
     * @param array<array-key, mixed> $headers the request headers (X-Signature in any case)
     * @param string|list<string> $secrets the signing secret, or the secrets accepted during a rotation
     * @throws WebhookSignatureError the signature is missing, malformed or wrong; do not act on the body
     * @throws ConfigurationError no usable secret
     * @throws WebhookPayloadError a correctly signed body that is not a JSON object with data.event
     */
    public function verify(mixed $rawBody, array $headers, #[\SensitiveParameter] string|array $secrets): WebhookEvent
    {
        try {
            $verdict = Webhook::verifySignature($rawBody, $headers, $secrets);
        } catch (VerifyWebhookSignatureError $error) {
            throw new WebhookSignatureError($error->reason, $error->getMessage(), $error);
        } catch (VerifyConfigurationError $error) {
            throw new ConfigurationError($error->getMessage(), 0, $error);
        }

        $payload = Json::decode((string) $rawBody);
        $data = $payload instanceof \stdClass ? ($payload->data ?? null) : null;
        if (!$data instanceof \stdClass || !is_string($data->event ?? null) || $data->event === '') {
            throw new WebhookPayloadError($payload instanceof \stdClass ? 'the webhook delivery verified, but it has no data.event' : 'the webhook delivery verified, but its body is not a JSON object');
        }
        $item = ($data->item ?? null) instanceof \stdClass ? Json::toArray($data->item) : [];
        $text = static fn (mixed $value): ?string => is_string($value) ? $value : null;

        return new WebhookEvent(
            $data->event,
            $item,
            $text($payload->webhookId ?? null),
            $text($payload->idempotencyKey ?? null),
            $text($payload->walletId ?? null),
            $text($payload->apiVersion ?? null),
            Json::toArray($payload),
            $verdict['secretIndex'],
        );
    }
}
