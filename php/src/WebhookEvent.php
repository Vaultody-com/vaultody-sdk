<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

/**
 * One verified webhook delivery. $event is data.event; an event this SDK version does not know is still
 * returned (isKnown() false), never refused, so a new event type does not break a receiver.
 *
 * The signature scheme has no timestamp, and Vaultody may deliver the same event more than once, so a valid
 * signature does not prove a delivery is new. Before acting on an event, check whether it was acted on already,
 * keyed on what the event is about, as the docs' Webhook Notifications page says: outgoing transaction events
 * $item['requestId'] and $event; incoming ones $item['transactionId'], $item['address'], $event and
 * $item['currentConfirmations'] ($item['parentTransactionId'] and $item['operationId'] in place of
 * transactionId for an internal transfer). The SDK stores nothing.
 */
final class WebhookEvent
{
    public const TRANSACTION_REQUEST = 'TRANSACTION_REQUEST';
    public const TRANSACTION_APPROVED = 'TRANSACTION_APPROVED';
    public const TRANSACTION_REJECTED = 'TRANSACTION_REJECTED';
    public const TRANSACTION_BROADCASTED = 'TRANSACTION_BROADCASTED';
    public const OUTGOING_MINED = 'OUTGOING_MINED';
    public const OUTGOING_MINED_WITH_ERRORS = 'OUTGOING_MINED_WITH_ERRORS';
    public const OUTGOING_FAILED = 'OUTGOING_FAILED';
    public const INCOMING_MINED_TX = 'INCOMING_MINED_TX';
    public const INCOMING_CONFIRMED_COIN_TX = 'INCOMING_CONFIRMED_COIN_TX';
    public const INCOMING_CONFIRMED_TOKEN_TX = 'INCOMING_CONFIRMED_TOKEN_TX';
    public const INCOMING_CONFIRMED_INTERNAL_TX = 'INCOMING_CONFIRMED_INTERNAL_TX';
    /** A deposit removed from the chain by a reorganisation (opt-in). */
    public const INCOMING_TX_REVERTED = 'INCOMING_TX_REVERTED';

    public const KNOWN = [
        self::TRANSACTION_REQUEST, self::TRANSACTION_APPROVED, self::TRANSACTION_REJECTED, self::TRANSACTION_BROADCASTED,
        self::OUTGOING_MINED, self::OUTGOING_MINED_WITH_ERRORS, self::OUTGOING_FAILED, self::INCOMING_MINED_TX,
        self::INCOMING_CONFIRMED_COIN_TX, self::INCOMING_CONFIRMED_TOKEN_TX, self::INCOMING_CONFIRMED_INTERNAL_TX,
        self::INCOMING_TX_REVERTED,
    ];

    /**
     * @param array<string, mixed> $item data.item, with unknown fields (such as inclusion) kept
     * @param array<string, mixed> $payload the whole delivery
     */
    public function __construct(
        public readonly string $event,
        public readonly array $item,
        public readonly ?string $webhookId,
        public readonly ?string $idempotencyKey,
        public readonly ?string $walletId,
        public readonly ?string $apiVersion,
        public readonly array $payload,
        /** the index of the configured secret that matched, during a rotation */
        public readonly int $secretIndex = 0,
    ) {
    }

    public function isKnown(): bool
    {
        return in_array($this->event, self::KNOWN, true);
    }
}
