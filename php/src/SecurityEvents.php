<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

/**
 * The security events the client hands to onSecurityEvent: their names and fields, the same in every language
 * (test-vectors/security-events-v1.json). An event never carries a secret, an xpub or an address.
 */
final class SecurityEvents
{
    public const EVENTS = [
        'unsigned_response_accepted' => ['type', 'origin', 'operationId'],
        'response_signature_latched' => ['type', 'origin', 'rootId', 'latchedAt'],
        'response_verification_failed' => ['type', 'origin', 'operationId', 'status', 'reason'],
        'vault_key_pinned' => ['type', 'origin', 'vaultId', 'status'],
        'vault_key_verified' => ['type', 'origin', 'vaultId', 'status'],
        'vault_key_changed' => ['type', 'origin', 'alarms'],
        'address_verification_failed' => ['type', 'origin', 'operationId', 'vaultId', 'code'],
    ];

    /**
     * The event of a type with exactly its fields, in the catalogue's order; a field not given is null. A type
     * or a field that is not in the catalogue is a mistake in the SDK and throws, so no event can grow or rename
     * a field the other languages don't send (every place that raises an event runs in the tests).
     *
     * @param array<string, mixed> $data ['type' => ..., ...fields]
     * @return array<string, mixed>
     * @throws \LogicException
     */
    public static function build(array $data): array
    {
        $type = $data['type'] ?? null;
        if (!is_string($type) || !isset(self::EVENTS[$type])) {
            throw new \LogicException(sprintf('no security event %s', json_encode($type)));
        }
        $fields = self::EVENTS[$type];
        $extra = array_diff(array_keys($data), $fields);
        if ($extra !== []) {
            throw new \LogicException(sprintf('%s has no field %s', $type, implode(', ', $extra)));
        }
        $event = [];
        foreach ($fields as $field) {
            $event[$field] = $data[$field] ?? null;
        }

        return $event;
    }
}
