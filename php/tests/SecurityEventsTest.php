<?php

declare(strict_types=1);

// test-vectors/security-events-v1.json: the security events' names and fields, and the entries of the per-answer
// results, the same in every language. The catalogue the transport builds events from is the vector's; the
// events the transport tests see are checked against it (TransportTest.php).

use Vaultody\Sdk\SecurityEvents;

$vectors = vectors('security-events-v1.json');
$tests = [];

$tests['security events: the catalogue is the vector\'s, the same types with the same fields'] = static function () use ($vectors): void {
    check(array_column($vectors['events'], 'fields', 'type') === SecurityEvents::EVENTS, 'catalogue ' . json_encode(SecurityEvents::EVENTS));
    check($vectors['addressCheck']['fields'] === ['vaultId', 'address', 'status'] && $vectors['vaultKeyResult']['fields'] === ['vaultId', 'status', 'outcome'], 'result entries');
};

foreach ($vectors['events'] as $event) {
    $tests['security events: ' . $event['type'] . ' has exactly its fields; another field is refused'] = static function () use ($event): void {
        $built = SecurityEvents::build(['type' => $event['type'], 'origin' => 'https://rest.example.test']);
        check(array_keys($built) === $event['fields'], 'fields ' . json_encode(array_keys($built)));
        check($built['type'] === $event['type'] && $built['origin'] === 'https://rest.example.test', 'values');
        foreach (array_diff($event['fields'], ['type', 'origin']) as $field) {
            check($built[$field] === null, $field . ' not given is null');
        }
        thrown(static fn () => SecurityEvents::build(['type' => $event['type'], 'origin' => 'o', 'extra' => 'x']), LogicException::class);
    };
}

$tests['security events: a type that is not catalogued is refused'] = static function (): void {
    foreach (['vault_key_upgraded', 'address_mismatch', 'signing_key_confirmation', null] as $type) {
        thrown(static fn () => SecurityEvents::build(['type' => $type]), LogicException::class);
    }
};

return $tests;
