<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Model;

use Vaultody\Sdk\Transport\Meta;

/** A public key registered for request signing on the calling API key (listApiKeySigningKeys). */
final class ApiKeySigningKey extends Model
{
    /**
     * @param ?string $algorithm The key's algorithm: `ed25519` or `p-256` (ECDSA P-256).
     * @param ?int $approvedTimestamp When an owner approved the key, as a Unix timestamp in seconds.
     * @param ?int $createdTimestamp When the key was sent for approval in the Dashboard, as a Unix timestamp in seconds.
     * @param ?string $fingerprint The key's fingerprint: `SHA256:` and the unpadded Base64 of the SHA-256 of the public key in DER form; compare it with your own key's.
     * @param ?string $status The key's status; the list holds approved keys only, so it is `active`.
     * @param array<string, mixed> $raw the object as it came, undocumented fields included
     */
    public function __construct(
        public readonly ?string $algorithm = null,
        public readonly ?int $approvedTimestamp = null,
        public readonly ?int $createdTimestamp = null,
        public readonly ?string $fingerprint = null,
        public readonly ?string $status = null,
        array $raw = [],
        ?Meta $meta = null,
    ) {
        parent::__construct($raw, $meta);
    }
}
