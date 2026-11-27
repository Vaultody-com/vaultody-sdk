<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * The production root public keys this package trusts, embedded so that the trust anchor never has to be
 * fetched over a network the SDK is meant to distrust.
 *
 * CURRENT holds the production root (root-prod, a P-256 key in Cloud KMS that never leaves its HSM); NEXT is
 * empty until a rotation. To trust another environment's root instead, pass the `roots` option.
 *
 * Two slots make key rotation possible without a flag day:
 *  - current: the root the gateway signs certificates with today;
 *  - next:    the root it will switch to, published in a release ahead of the switch.
 *
 * Each slot holds the root's SubjectPublicKeyInfo as PEM and its fingerprint: the lowercase hex SHA-256 of
 * the same key in DER, the value published to clients and named in every certificate. Roots::embedded()
 * recomputes each fingerprint from the PEM and refuses to run if they differ, so a key pasted wrongly fails
 * at the first use instead of passing silently. The bytes must equal the Node and Python packages'.
 */
final class EmbeddedRoots
{
    // A single-quoted string across lines, so the PEM's line breaks are in it as written (the release guard
    // reads this form).
    public const CURRENT = [
        'pem' => '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1ikEmarTSQWW1eSFI1gjyXo3ctGp
nY25exvYPRD0rNOwrpfTf+PvUIeVdZrydIpxK/A6Ck9jrIjG/Wg98JeMYA==
-----END PUBLIC KEY-----
',
        'fingerprint' => '0194e94f295844b04dbdfb885338fb4242095e55479a01a03caafee3e36cdd76',
    ];

    public const NEXT = ['pem' => '', 'fingerprint' => ''];
}
