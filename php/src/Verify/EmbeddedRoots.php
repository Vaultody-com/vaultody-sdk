<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * The production root public keys this package trusts, embedded so that the trust anchor never has to be
 * fetched over a network the SDK is meant to distrust.
 *
 * FILLED IN AT RELEASE. The production root keys do not exist yet, so both slots are empty. With no roots,
 * a signed response fails with a ConfigurationError instead of passing; an unsigned one needs no root.
 * Until then, pass the `roots` option (test environments only).
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
    public const CURRENT = ['pem' => '', 'fingerprint' => ''];

    public const NEXT = ['pem' => '', 'fingerprint' => ''];
}
