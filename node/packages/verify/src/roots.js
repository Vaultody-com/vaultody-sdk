'use strict';

/**
 * The production root public keys this package trusts, embedded so that the trust anchor never has to
 * be fetched over a network the helper is meant to distrust.
 *
 * FILLED IN AT RELEASE. The production root keys do not exist yet, so both slots are empty. With no
 * roots, every verification throws a ConfigurationError instead of passing. Until then, pass
 * the `roots` option.
 *
 * Two slots make key rotation possible without a flag day:
 *  - current: the root the gateway signs certificates with today;
 *  - next:    the root it will switch to. It is published in a release ahead of the switch, so clients
 *             that have upgraded accept both roots during the change-over.
 *
 * Each slot holds the root's SubjectPublicKeyInfo as PEM and its fingerprint: the lowercase hex SHA-256
 * of the same key in DER. The fingerprint is what is published to clients outside this package (by
 * email) and what the gateway puts in every certificate as the root id. When this package loads, it
 * recomputes each fingerprint from the PEM and refuses to load if they differ, so a key pasted wrongly
 * fails at startup instead of at the first response.
 *
 * Leave a slot as { pem: '', fingerprint: '' } when it has no key.
 */
module.exports = Object.freeze({
    current: Object.freeze({
        pem: '',
        fingerprint: '',
    }),
    next: Object.freeze({
        pem: '',
        fingerprint: '',
    }),
});
