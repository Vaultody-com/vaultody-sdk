'use strict';

/**
 * The production root public keys this package trusts, embedded so that the trust anchor never has to
 * be fetched over a network the helper is meant to distrust.
 *
 * current holds the production root (root-prod, a P-256 key in Cloud KMS that never leaves its HSM);
 * next is empty until a rotation. To trust another environment's root instead, pass the `roots` option.
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
        pem: '-----BEGIN PUBLIC KEY-----\n'
            + 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1ikEmarTSQWW1eSFI1gjyXo3ctGp\n'
            + 'nY25exvYPRD0rNOwrpfTf+PvUIeVdZrydIpxK/A6Ck9jrIjG/Wg98JeMYA==\n'
            + '-----END PUBLIC KEY-----\n',
        fingerprint: '0194e94f295844b04dbdfb885338fb4242095e55479a01a03caafee3e36cdd76',
    }),
    next: Object.freeze({
        pem: '',
        fingerprint: '',
    }),
});
