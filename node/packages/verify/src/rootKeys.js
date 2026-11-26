'use strict';

const crypto = require('node:crypto');

const { ConfigurationError } = require('./errors');
const { sha256 } = require('./encoding');
const EMBEDDED_ROOTS = require('./roots');

const EMBEDDED_SLOTS = ['current', 'next'];
const FINGERPRINT = /^[0-9a-f]{64}$/;
const PEM_LABEL = /-----BEGIN ([^-]*)-----/g;
const PEM_BODY = /-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/;
// A P-256 SubjectPublicKeyInfo with a named curve and an uncompressed point is this fixed 27-byte header
// (algorithm ecPublicKey, curve prime256v1, uncompressed-point marker) followed by the 64-byte point.
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex');
const P256_SPKI_BYTES = P256_SPKI_PREFIX.length + 64;

/**
 * Turns one configured root into the key used to check certificates and its id. The id is the lowercase
 * hex SHA-256 of the key's SubjectPublicKeyInfo DER, which is how the gateway names the root in every
 * certificate and how the fingerprint is published to clients.
 *
 * @param {string|{ pem: string, fingerprint?: string }} entry
 * @param {string} label where the entry came from, for error messages
 * @returns {{ rootId: string, key: crypto.KeyObject }}
 */
function pinRoot(entry, label) {
    const pem = typeof entry === 'string' ? entry : entry && typeof entry === 'object' ? entry.pem : undefined;
    if (typeof pem !== 'string' || pem.trim() === '') {
        throw new ConfigurationError(`${label} must be a public key in SPKI PEM form, or { pem }`);
    }

    // Only a public key is accepted. Node would happily derive a public key from a private key or read
    // one out of a certificate, but a root's private key must never be on a client, and a certificate
    // here would mean something was mixed up.
    const labels = [...pem.matchAll(PEM_LABEL)].map(match => match[1]);
    if (labels.length !== 1 || labels[0] !== 'PUBLIC KEY') {
        throw new ConfigurationError(`${label} must hold exactly one "PUBLIC KEY" PEM block`);
    }

    let key;
    try {
        key = crypto.createPublicKey({ key: pem, format: 'pem' });
    } catch (e) {
        throw new ConfigurationError(`${label} is not a readable public key: ${e.message}`);
    }
    if (key.asymmetricKeyType !== 'ec' || !key.asymmetricKeyDetails || key.asymmetricKeyDetails.namedCurve !== 'prime256v1') {
        throw new ConfigurationError(`${label} must be an EC P-256 key`);
    }

    // The root id is a hash of the key's DER bytes, so every party must hash the same bytes for the same
    // key. Only the one standard layout is accepted, the one Cloud KMS publishes; a compressed point or
    // explicit curve parameters would describe the same key with different bytes and a different id.
    const body = pem.match(PEM_BODY);
    const spki = body ? Buffer.from(body[1].replace(/\s+/g, ''), 'base64') : Buffer.alloc(0);
    if (spki.length !== P256_SPKI_BYTES || !spki.subarray(0, P256_SPKI_PREFIX.length).equals(P256_SPKI_PREFIX)) {
        throw new ConfigurationError(`${label} must be a P-256 key in standard SPKI form (named curve, uncompressed point)`);
    }

    const rootId = sha256(spki).toString('hex');
    const fingerprint = entry && typeof entry === 'object' ? entry.fingerprint : undefined;
    if (fingerprint !== undefined && fingerprint !== null && fingerprint !== '') {
        if (typeof fingerprint !== 'string' || !FINGERPRINT.test(fingerprint)) {
            throw new ConfigurationError(`${label} fingerprint must be 64 lowercase hex characters`);
        }
        if (fingerprint !== rootId) {
            throw new ConfigurationError(`${label} fingerprint ${fingerprint} does not match its key, whose SHA-256 SPKI fingerprint is ${rootId}`);
        }
    }

    return Object.freeze({ rootId, key });
}

const isEmptyEntry = entry => entry === undefined || entry === null || entry === ''
    || (typeof entry === 'object' && (entry.pem === undefined || entry.pem === null || entry.pem === '')
        && (entry.fingerprint === undefined || entry.fingerprint === null || entry.fingerprint === ''));

/**
 * Checks the roots embedded in the package. A slot is either fully empty or holds a key together with
 * the fingerprint that was published for it; anything in between, or a fingerprint that does not match
 * its key, stops the package from loading.
 *
 * @param {{ current?: { pem: string, fingerprint: string }, next?: { pem: string, fingerprint: string } }} embedded
 * @returns {ReadonlyArray<{ rootId: string, key: crypto.KeyObject }>}
 */
function loadEmbeddedRoots(embedded) {
    const pinned = [];
    for (const slot of EMBEDDED_SLOTS) {
        const entry = (embedded && embedded[slot]) || {};
        const hasPem = typeof entry.pem === 'string' && entry.pem !== '';
        const hasFingerprint = typeof entry.fingerprint === 'string' && entry.fingerprint !== '';
        if (!hasPem && !hasFingerprint) {
            continue;
        }
        if (!hasPem || !hasFingerprint) {
            throw new ConfigurationError(`embedded root "${slot}" has ${hasPem ? 'a key but no fingerprint' : 'a fingerprint but no key'}`);
        }
        pinned.push(pinRoot(entry, `embedded root "${slot}"`));
    }

    return Object.freeze(pinned);
}

// Runs when the package is first required, so a wrongly filled-in root fails the process at startup.
const EMBEDDED = loadEmbeddedRoots(EMBEDDED_ROOTS);

/**
 * Reads the `roots` option without requiring it to hold a key: a malformed entry is a setup mistake and
 * throws at once, but empty slots are allowed, because whether any root is needed depends on the response
 * (an unsigned one needs none).
 *
 * @param {undefined|null|string|{ pem: string, fingerprint?: string }|Array|Object} roots
 * @returns {ReadonlyArray<{ rootId: string, key: crypto.KeyObject }>|null} null when the option is not given
 */
function parseRoots(roots) {
    if (roots === undefined || roots === null) {
        return null;
    }

    let entries;
    if (typeof roots === 'string' || (typeof roots === 'object' && !Array.isArray(roots) && 'pem' in roots)) {
        entries = [['roots', roots]];
    } else if (Array.isArray(roots)) {
        entries = roots.map((entry, index) => [`roots[${index}]`, entry]);
    } else if (typeof roots === 'object') {
        entries = Object.entries(roots).map(([name, entry]) => [`roots.${name}`, entry]);
    } else {
        throw new ConfigurationError('`roots` must be a PEM string, { pem }, an array of those, or an object such as { current, next }');
    }

    // An empty slot is allowed, because "next" exists only around a rotation.
    return Object.freeze(entries.filter(([, entry]) => !isEmptyEntry(entry)).map(([label, entry]) => pinRoot(entry, label)));
}

/**
 * The roots to check a signed response against: the parsed `roots` option when given, else the embedded
 * ones. Having none is a setup mistake and is reported as one, never treated as "nothing to check". It is
 * called only once a response carries a signature, so an unsigned response never needs a root.
 *
 * @param {ReadonlyArray<{ rootId: string, key: crypto.KeyObject }>|null} parsed the result of parseRoots
 * @returns {ReadonlyArray<{ rootId: string, key: crypto.KeyObject }>}
 */
function requireRoots(parsed) {
    if (parsed === null) {
        if (EMBEDDED.length === 0) {
            throw new ConfigurationError('no root keys are configured: this build of @vaultody/verify has no embedded '
                + 'production roots yet, so pass them in the `roots` option. Refusing to treat any response as verified.');
        }

        return EMBEDDED;
    }
    if (parsed.length === 0) {
        throw new ConfigurationError('the `roots` option holds no keys. Refusing to treat any response as verified.');
    }

    return parsed;
}

/**
 * The roots to check certificates against: the `roots` option when given, else the embedded ones.
 * Having none is a setup mistake and is reported as one, never treated as "nothing to check".
 *
 * @param {undefined|null|string|{ pem: string, fingerprint?: string }|Array|Object} roots
 *        a PEM string or { pem }, an array of those, or an object of them such as { current, next }
 * @returns {ReadonlyArray<{ rootId: string, key: crypto.KeyObject }>}
 */
function resolveRoots(roots) {
    return requireRoots(parseRoots(roots));
}

/**
 * The fingerprints (root ids) of the roots embedded in this build, to compare with the ones Vaultody
 * published. Empty until the production root exists: then a signed response needs the `roots` option.
 *
 * @returns {ReadonlyArray<string>}
 */
const embeddedFingerprints = () => Object.freeze(EMBEDDED.map(root => root.rootId));

module.exports = {
    pinRoot,
    loadEmbeddedRoots,
    parseRoots,
    requireRoots,
    resolveRoots,
    embeddedFingerprints,
};
