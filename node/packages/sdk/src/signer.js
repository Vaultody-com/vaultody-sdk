'use strict';

/**
 * Request-signing key pairs: where the private key lives is the caller's choice.
 *
 * A signer is any object of this shape:
 *
 *   {
 *     algorithm: 'ed25519' | 'p-256',
 *     publicKeyPem: string,                        // the public key registered on the API key (SPKI PEM)
 *     sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>,
 *     digestOnly?: boolean,                        // P-256 only: sign() receives SHA-256(message), 32 bytes
 *   }
 *
 * so the private key can stay in a KMS or an HSM: the SDK hands over the bytes to sign and gets a signature
 * back. fileSigner and pemSigner keep a key in this process instead (as a KeyObject); awsKmsSigner,
 * gcpKmsSigner and vaultTransitSigner shape the request and the answer of those services around a function
 * the caller passes in, so the SDK depends on none of their client libraries.
 *
 * Around every signer the SDK:
 *  - computes the fingerprint sent as x-api-keypair-id from publicKeyPem (the canonical SPKI, so a compressed
 *    P-256 key gives the same fingerprint);
 *  - turns a 64-byte IEEE P1363 r||s P-256 signature (Web Crypto, Azure Key Vault, some KMS APIs) into the DER
 *    the gateway requires (test-vectors/p1363-der-v1.json), and refuses an Ed25519 signature that is not 64
 *    bytes;
 *  - checks each signature against publicKeyPem before the request is sent (verifyLocally, on by default), so
 *    a signer holding the wrong key fails here with a clear error instead of as a stream of 401s.
 */

const crypto = require('node:crypto');

const { readSigningKey, readSigningKeyFile, p1363ToDer, ALGORITHMS, SigningKeyError, SignatureFormatError } = require('@vaultody-com/verify/keys');
const { ConfigurationError } = require('./errors');

const P1363_BYTES = 64;
const ED25519_SIGNATURE_BYTES = 64;
// AWS KMS signs a RAW Ed25519 message only up to this size; larger bodies need a P-256 key there.
const AWS_KMS_RAW_MESSAGE_LIMIT = 4096;
// Cloud KMS signs Ed25519 data only up to 64 KiB.
const GCP_KMS_DATA_LIMIT = 64 * 1024;
const VAULT_SIGNATURE_PREFIX = /^vault:v[0-9]+:/;

const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest();
const isBytes = value => value instanceof Uint8Array;

function keyError(error, what) {
    if (error instanceof SigningKeyError) {
        return new ConfigurationError('invalid_signer', `${what}: ${error.message}`);
    }
    // Usage errors from the key reader name the file, never its contents.
    if (error && error.name === 'UsageError') {
        return new ConfigurationError('invalid_signer', error.message);
    }

    return error;
}

/** A signer over a private key held in this process. */
function keyObjectSigner(key) {
    const { privateKey, algorithm, publicKeyPem } = key;

    return Object.freeze({
        algorithm,
        publicKeyPem,
        sign: message => (algorithm === ALGORITHMS.ED25519
            ? crypto.sign(null, message, privateKey)
            : crypto.sign('sha256', message, { key: privateKey, dsaEncoding: 'der' })),
    });
}

/**
 * A signer over a PEM private key (PKCS#8 or SEC1, Ed25519 or P-256, unencrypted).
 *
 * @param {string} pem
 * @returns {{ algorithm: string, publicKeyPem: string, sign: Function }}
 * @throws {ConfigurationError} invalid_signer
 */
function pemSigner(pem) {
    try {
        return keyObjectSigner(readSigningKey(pem, { accept: 'private' }));
    } catch (error) {
        throw keyError(error, 'the signing key is not usable');
    }
}

/**
 * A signer over a private key file, read with the same rules as the vaultody keys command line (a size cap,
 * private keys only).
 *
 * @param {string} file
 * @returns {{ algorithm: string, publicKeyPem: string, sign: Function }}
 * @throws {ConfigurationError} invalid_signer
 */
function fileSigner(file) {
    try {
        return keyObjectSigner(readSigningKeyFile(file, { accept: 'private' }));
    } catch (error) {
        throw keyError(error, 'the signing key file is not usable');
    }
}

function toBuffer(value, what) {
    if (isBytes(value)) {
        return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    if (typeof value === 'string') {
        // Some clients return base64 text.
        const bytes = Buffer.from(value, 'base64');
        if (bytes.length > 0 && bytes.toString('base64') === value) {
            return bytes;
        }
    }
    throw new ConfigurationError('invalid_signature', `${what} did not return the signature as bytes`);
}

/**
 * Checks the shape of a signer and wraps it in what the transport calls: one async sign() that returns the
 * signature as sent in x-api-keypair-sign, plus the fingerprint.
 *
 * @param {Object} signer
 * @param {{ verifyLocally?: boolean }} [options]
 * @returns {{ algorithm: string, fingerprint: string, sign(message: Buffer): Promise<string> }}
 * @throws {ConfigurationError} invalid_signer
 */
function prepareSigner(signer, { verifyLocally = true } = {}) {
    if (!signer || typeof signer !== 'object' || typeof signer.sign !== 'function') {
        throw new ConfigurationError('invalid_signer', 'signer must be { algorithm, publicKeyPem, sign(message) }');
    }
    if (signer.algorithm !== ALGORITHMS.ED25519 && signer.algorithm !== ALGORITHMS.P256) {
        throw new ConfigurationError('invalid_signer', `signer.algorithm must be "${ALGORITHMS.ED25519}" or "${ALGORITHMS.P256}"`);
    }
    if (signer.digestOnly !== undefined && typeof signer.digestOnly !== 'boolean') {
        throw new ConfigurationError('invalid_signer', 'signer.digestOnly must be true or false');
    }
    const digestOnly = signer.digestOnly === true;
    if (digestOnly && signer.algorithm !== ALGORITHMS.P256) {
        throw new ConfigurationError('invalid_signer', 'digestOnly is for P-256 signers: Ed25519 signs the whole message');
    }

    let publicKey;
    try {
        publicKey = readSigningKey(signer.publicKeyPem, { accept: 'public' });
    } catch (error) {
        throw keyError(error, 'signer.publicKeyPem is not a usable public key');
    }
    if (publicKey.algorithm !== signer.algorithm) {
        throw new ConfigurationError('invalid_signer', `signer.algorithm is ${signer.algorithm}, but publicKeyPem is a ${publicKey.algorithm} key`);
    }

    async function sign(message) {
        let output;
        try {
            output = await signer.sign(digestOnly ? sha256(message) : Buffer.from(message));
        } catch (error) {
            if (error instanceof ConfigurationError) {
                throw error;
            }
            throw new ConfigurationError('signer_failed', 'the request signer failed', { cause: error });
        }
        const signature = normalizeSignature(signer.algorithm, toBuffer(output, 'the request signer'));
        if (verifyLocally && !verifiesLocally(signer.algorithm, publicKey.publicKey, message, signature)) {
            throw new ConfigurationError('signer_key_mismatch', `the request signer's signature does not verify with its publicKeyPem (${publicKey.fingerprint}): `
                + 'it signs with another key, or returns something other than a signature over what it was given');
        }

        return signature.toString('base64');
    }

    return Object.freeze({ algorithm: signer.algorithm, fingerprint: publicKey.fingerprint, sign });
}

/**
 * A signature in the form the gateway takes: Ed25519 the raw 64 bytes; P-256 DER, converted from IEEE P1363
 * when it is 64 bytes (r||s).
 *
 * @param {string} algorithm
 * @param {Buffer} signature
 * @returns {Buffer}
 * @throws {ConfigurationError} invalid_signature
 */
function normalizeSignature(algorithm, signature) {
    if (algorithm === ALGORITHMS.ED25519) {
        if (signature.length !== ED25519_SIGNATURE_BYTES) {
            throw new ConfigurationError('invalid_signature', `an Ed25519 signature is ${ED25519_SIGNATURE_BYTES} bytes; the signer returned ${signature.length}`);
        }

        return signature;
    }
    if (signature.length === P1363_BYTES) {
        try {
            return p1363ToDer(signature);
        } catch (error) {
            if (error instanceof SignatureFormatError) {
                throw new ConfigurationError('invalid_signature', `the P-256 signature is not usable: ${error.message} (${error.code})`);
            }
            throw error;
        }
    }

    // Anything else must already be DER; the local check, and the gateway, refuse it otherwise.
    return signature;
}

function verifiesLocally(algorithm, publicKey, message, signature) {
    try {
        return algorithm === ALGORITHMS.ED25519
            ? crypto.verify(null, message, publicKey, signature)
            : crypto.verify('sha256', message, { key: publicKey, dsaEncoding: 'der' }, signature);
    } catch (e) {
        return false;
    }
}

function requireFunction(value, name) {
    if (typeof value !== 'function') {
        throw new ConfigurationError('invalid_signer', `${name} must be a function`);
    }
}

function requireString(value, name) {
    if (typeof value !== 'string' || value === '') {
        throw new ConfigurationError('invalid_signer', `${name} must be a non-empty string`);
    }
}

/**
 * AWS KMS (an ECC_NIST_P256 or ECC_NIST_EDWARDS25519 key with key usage SIGN_VERIFY).
 *
 *   const { KMSClient, SignCommand } = require('@aws-sdk/client-kms');
 *   const kms = new KMSClient({});
 *   const signer = awsKmsSigner({ keyId, algorithm: 'p-256', publicKeyPem, sign: params => kms.send(new SignCommand(params)) });
 *
 * P-256 sends the SHA-256 digest (MessageType DIGEST, ECDSA_SHA_256) and gets DER back. Ed25519 sends the
 * whole message (MessageType RAW, ED25519_SHA_512), which AWS limits to 4096 bytes: a larger body, such as a
 * batch transfer, can't be signed that way, so use a P-256 key with AWS KMS.
 *
 * @param {{ keyId: string, algorithm: 'p-256'|'ed25519', publicKeyPem: string, sign: function(Object): Promise<{ Signature: Uint8Array }> }} options
 */
function awsKmsSigner({ keyId, algorithm, publicKeyPem, sign }) {
    requireString(keyId, 'keyId');
    requireFunction(sign, 'sign');
    const p256 = algorithm === ALGORITHMS.P256;

    return Object.freeze({
        algorithm,
        publicKeyPem,
        digestOnly: p256,
        async sign(bytes) {
            if (!p256 && bytes.length > AWS_KMS_RAW_MESSAGE_LIMIT) {
                throw new ConfigurationError('signer_message_too_large', `AWS KMS signs an Ed25519 message of at most ${AWS_KMS_RAW_MESSAGE_LIMIT} bytes; `
                    + `this request's signed string is ${bytes.length}. Use a P-256 key with AWS KMS.`);
            }
            const output = await sign(p256
                ? { KeyId: keyId, Message: bytes, MessageType: 'DIGEST', SigningAlgorithm: 'ECDSA_SHA_256' }
                : { KeyId: keyId, Message: bytes, MessageType: 'RAW', SigningAlgorithm: 'ED25519_SHA_512' });

            return output && output.Signature;
        },
    });
}

/**
 * Google Cloud KMS (EC_SIGN_P256_SHA256 or EC_SIGN_ED25519).
 *
 *   const { KeyManagementServiceClient } = require('@google-cloud/kms');
 *   const kms = new KeyManagementServiceClient();
 *   const signer = gcpKmsSigner({ name: keyVersionName, algorithm: 'p-256', publicKeyPem,
 *       asymmetricSign: request => kms.asymmetricSign(request) });
 *
 * P-256 sends the SHA-256 digest and gets DER back; Ed25519 sends the message as data (at most 64 KiB).
 *
 * @param {{ name: string, algorithm: 'p-256'|'ed25519', publicKeyPem: string, asymmetricSign: function(Object): Promise<*> }} options
 */
function gcpKmsSigner({ name, algorithm, publicKeyPem, asymmetricSign }) {
    requireString(name, 'name');
    requireFunction(asymmetricSign, 'asymmetricSign');
    const p256 = algorithm === ALGORITHMS.P256;

    return Object.freeze({
        algorithm,
        publicKeyPem,
        digestOnly: p256,
        async sign(bytes) {
            if (!p256 && bytes.length > GCP_KMS_DATA_LIMIT) {
                throw new ConfigurationError('signer_message_too_large', `Cloud KMS signs Ed25519 data of at most ${GCP_KMS_DATA_LIMIT} bytes; `
                    + `this request's signed string is ${bytes.length}`);
            }
            const output = await asymmetricSign(p256 ? { name, digest: { sha256: bytes } } : { name, data: bytes });
            // The Node client resolves to [response]; a REST call gives the response itself.
            const response = Array.isArray(output) ? output[0] : output;

            return response && response.signature;
        },
    });
}

/**
 * HashiCorp Vault's transit engine (an ecdsa-p256 or ed25519 key).
 *
 *   const signer = vaultTransitSigner({ keyName, algorithm: 'p-256', publicKeyPem,
 *       write: (path, body) => vault.write(path, body) });   // POST /v1/<mount>/sign/<keyName>
 *
 * P-256 sends the SHA-256 digest (prehashed, sha2-256, asn1 marshaling: DER); Ed25519 sends the message.
 * The "vault:v1:" prefix of the answer is removed.
 *
 * @param {{ keyName: string, mount?: string, algorithm: 'p-256'|'ed25519', publicKeyPem: string, write: function(string, Object): Promise<{ data: { signature: string } }> }} options
 */
function vaultTransitSigner({ keyName, mount = 'transit', algorithm, publicKeyPem, write }) {
    requireString(keyName, 'keyName');
    requireString(mount, 'mount');
    requireFunction(write, 'write');
    const p256 = algorithm === ALGORITHMS.P256;

    return Object.freeze({
        algorithm,
        publicKeyPem,
        digestOnly: p256,
        async sign(bytes) {
            const input = Buffer.from(bytes).toString('base64');
            const output = await write(`${mount}/sign/${keyName}`, p256
                ? { input, prehashed: true, hash_algorithm: 'sha2-256', marshaling_algorithm: 'asn1' }
                : { input });
            const signature = output && output.data && output.data.signature;
            if (typeof signature !== 'string' || !VAULT_SIGNATURE_PREFIX.test(signature)) {
                throw new ConfigurationError('invalid_signature', 'Vault transit did not return a "vault:vN:" signature');
            }

            return Buffer.from(signature.replace(VAULT_SIGNATURE_PREFIX, ''), 'base64');
        },
    });
}

module.exports = {
    pemSigner,
    fileSigner,
    awsKmsSigner,
    gcpKmsSigner,
    vaultTransitSigner,
    prepareSigner,
    normalizeSignature,
    // Internal (the vaultody command line signs with a key it has already read); not exported by the package.
    keyObjectSigner,
};
