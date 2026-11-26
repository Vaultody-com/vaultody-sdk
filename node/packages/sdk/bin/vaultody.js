#!/usr/bin/env node
'use strict';

/**
 * The `vaultody` command line: request-signing key pairs for Vaultody API keys, and the SDK's vault xpub pins.
 *
 *   vaultody keys generate --algorithm ed25519|p-256 --out private.pem --public-out public.pem [--force]
 *   vaultody keys fingerprint --key public.pem|private.pem
 *   vaultody keys prove --key private.pem --api-key-id <id> --challenge vk-chal-<64 hex>
 *   vaultody keys verify --key private.pem [--root <url>] [--response-root-key <root.pem>] [--allow-unsigned]
 *   vaultody vault-keys accept --vault-id <id> [--file <vault-keys.json>] [--root <url>] [--key private.pem]
 *                              [--response-root-key <root.pem>] [--allow-unsigned]
 *                              [--yes --expect type=<main|test>,ECDSA=<fingerprint|->,EDDSA=<fingerprint|->]
 *
 * It ships with @vaultody-com/sdk (`npx @vaultody-com/sdk keys ...`). The key formats are @vaultody-com/verify's
 * (keys.js); `keys verify` asks the API through the SDK's own client (listApiKeySigningKeys), so its request is
 * signed, and its response verified, exactly as every SDK call. This file reads the arguments, prints and picks
 * the exit code. It never prints a private key, the API secret, the passphrase or the API key, and reads the
 * credentials from the environment only, never from arguments (which other users of the machine can see).
 */

const fs = require('node:fs');
const util = require('node:util');

const keys = require('@vaultody-com/verify/keys');
const { parseRoots, embeddedFingerprints, ConfigurationError: RootKeyError } = require('@vaultody-com/verify/response');
const { Vaultody } = require('../src/client');
const { MODES, carriesSignature } = require('../src/responseVerification');
const { MemoryVaultKeyStore, FileVaultKeyStore, defaultVaultKeysFile } = require('../src/vaultKeyStore');
const { ALGORITHMS: PIN_ALGORITHMS, xpubHash } = require('../src/vaultKeys');
const { keyObjectSigner } = require('../src/signer');
const {
    ApiError, ConfigurationError, ResponseVerificationError, TransportError, VaultKeyStoreError,
} = require('../src/errors');
const { version } = require('../package.json');

const EXIT = Object.freeze({
    OK: 0,
    // the API refused the request, the key is not registered or not active, or the response failed its signature check
    REFUSED: 1,
    // wrong arguments, files or environment
    USAGE: 2,
    // a network error or an answer that is neither the list nor a refusal
    UNEXPECTED: 3,
    // the response was not signed, so the answer could not be verified
    UNSIGNED: 4,
});

const CREDENTIAL_ENV = Object.freeze({
    apiKey: 'VAULTODY_API_KEY',
    apiSecret: 'VAULTODY_API_SECRET',
    passphrase: 'VAULTODY_PASSPHRASE',
});

const CREDENTIALS_FROM_ENV = `The API credentials are read only from the environment: ${Object.values(CREDENTIAL_ENV).join(', ')}.`;
// Option names a person might try for the credentials
const CREDENTIAL_OPTION = /secret|passphrase|password|^--?api-?key$|^--?key-?secret$/i;
// Root private keys are read with a cap; a P-256 public key PEM is under 200 bytes.
const MAX_ROOT_KEY_FILE_BYTES = 16 * 1024;

const EXIT_CODES_HELP = 'Exit codes: 0 ok, 1 refused or not registered, 2 usage error, 3 network or unexpected error, '
    + '4 the response was not signed, so the answer could not be verified.';

const UNSIGNED_VERDICT = 'the response was not signed, so the answer could not be verified.';

// Response-signing root keys built into this package. Once there are any, every response must be signed.
const HAS_EMBEDDED_ROOTS = embeddedFingerprints().length > 0;

const MAIN_USAGE = `Usage: vaultody keys <command> [options]
       vaultody vault-keys accept [options]

Request-signing key pairs for Vaultody API keys, and the vault xpub pins of the Vaultody SDKs.

Commands:
  keys generate        Make a new key pair
                       vaultody keys generate --algorithm ed25519 --out private.pem --public-out public.pem
  keys fingerprint     Print the fingerprint of a public or private key
                       vaultody keys fingerprint --key public.pem
  keys prove           Sign the challenge the dashboard shows when you register a key
                       vaultody keys prove --key private.pem --api-key-id <apiKeyId> --challenge <challenge>
  keys verify          Check that the key is registered and active on your API key
                       vaultody keys verify --key private.pem
  vault-keys accept    Re-pin a vault whose keys or type changed, once you confirmed the change with Vaultody
                       vaultody vault-keys accept --vault-id <vaultId> [--yes --expect <fingerprints>]

Run "vaultody keys <command> --help" or "vaultody vault-keys accept --help" for the options of a command.
${EXIT_CODES_HELP}
`;

const COMMANDS = {
    generate: {
        options: {
            algorithm: { type: 'string' },
            out: { type: 'string' },
            'public-out': { type: 'string' },
            force: { type: 'boolean' },
        },
        required: ['algorithm', 'out', 'public-out'],
        usage: `Usage: vaultody keys generate --algorithm ed25519|p-256 --out private.pem --public-out public.pem [--force]

Makes a new key pair and prints its fingerprint.

  --algorithm    ed25519 (recommended) or p-256 (ECDSA P-256)
  --out          where to write the private key (PKCS#8 PEM, mode 0600). Keep it secret.
  --public-out   where to write the public key (SPKI PEM, mode 0644). Paste this one into the dashboard.
  --force        replace files that already exist; without it nothing is ever overwritten
`,
        run: runGenerate,
    },
    fingerprint: {
        options: {
            key: { type: 'string' },
        },
        required: ['key'],
        usage: `Usage: vaultody keys fingerprint --key public.pem|private.pem

Prints the key's fingerprint, as the dashboard shows it: SHA256: and the unpadded base64 SHA-256 of the
public key (SubjectPublicKeyInfo DER, a P-256 point uncompressed).
`,
        run: runFingerprint,
    },
    prove: {
        options: {
            key: { type: 'string' },
            'api-key-id': { type: 'string' },
            challenge: { type: 'string' },
        },
        required: ['key', 'api-key-id', 'challenge'],
        usage: `Usage: vaultody keys prove --key private.pem --api-key-id <apiKeyId> --challenge vk-chal-<64 hex>

Signs the registration challenge and prints the signature (base64) for you to paste into the dashboard.

  --key          the private key of the public key you are registering
  --api-key-id   the API key id the dashboard shows next to the challenge
  --challenge    the challenge exactly as the dashboard shows it
`,
        run: runProve,
    },
    verify: {
        options: {
            key: { type: 'string' },
            root: { type: 'string' },
            'api-version': { type: 'string' },
            'response-root-key': { type: 'string', multiple: true },
            'allow-unsigned': { type: 'boolean' },
        },
        required: ['key'],
        usage: `Usage: vaultody keys verify --key private.pem [--root <url>] [--api-version <YYYY-MM-DD>] [--response-root-key <root.pem>]
                            [--allow-unsigned]

Asks GET ${keys.SIGNING_KEYS_PATH} with a request signed with the API key and this private key, through
the SDK's client (a network error, 429 or 5xx is retried as for any read), and checks that the key is
registered and active on the API key. The response must be signed, and its signature is verified before
anything in it is read. An unsigned response exits 4: its answer could not be verified, because whatever
removed the signature could also have changed the answer.

  --key                 the private key to check
  --root                the API root (default ${keys.DEFAULT_API_ROOT}); https, or plain http only to
                        localhost (a port-forward)
  --api-version         the x-api-version to send, YYYY-MM-DD (default ${keys.SIGNING_KEYS_API_VERSION}, the version
                        the endpoint was introduced in)
  --response-root-key   a response-signing root public key (PEM) to trust instead of the built-in ones,
                        for test environments; may be given more than once
  --allow-unsigned      accept an unsigned response with a warning (exit 0 or 1 instead of 4), for as long as
                        Vaultody does not sign responses yet. Ignored when response-signing root keys are
                        configured (built in or --response-root-key): then the response must be signed.

${CREDENTIALS_FROM_ENV}
${EXIT_CODES_HELP}
`,
        run: runVerify,
    },
};

const VAULT_KEY_COMMANDS = {
    accept: {
        options: {
            'vault-id': { type: 'string' },
            file: { type: 'string' },
            root: { type: 'string' },
            key: { type: 'string' },
            'response-root-key': { type: 'string', multiple: true },
            'allow-unsigned': { type: 'boolean' },
            yes: { type: 'boolean' },
            expect: { type: 'string' },
        },
        required: ['vault-id'],
        usage: `Usage: vaultody vault-keys accept --vault-id <vaultId> [--file <vault-keys.json>] [--root <url>] [--key private.pem]
                                  [--response-root-key <root.pem>] [--allow-unsigned]
                                  [--yes --expect type=<main|test>,ECDSA=<fingerprint|->,EDDSA=<fingerprint|->]

Re-pins one vault in the SDKs' pin file. The SDKs refuse a vault whose xpub changed, that gained a key it did
not have, or whose type changed (VaultKeyChangedError) until it is re-pinned. Confirm the change with Vaultody
first: this command asks the API for the vault list (GET /vaults/main and /vaults/test, through the SDK's
client) and shows the pinned and the new fingerprints side by side, with the exact --yes --expect options that
re-pin to what it showed. The fingerprints are the ones the alarm shows: the first 16 hex characters of the
SHA-256 of each xpub. The run with --yes reads the vault list again and replaces the pin only when that list
shows exactly the type and fingerprints given in --expect, the ones you confirmed with Vaultody.

  --vault-id            the vault to re-pin
  --file                the pin file (default VAULTODY_VAULT_KEYS_FILE, else ~/.vaultody/vault-keys.json): the
                        file every SDK language shares
  --root                the API root (default ${keys.DEFAULT_API_ROOT}); https, or plain http only to
                        localhost (a port-forward). Pins are kept per API origin.
  --key                 the private key registered on the API key, when the API key has one: requests must then
                        be signed with it
  --response-root-key   a response-signing root public key (PEM) to trust instead of the built-in ones, for test
                        environments; may be given more than once
  --allow-unsigned      accept an unsigned vault list, for as long as Vaultody does not sign responses yet; the new
                        pin is then unverified until a signed answer confirms it. Ignored when response-signing root
                        keys are configured, or the pin file has seen a signed answer from this API: then the answer
                        must be signed.
  --yes                 replace the pin; without it nothing is written. Needs --expect
  --expect              the type and fingerprints the new pin must have, as the run without --yes prints them:
                        type=main,ECDSA=<16 hex>,EDDSA=- (- for an algorithm the vault has no key for)

${CREDENTIALS_FROM_ENV}
Exit codes: 0 re-pinned, or the pin already matches; 1 not re-pinned (no --yes, the API shows other keys than
--expect, no pin to replace, the vault is not listed or has no keys, the API refused, or the response failed its
signature check); 2 usage error (--yes without --expect among them); 3 network or unexpected error; 4 the response
was not signed, so the answer could not be verified.
`,
        run: runAccept,
    },
};

const COMMAND_GROUPS = Object.freeze({ keys: COMMANDS, 'vault-keys': VAULT_KEY_COMMANDS });

/** The option's name as typed, from a parseArgs error, which never includes the value */
const optionNameIn = message => {
    const match = /'(-[^'\s]*)/.exec(message);

    return match ? match[1] : 'an option';
};

/** A mistake in the arguments themselves, after which the command's help is worth pointing to */
const argumentError = message => Object.assign(new keys.UsageError(message), { showHelp: true });

function parseCommandArgs(command, args) {
    const options = { help: { type: 'boolean', short: 'h' } };
    for (const [name, spec] of Object.entries(command.options)) {
        // Every string option is collected as a list, so one given twice is refused instead of silently replaced.
        options[name] = spec.type === 'string' ? { type: 'string', multiple: true } : spec;
    }

    let parsed;
    try {
        parsed = util.parseArgs({ args, options, strict: true, allowPositionals: false });
    } catch (e) {
        // parseArgs' own messages can quote a stray argument, which may be a secret: never print them.
        const name = optionNameIn(e.message);
        if (e.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') {
            throw argumentError(`unknown option ${name}${CREDENTIAL_OPTION.test(name) ? `. ${CREDENTIALS_FROM_ENV}` : ''}`);
        }
        if (e.code === 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE') {
            throw argumentError(/does not take/.test(e.message) ? `${name} takes no value` : `${name} needs a value`);
        }
        if (e.code === 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL') {
            throw argumentError('unexpected argument: every value follows its option, as in --key private.pem');
        }
        throw argumentError('the arguments could not be read');
    }

    const values = {};
    for (const [name, value] of Object.entries(parsed.values)) {
        if (Array.isArray(value) && !command.options[name].multiple) {
            if (value.length > 1) {
                throw argumentError(`--${name} was given more than once`);
            }
            values[name] = value[0];
        } else {
            values[name] = value;
        }
    }
    if (values.help) {
        return values;
    }
    for (const name of command.required) {
        if (values[name] === undefined) {
            throw argumentError(`--${name} is required`);
        }
        if (values[name] === '') {
            throw argumentError(`--${name} needs a value`);
        }
    }

    return values;
}

const FILE_USAGE_ERRORS = new Set(['EEXIST', 'ENOENT', 'EACCES', 'EPERM', 'EISDIR', 'ENOTDIR', 'EROFS', 'ELOOP', 'ENAMETOOLONG']);

async function runGenerate(values, io) {
    const algorithm = values.algorithm;
    if (!Object.values(keys.ALGORITHMS).includes(algorithm)) {
        throw new keys.UsageError(`--algorithm must be "${keys.ALGORITHMS.ED25519}" or "${keys.ALGORITHMS.P256}"`);
    }

    const pair = keys.generateSigningKeyPair(algorithm);
    try {
        keys.writeKeyPairFiles({
            privatePath: values.out,
            publicPath: values['public-out'],
            privateKeyPem: pair.privateKeyPem,
            publicKeyPem: pair.publicKeyPem,
            force: values.force === true,
        });
    } catch (e) {
        if (e.code === 'EEXIST') {
            throw new keys.UsageError(`${JSON.stringify(e.path)} already exists. Nothing was written; pass --force to replace it.`);
        }
        if (FILE_USAGE_ERRORS.has(e.code)) {
            throw new keys.UsageError(`cannot write ${JSON.stringify(e.path)} (${e.code}). Nothing was written.`);
        }
        throw e;
    }

    io.stderr(`Wrote ${values.out}: the ${algorithm} private key (mode 0600). Keep it secret: never paste or send it anywhere, Vaultody included.\n`);
    io.stderr(`Wrote ${values['public-out']}: the public key. Paste this one into the dashboard.\n`);
    io.stdout(`${pair.fingerprint}\n`);

    return EXIT.OK;
}

async function runFingerprint(values, io) {
    const key = readKeyArgument(values.key, 'any');
    io.stdout(`${key.fingerprint}\n`);

    return EXIT.OK;
}

async function runProve(values, io) {
    const challenge = values.challenge;
    const apiKeyId = values['api-key-id'];
    if (!keys.isChallenge(challenge)) {
        throw new keys.UsageError('--challenge must be "vk-chal-" followed by 64 lowercase hex characters, exactly as the dashboard shows it, '
            + 'with no spaces or line breaks');
    }
    if (!keys.isApiKeyId(apiKeyId)) {
        throw new keys.UsageError('--api-key-id must be the 24-character API key id the dashboard shows next to the challenge');
    }

    const key = readKeyArgument(values.key, 'private');
    const signature = keys.signChallengeProof(key, { apiKeyId, challenge });
    // A signature that would not verify is never handed out.
    if (!keys.verifyChallengeProof(key, { apiKeyId, challenge, signature })) {
        throw new Error('the signature just made does not verify');
    }
    io.stdout(`${signature}\n`);

    return EXIT.OK;
}

function readKeyArgument(file, accept) {
    try {
        return keys.readSigningKeyFile(file, { accept });
    } catch (e) {
        if (e instanceof keys.SigningKeyError) {
            throw new keys.UsageError(`${file}: ${e.message}`);
        }
        throw e;
    }
}

function readRootKeys(files) {
    const pems = files.map(file => {
        try {
            const stat = fs.statSync(file);
            if (!stat.isFile() || stat.size > MAX_ROOT_KEY_FILE_BYTES) {
                throw new keys.UsageError(`--response-root-key ${JSON.stringify(file)} is not a public key file`);
            }

            return fs.readFileSync(file, 'utf8');
        } catch (e) {
            if (e instanceof keys.UsageError) {
                throw e;
            }
            throw new keys.UsageError(`cannot read --response-root-key ${JSON.stringify(file)} (${e.code || 'error'})`);
        }
    });
    // Checked now, so a wrong root fails before anything is sent.
    parseRoots(pems);

    return pems;
}

function readCredentials(env) {
    const credentials = {};
    const missing = [];
    for (const [field, name] of Object.entries(CREDENTIAL_ENV)) {
        const value = env[name];
        if (typeof value !== 'string' || value === '') {
            missing.push(name);
        } else {
            credentials[field] = value;
        }
    }
    if (missing.length > 0) {
        throw new keys.UsageError(`set ${missing.join(', ')} in the environment; the credentials are never taken from arguments`);
    }
    try {
        keys.decodeApiSecret(credentials.apiSecret);
    } catch (e) {
        throw new keys.UsageError(`${CREDENTIAL_ENV.apiSecret} is not the API secret (base64) the dashboard gave you`);
    }

    return credentials;
}

/** Text from the API, made safe to print: printable ASCII on one line, so no answer can drive the terminal */
const shown = text => String(text).replace(/[^\x20-\x7e]/g, '?').slice(0, 300);

// What to do next, for the refusals a person can act on
const REFUSAL_HINTS = Object.freeze({
    unknown_api_keypair_id: 'This key is not registered on this API key, or its registration is not approved yet.',
    invalid_api_keypair_sign: 'The API did not accept the signature made with this key.',
    api_keypair_required: 'This API key has no signing key yet: register one in the dashboard.',
    invalid_api_key: `Check ${CREDENTIAL_ENV.apiKey} and ${CREDENTIAL_ENV.passphrase}.`,
    invalid_api_sign: `Check ${CREDENTIAL_ENV.apiSecret} and ${CREDENTIAL_ENV.passphrase}.`,
    missing_authorization_header: `Check ${Object.values(CREDENTIAL_ENV).join(', ')}.`,
    invalid_api_timestamp: 'Check the clock of this machine.',
    ip_address_not_whitelisted: 'Call from an IP address on the API key\'s allow-list.',
});

function describeKeys(result) {
    if (result.keys.length === 0) {
        return 'This API key has no signing keys.\n';
    }
    const lines = result.keys.map(item => `  ${shown(item.fingerprint)}  ${shown(item.algorithm).padEnd(7)}  ${shown(item.status)}`
        + `${item.fingerprint === result.fingerprint ? '  (this key)' : ''}`);

    return `Signing keys of this API key:\n${lines.join('\n')}\n`;
}

const describeResponseSignature = (result, origin) => {
    if (result.responseSignature.signed) {
        const { rootId } = result.responseSignature;

        return `Response signature: verified${rootId ? ` (root ${rootId})` : ''}.\n`;
    }

    return `Response signature: none. ${origin} did not sign this response, so this answer could not be verified; `
        + 'accepted only because of --allow-unsigned.\n';
};

/** What an answer said, in one line and a hint, for an answer that could not be verified */
function describeOutcome(result, key) {
    if (result.outcome === 'unread') {
        return 'not read: with response-signing root keys configured, an unsigned answer is refused before it is read.\n';
    }
    if (result.outcome === 'refused') {
        const hint = REFUSAL_HINTS[result.error.code];

        return `the API refused the request: ${shown(result.error.code)} (HTTP ${result.status}).\n${hint ? `${hint}\n` : ''}`;
    }
    if (result.outcome === 'active') {
        return `${key.fingerprint} is listed as registered and active.\n`;
    }

    return result.outcome === 'inactive'
        ? `${key.fingerprint} is listed but not active.\n`
        : `${key.fingerprint} is not listed.\n`;
}

/** The API's own message of an error answer, or '' when it gave none (ApiError then words one itself). */
const apiMessageOf = error => (error.message === `Vaultody API answered ${error.status}${error.code ? ` ${error.code}` : ''}` ? '' : error.message);

/** The system code of a network failure (ECONNREFUSED, ENOTFOUND, a TLS code, ...), from the errors under it. */
function networkCodeOf(error) {
    const queue = [error];
    for (let seen = 0; queue.length > 0 && seen < 16; seen += 1) {
        const next = queue.shift();
        if (next && typeof next === 'object') {
            if (next !== error && typeof next.code === 'string') {
                return next.code;
            }
            queue.push(next.cause, ...(Array.isArray(next.errors) ? next.errors : []));
        }
    }

    return null;
}

/**
 * Asks the API which signing keys the API key holds (listApiKeySigningKeys), through the SDK's client: the request
 * signed with HMAC v2 and this key pair, the response verified whenever it carries a signature, before anything
 * in it is read. An unsigned response is accepted by the client and reported as unsigned; the caller decides.
 *
 * @returns {Promise<{ outcome: 'active'|'inactive'|'not_listed'|'refused', status: number, requestId: string|null,
 *          keys: Array<Object>, error: { code: string, message: string }|null,
 *          responseSignature: { signed: boolean, rootId?: string } }>}
 * @throws {ResponseVerificationError} the response signature does not verify
 * @throws {ApiError} an answer that is neither the list nor a refusal
 * @throws {TransportError|ConfigurationError}
 */
async function checkRegisteredKey(key, credentials, { apiRoot, apiVersion, roots, io }) {
    const unsupported = { apiVersion };
    if (io.clock) {
        unsupported.clock = io.clock;
    }
    if (io.sleep) {
        unsupported.sleep = io.sleep;
    }
    // With root keys configured the client refuses an unsigned answer before reading it. The headers of the last
    // answer tell an answer with no signature at all (reported as unsigned, exit 4, as without root keys) from one
    // with part of a signature stripped (a failed check, exit 1).
    let lastHeaders = null;
    unsupported.fetch = async (url, init) => {
        const response = await fetch(url, init);
        lastHeaders = response.headers;

        return response;
    };
    const client = new Vaultody({
        apiKey: credentials.apiKey,
        apiSecret: credentials.apiSecret,
        passphrase: credentials.passphrase,
        baseUrl: apiRoot,
        signer: keyObjectSigner(key),
        // An unsigned answer is accepted, marked unsigned, and judged here (exit 4, or --allow-unsigned); a signed
        // one is always verified. With root keys the client is strict whatever this says.
        responseSignature: MODES.WHEN_PRESENT,
        ...(roots === undefined ? {} : { roots }),
        // One request: nothing of the pin file, and no latch kept after the command.
        vaultKeyStore: new MemoryVaultKeyStore(),
        // The command prints its own verdicts.
        logger: { warn: () => {} },
        onSecurityEvent: () => {},
        ...(io.timeoutMs === undefined ? {} : { timeoutMs: io.timeoutMs }),
        unsupported,
    });

    let page;
    try {
        page = await client.apiKeys.listApiKeySigningKeys();
    } catch (error) {
        if (error instanceof ResponseVerificationError && error.reason === 'missing' && lastHeaders !== null && !carriesSignature(lastHeaders)) {
            return {
                outcome: 'unread',
                fingerprint: key.fingerprint,
                status: error.status,
                requestId: null,
                keys: [],
                error: null,
                responseSignature: { signed: false },
            };
        }
        // A refusal with the API's own error code: what the API says about this key or these credentials.
        if (error instanceof ApiError && (error.status === 401 || error.status === 403) && typeof error.code === 'string') {
            return {
                outcome: 'refused',
                fingerprint: key.fingerprint,
                status: error.status,
                requestId: error.requestId,
                keys: [],
                error: { code: error.code, message: apiMessageOf(error) },
                responseSignature: { signed: error.signature === 'verified' },
            };
        }
        throw error;
    }

    if (!page || !Array.isArray(page.items)) {
        // A 2xx with one item instead of the list
        const requestId = page && page.meta ? page.meta.requestId : null;
        throw new keys.UnexpectedResponseError('the API answered 200 without a list of signing keys', { status: 200, requestId });
    }
    const listed = page.items.filter(item => item !== null && typeof item === 'object').map(item => ({
        fingerprint: String(item.fingerprint),
        algorithm: String(item.algorithm),
        status: String(item.status),
    }));
    const own = listed.find(item => item.fingerprint === key.fingerprint);
    let outcome = 'not_listed';
    if (own) {
        outcome = own.status === 'active' ? 'active' : 'inactive';
    }

    return {
        outcome,
        fingerprint: key.fingerprint,
        status: 200,
        requestId: page.meta.requestId,
        keys: listed,
        error: null,
        responseSignature: page.meta.signature === 'verified' ? { signed: true, rootId: page.meta.rootId } : { signed: false },
    };
}

async function runVerify(values, io) {
    const apiRoot = values.root === undefined ? keys.DEFAULT_API_ROOT : values.root;
    const url = keys.signingKeysUrl(apiRoot);
    const apiVersion = values['api-version'] === undefined ? keys.SIGNING_KEYS_API_VERSION : values['api-version'];
    if (!keys.isApiVersion(apiVersion)) {
        throw argumentError(`--api-version must be a date, YYYY-MM-DD, such as ${keys.SIGNING_KEYS_API_VERSION}`);
    }
    const roots = values['response-root-key'] && values['response-root-key'].length > 0 ? readRootKeys(values['response-root-key']) : undefined;
    // With root keys configured a response is expected to be signed, so an unsigned one is never accepted.
    const rootsConfigured = roots !== undefined || HAS_EMBEDDED_ROOTS;
    const allowUnsigned = values['allow-unsigned'] === true && !rootsConfigured;
    const key = readKeyArgument(values.key, 'private');
    const credentials = readCredentials(io.env);
    io.redact.push(credentials.apiKey, credentials.apiSecret, credentials.passphrase);
    if (values['allow-unsigned'] === true && rootsConfigured) {
        io.stderr(`vaultody: warning: --allow-unsigned is ignored: ${roots !== undefined ? '--response-root-key is given' : 'this build has response-signing root keys'}, `
            + 'so the response must be signed.\n');
    }

    const result = await checkRegisteredKey(key, credentials, { apiRoot, apiVersion, roots, io });
    const requestId = result.requestId ? `Request id: ${shown(result.requestId)}\n` : '';

    if (!result.responseSignature.signed) {
        if (!allowUnsigned) {
            io.stderr(`vaultody: ${UNSIGNED_VERDICT}\n`
                + `Either ${url.origin} does not sign responses yet, or something between you and Vaultody removed the signature `
                + 'and could have changed the answer too. Do not rely on it.\n'
                + `${rootsConfigured ? '' : 'While Vaultody does not sign responses yet, --allow-unsigned accepts an unsigned answer with a warning.\n'}`
                + `Unverified answer: ${describeOutcome(result, key)}${requestId}`);

            return EXIT.UNSIGNED;
        }
        io.stderr(`vaultody: warning: ${UNSIGNED_VERDICT} Accepted because of --allow-unsigned.\n`);
    }

    if (result.outcome === 'active') {
        io.stdout(`OK: ${key.fingerprint} (${key.algorithm}) is registered and active on this API key.\n`
            + describeResponseSignature(result, url.origin) + describeKeys(result));

        return EXIT.OK;
    }

    if (result.outcome === 'refused') {
        const hint = REFUSAL_HINTS[result.error.code];
        io.stderr(`vaultody: the API refused the request: ${shown(result.error.code)} (HTTP ${result.status})`
            + `${result.error.message ? `: ${shown(result.error.message)}` : ''}\n${hint ? `${hint}\n` : ''}${requestId}`
            + describeResponseSignature(result, url.origin));

        return EXIT.REFUSED;
    }

    const verdict = result.outcome === 'inactive'
        ? `${key.fingerprint} is on this API key but not active.`
        : `${key.fingerprint} is not a signing key of this API key. Register its public key in the dashboard; it counts once the owner approves it.`;
    io.stderr(`vaultody: ${verdict}\n${describeResponseSignature(result, url.origin)}${describeKeys(result)}${requestId}`);

    return EXIT.REFUSED;
}

/** What a pin holds, as the fingerprints the alarm shows: the type and the short hash of each xpub. */
const fingerprintsOf = pin => ({
    type: pin.type,
    ...Object.fromEntries(PIN_ALGORITHMS.map(algorithm => [algorithm, pin.keys[algorithm] === null ? null : xpubHash(pin.keys[algorithm])])),
});

function describeChange(vaultId, origin, file, before, after) {
    const row = (label, old, now) => {
        let note = '';
        if (old !== now) {
            if (old === null) {
                note = '  added';
            } else {
                note = now === null ? '  gone' : '  changed';
            }
        }

        return `  ${label.padEnd(8)}${String(old === null ? '-' : old).padEnd(19)}${String(now === null ? '-' : now).padEnd(19)}${note}`.trimEnd();
    };
    const lines = [
        `Vault ${shown(vaultId)} at ${origin} (pin file ${file}):`,
        `  ${''.padEnd(8)}${'pinned'.padEnd(19)}now`,
        row('type', before.type, after.type),
        ...PIN_ALGORITHMS.map(algorithm => row(algorithm, before[algorithm], after[algorithm])),
    ];

    return `${lines.join('\n')}\n`;
}

/**
 * Lists the vaults through the SDK's client into a fresh in-memory pin store, page by page, the vault's pinned type
 * first, until the vault shows up. Its pin there is what the API shows now; every page is verified first.
 *
 * @returns {Promise<{ pin: Object|null, withoutKeys: boolean, signed: boolean, rootId: string|null }|{ unread: true }|null>}
 *          null when neither list holds the vault; unread: an unsigned answer refused before it was read (root keys are
 *          configured)
 */
async function currentVaultKeys(vaultId, firstType, credentials, { apiRoot, roots, key, io }) {
    const unsupported = {};
    if (io.clock) {
        unsupported.clock = io.clock;
    }
    if (io.sleep) {
        unsupported.sleep = io.sleep;
    }
    // With root keys configured the client refuses an unsigned answer before reading it: one with no signature at
    // all is reported as unsigned (exit 4), as without root keys; part of a signature stripped is a failed check.
    let lastHeaders = null;
    unsupported.fetch = async (url, init) => {
        const response = await fetch(url, init);
        lastHeaders = response.headers;

        return response;
    };
    const fresh = new MemoryVaultKeyStore();
    const client = new Vaultody({
        apiKey: credentials.apiKey,
        apiSecret: credentials.apiSecret,
        passphrase: credentials.passphrase,
        baseUrl: apiRoot,
        ...(key ? { signer: keyObjectSigner(key) } : {}),
        // An unsigned answer is accepted, marked unsigned, and judged by the caller; a signed one is always verified.
        // With root keys the client is strict whatever this says.
        responseSignature: MODES.WHEN_PRESENT,
        ...(roots === undefined ? {} : { roots }),
        // A fresh store: what the API shows now is pinned there as on first sight, never compared with the file.
        vaultKeyStore: fresh,
        logger: { warn: () => {} },
        onSecurityEvent: () => {},
        ...(io.timeoutMs === undefined ? {} : { timeoutMs: io.timeoutMs }),
        unsupported,
    });

    for (const networkType of firstType === 'test' ? ['test', 'main'] : ['main', 'test']) {
        let page;
        try {
            page = await client.vaults.listVaults({ networkType });
        } catch (error) {
            if (error instanceof ResponseVerificationError && error.reason === 'missing' && lastHeaders !== null && !carriesSignature(lastHeaders)) {
                return { unread: true };
            }
            throw error;
        }
        while (page) {
            const result = (page.meta.vaultKeys || []).find(entry => entry.vaultId === vaultId);
            if (result) {
                const signed = page.meta.signature === 'verified';

                return {
                    pin: await fresh.get(client.origin, vaultId),
                    withoutKeys: result.outcome === 'not_verifiable',
                    signed,
                    rootId: signed ? page.meta.rootId || null : null,
                };
            }
            page = await page.nextPage();
        }
    }

    return null;
}

const EXPECT_FORMAT = 'type=<main|test>,ECDSA=<fingerprint|->,EDDSA=<fingerprint|->';

/**
 * --expect: the type and the fingerprints (as fingerprintsOf gives them, null for "-") the new pin must have.
 *
 * @returns {{ type: string, ECDSA: string|null, EDDSA: string|null }}
 * @throws {keys.UsageError}
 */
function readExpect(text) {
    const bad = why => new keys.UsageError(`--expect must be ${EXPECT_FORMAT}, as the run without --yes prints it: ${why}`);
    const fields = {};
    for (const part of text.split(',')) {
        const at = part.indexOf('=');
        const name = at < 0 ? part : part.slice(0, at);
        if (at < 0 || !['type', ...PIN_ALGORITHMS].includes(name)) {
            throw bad(`${shown(part)} is not type=, ECDSA= or EDDSA=`);
        }
        if (Object.prototype.hasOwnProperty.call(fields, name)) {
            throw bad(`${name} is given twice`);
        }
        fields[name] = part.slice(at + 1);
    }
    for (const name of ['type', ...PIN_ALGORITHMS]) {
        if (!Object.prototype.hasOwnProperty.call(fields, name)) {
            throw bad(`${name} is missing`);
        }
    }
    if (fields.type !== 'main' && fields.type !== 'test') {
        throw bad('type is main or test');
    }
    for (const algorithm of PIN_ALGORITHMS) {
        if (fields[algorithm] !== '-' && !/^[0-9a-f]{16}$/.test(fields[algorithm])) {
            throw bad(`${algorithm} is 16 lowercase hex characters, or - for none`);
        }
    }

    return { type: fields.type, ...Object.fromEntries(PIN_ALGORITHMS.map(algorithm => [algorithm, fields[algorithm] === '-' ? null : fields[algorithm]])) };
}

/** The --expect text of what a pin holds. */
const expectOf = fingerprints => [`type=${fingerprints.type}`, ...PIN_ALGORITHMS.map(algorithm => `${algorithm}=${fingerprints[algorithm] === null ? '-' : fingerprints[algorithm]}`)].join(',');

async function runAccept(values, io) {
    const vaultId = values['vault-id'];
    // The run that writes must name what it accepts: the answer of a second fetch is never pinned unseen.
    const expected = values.expect === undefined ? null : readExpect(values.expect);
    if (values.yes === true && expected === null) {
        throw new keys.UsageError(`--yes needs --expect ${EXPECT_FORMAT}: the type and fingerprints you confirmed with Vaultody. Run without --yes to see them.`);
    }
    if (expected !== null && values.yes !== true) {
        throw new keys.UsageError('--expect goes with --yes');
    }
    const apiRoot = values.root === undefined ? keys.DEFAULT_API_ROOT : values.root;
    let origin;
    try {
        origin = keys.signingKeysUrl(apiRoot).origin;
    } catch (e) {
        throw new keys.UsageError(`--root: ${e.message}`);
    }
    const file = values.file === undefined ? defaultVaultKeysFile(io.env) : values.file;
    if (!file) {
        throw new keys.UsageError('no pin file: pass --file, or set VAULTODY_VAULT_KEYS_FILE');
    }
    const roots = values['response-root-key'] && values['response-root-key'].length > 0 ? readRootKeys(values['response-root-key']) : undefined;
    const key = values.key === undefined ? null : readKeyArgument(values.key, 'private');
    const credentials = readCredentials(io.env);
    io.redact.push(credentials.apiKey, credentials.apiSecret, credentials.passphrase);

    const store = new FileVaultKeyStore({ file });
    const pinned = await store.get(origin, vaultId);
    if (!pinned) {
        io.stderr(`vaultody: ${file} has no pin for vault ${shown(vaultId)} at ${origin}; nothing to accept. The SDK pins a vault `
            + 'the first time it sees it.\n');

        return EXIT.REFUSED;
    }
    // A signed answer is required once roots are configured, or once this pin file saw a signed answer from this API.
    const latched = (await store.getResponseSignatureLatch(origin)) !== null;
    const rootsConfigured = roots !== undefined || HAS_EMBEDDED_ROOTS;
    const allowUnsigned = values['allow-unsigned'] === true && !rootsConfigured && !latched;
    if (values['allow-unsigned'] === true && !allowUnsigned) {
        io.stderr(`vaultody: warning: --allow-unsigned is ignored: ${latched ? `${file} has seen a signed answer from ${origin}` : 'response-signing root keys are configured'}, `
            + 'so the response must be signed.\n');
    }

    let found;
    try {
        found = await currentVaultKeys(vaultId, pinned.type, credentials, { apiRoot, roots, key, io });
    } catch (error) {
        if (error instanceof ApiError && (error.status === 401 || error.status === 403) && typeof error.code === 'string') {
            const hint = REFUSAL_HINTS[error.code];
            io.stderr(`vaultody: the API refused the request: ${shown(error.code)} (HTTP ${error.status})\n${hint ? `${hint}\n` : ''}`);

            return EXIT.REFUSED;
        }
        throw error;
    }
    if (!found) {
        io.stderr(`vaultody: vault ${shown(vaultId)} is in neither GET /vaults/main nor GET /vaults/test of this API key; nothing was changed.\n`);

        return EXIT.REFUSED;
    }
    if (found.unread) {
        io.stderr(`vaultody: ${UNSIGNED_VERDICT}\n`
            + `Either ${origin} does not sign responses yet, or something between you and Vaultody removed the signature. `
            + 'With response-signing root keys configured the answer is refused before it is read. Nothing was changed.\n');

        return EXIT.UNSIGNED;
    }
    if (found.withoutKeys || !found.pin) {
        io.stderr(`vaultody: vault ${shown(vaultId)} is listed without MPC keys (such as a SMART vault): there is nothing to pin, so nothing was changed.\n`);

        return EXIT.REFUSED;
    }

    const before = fingerprintsOf(pinned);
    const after = fingerprintsOf(found.pin);
    const table = describeChange(vaultId, origin, file, before, after);
    if (!found.signed && !allowUnsigned) {
        io.stderr(`vaultody: ${UNSIGNED_VERDICT}\n`
            + `Either ${origin} does not sign responses yet, or something between you and Vaultody removed the signature `
            + 'and could have changed the answer too. Nothing was changed.\n'
            + `${rootsConfigured || latched ? '' : 'While Vaultody does not sign responses yet, --allow-unsigned accepts an unsigned answer.\n'}`
            + `Unverified answer:\n${table}`);

        return EXIT.UNSIGNED;
    }
    const evidence = found.signed
        ? `The vault list was signed and verified${found.rootId ? ` (root ${shown(found.rootId)})` : ''}.\n`
        : `The vault list was not signed: the new pin is unverified until a signed answer shows the same keys. Accepted because of --allow-unsigned.\n`;

    if (PIN_ALGORITHMS.every(algorithm => before[algorithm] === after[algorithm]) && before.type === after.type) {
        io.stdout(`${table}${evidence}The pin already matches what the API shows; nothing to accept.\n`);

        return EXIT.OK;
    }
    io.stdout(`${table}${evidence}`);
    if (values.yes !== true) {
        io.stderr('vaultody: nothing was changed. Confirm the new fingerprints with Vaultody, then run this again with these options to re-pin '
            + `the vault to exactly what is shown:\n  --yes --expect ${expectOf(after)}\n`);

        return EXIT.REFUSED;
    }
    if (expectOf(after) !== expectOf(expected)) {
        io.stderr(`vaultody: the API shows ${expectOf(after)}, not the --expect ${expectOf(expected)}; nothing was changed. `
            + 'Confirm what the API shows now with Vaultody before you accept it.\n');

        return EXIT.REFUSED;
    }

    // The pin shown must still be the pin replaced: another process may have written the file meanwhile.
    const current = await store.get(origin, vaultId);
    if (!current || JSON.stringify(fingerprintsOf(current)) !== JSON.stringify(before)) {
        io.stderr(`vaultody: the pin of vault ${shown(vaultId)} changed in ${file} while this command ran; nothing was changed. Run it again.\n`);

        return EXIT.REFUSED;
    }
    const summary = ['type', ...PIN_ALGORITHMS].filter(field => before[field] !== after[field])
        .map(field => `${field} ${before[field] === null ? '-' : before[field]} -> ${after[field] === null ? '-' : after[field]}`).join(', ');
    await store.replace(origin, found.pin, `re-pinned with vaultody vault-keys accept: ${summary}`);
    io.stdout(`Re-pinned vault ${shown(vaultId)} as ${found.pin.status}.\n`);

    return EXIT.OK;
}

function describeError(error) {
    if (error instanceof keys.UsageError) {
        return { code: EXIT.USAGE, message: error.message };
    }
    if (error instanceof keys.SigningKeyError) {
        return { code: EXIT.USAGE, message: error.message };
    }
    if (error instanceof RootKeyError) {
        return { code: EXIT.USAGE, message: error.message };
    }
    if (error instanceof ConfigurationError) {
        return {
            code: EXIT.USAGE,
            message: error.code === 'no_root_keys'
                ? 'the response is signed, but this build has no response-signing root keys to check it with. '
                    + 'For a test environment, pass its root public key with --response-root-key <root.pem>.'
                : error.message,
        };
    }
    if (error instanceof VaultKeyStoreError) {
        return { code: EXIT.USAGE, message: `the pin file can't be used (${error.code}): ${error.message}` };
    }
    if (error instanceof ResponseVerificationError) {
        const detail = error.cause && error.cause.message ? ` ${error.cause.message}` : '';

        return { code: EXIT.REFUSED, message: `the response failed its signature check (${error.reason}); do not trust it.${detail}` };
    }
    if (error instanceof ApiError) {
        const what = error.status >= 200 && error.status <= 299
            ? `the API answered ${error.status} without the list asked for`
            : `the API answered ${error.status}${error.code ? ` (${error.code})` : ''}`;

        return { code: EXIT.UNEXPECTED, message: shown(`unexpected answer: ${what}${error.requestId ? `. Request id: ${error.requestId}` : ''}`) };
    }
    if (error instanceof keys.UnexpectedResponseError) {
        return { code: EXIT.UNEXPECTED, message: shown(`unexpected answer: ${error.message}${error.requestId ? `. Request id: ${error.requestId}` : ''}`) };
    }
    if (error instanceof TransportError) {
        const code = networkCodeOf(error);

        return { code: EXIT.UNEXPECTED, message: shown(`network error: ${error.message}${code ? ` (${code})` : ''}`) };
    }

    return { code: EXIT.UNEXPECTED, message: `unexpected error: ${error && error.message ? error.message : String(error)}` };
}

/** Removes any credential from text that is about to be printed: a last line of defence, never relied on. */
function redactWith(secrets) {
    return text => secrets.filter(secret => typeof secret === 'string' && secret.length >= 4)
        .reduce((out, secret) => out.split(secret).join('[redacted]'), text);
}

/** A clock (milliseconds) that starts at `now` (Unix seconds or a Date) and runs on from there; tests only. */
function clockFrom(now) {
    const start = now instanceof Date ? now.getTime() : now * 1000;
    const startedAt = Date.now();

    return () => start + (Date.now() - startedAt);
}

/**
 * Runs one command line.
 *
 * @param {string[]} argv the arguments after the program name
 * @param {Object} [io] where it reads and writes; the last three are for tests only
 * @param {Object} [io.env] the environment (process.env)
 * @param {function(string)} [io.stdout]
 * @param {function(string)} [io.stderr]
 * @param {number|Date} [io.now] the time `keys verify` signs its request and checks the response at (Unix seconds)
 * @param {function(number): Promise<void>} [io.sleep] how the client waits between retries
 * @param {number} [io.timeoutMs] the client's timeout per attempt
 * @returns {Promise<number>} the exit code
 */
async function main(argv, io = {}) {
    const secrets = [];
    const redact = redactWith(secrets);
    const write = sink => text => sink(redact(text));
    const context = {
        env: io.env || process.env,
        stdout: write(io.stdout || (text => process.stdout.write(text))),
        stderr: write(io.stderr || (text => process.stderr.write(text))),
        clock: io.now === undefined ? undefined : clockFrom(io.now),
        sleep: io.sleep,
        timeoutMs: io.timeoutMs,
        redact: secrets,
    };

    if (Number(process.versions.node.split('.')[0]) < 22) {
        context.stderr('vaultody: this command needs Node.js 22 or later.\n');

        return EXIT.UNEXPECTED;
    }

    const [group, name, ...rest] = argv;
    if (group === undefined) {
        context.stderr(MAIN_USAGE);

        return EXIT.USAGE;
    }
    if (group === '--help' || group === '-h' || group === 'help' || (Object.hasOwn(COMMAND_GROUPS, group) && (name === '--help' || name === '-h' || name === 'help'))) {
        context.stdout(MAIN_USAGE);

        return EXIT.OK;
    }
    if (group === '--version') {
        context.stdout(`${version}\n`);

        return EXIT.OK;
    }
    const commands = Object.hasOwn(COMMAND_GROUPS, group) ? COMMAND_GROUPS[group] : null;
    const command = commands && Object.hasOwn(commands, name) ? commands[name] : undefined;
    if (!command) {
        context.stderr(`vaultody: ${commands && name !== undefined ? 'unknown command' : 'expected "keys <command>" or "vault-keys accept"'}\n\n${MAIN_USAGE}`);

        return EXIT.USAGE;
    }

    try {
        const values = parseCommandArgs(command, rest);
        if (values.help) {
            context.stdout(command.usage);

            return EXIT.OK;
        }

        return await command.run(values, context);
    } catch (error) {
        const { code, message } = describeError(error);
        context.stderr(`vaultody: ${message}\n`);
        if (error.showHelp) {
            context.stderr(`Run "vaultody ${group} ${name} --help" for its options.\n`);
        }

        return code;
    }
}

module.exports = { main, EXIT, CREDENTIAL_ENV };

if (require.main === module) {
    main(process.argv.slice(2)).then(code => {
        process.exitCode = code;
    });
}
