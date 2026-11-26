<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Transport;

use Vaultody\Sdk\Envelope;
use Vaultody\Sdk\Exception\AddressVerificationError;
use Vaultody\Sdk\Exception\ApiError;
use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\ParameterError;
use Vaultody\Sdk\Exception\RequestOutcomeUnknownError;
use Vaultody\Sdk\Exception\ResponseVerificationError;
use Vaultody\Sdk\Exception\TransportError;
use Vaultody\Sdk\Exception\VaultKeyChangedError;
use Vaultody\Sdk\Exception\VaultKeyStoreError;
use Vaultody\Sdk\Exception\VaultodyError;
use Vaultody\Sdk\Http\CurlHttpClient;
use Vaultody\Sdk\Http\HttpClient;
use Vaultody\Sdk\Http\HttpRequest;
use Vaultody\Sdk\Http\HttpResponse;
use Vaultody\Sdk\Json;
use Vaultody\Sdk\Pagination;
use Vaultody\Sdk\RateLimiter;
use Vaultody\Sdk\RequestTarget;
use Vaultody\Sdk\Retry;
use Vaultody\Sdk\Signer\KeyFileSigner;
use Vaultody\Sdk\Signer\RequestSigner;
use Vaultody\Sdk\VaultKeys\FileVaultKeyStore;
use Vaultody\Sdk\VaultKeys\PinModel;
use Vaultody\Sdk\VaultKeys\VaultKeyStore;
use Vaultody\Sdk\Verify\Address\AddressVerificationError as DerivationError;
use Vaultody\Sdk\Verify\Address\AddressVerifier;
use Vaultody\Sdk\Verify\Address\Chains;
use Vaultody\Sdk\Verify\ConfigurationError as VerifyConfigurationError;
use Vaultody\Sdk\Verify\Keys;
use Vaultody\Sdk\Verify\ResponseSignatureError;
use Vaultody\Sdk\Verify\ResponseVerifier;
use Vaultody\Sdk\Verify\Roots;
use Vaultody\Sdk\Verify\SignatureFormatError;
use Vaultody\Sdk\Verify\SigningKey;
use Vaultody\Sdk\Verify\SigningKeyError;
use Vaultody\Sdk\Verify\UsageError;
use Vaultody\Sdk\SecurityEvents;
use Vaultody\Sdk\Version;

/**
 * The one pipeline every call goes through:
 *
 *  1. the params are checked against the operation and turned into the request target and the
 *     {context, data: {item}} body (UTF-8 JSON, at most 1 MiB);
 *  2. the rate limiter hands out a token (5 requests per second by default);
 *  3. the request is signed: HMAC v2 with a nonce, and the key-pair signature when a signer is set. A call gets
 *     a fresh nonce; a write keeps it on every retry (re-signed with a fresh timestamp, or resent as it was),
 *     except the one conflict retry after address_derivation_conflict or vault_accounts_creation_failed
 *     (nothing was executed), which gets a new one; a read gets a new one when re-signed (Retry);
 *  4. it is sent; the answer's body is read as raw bytes (at most 10 MiB). Before the first write of a client with
 *     response-signing roots, one signed read goes first (signedReadBeforeWrite), so a write is never sent to an
 *     origin whose answers can't be checked;
 *  5. the response signature is verified before anything in the body is read. Any answer that carries a signature,
 *     or part of one, latches the origin first, verified or not: unsigned answers are refused from then on. A
 *     failure raises a security event and ResponseVerificationError and is never retried; error answers are
 *     verified too, since a forged 409 or 429 could steer the retries;
 *  6. the envelope is read into a result or a typed error, and the retry rules decide (Retry);
 *  7. an answer listing vaults is compared with the xpub pins, and every address in an answer is checked
 *     against its vault's pinned xpub. Any alarm or mismatch refuses the whole answer.
 *
 * Security events go to the onSecurityEvent callable, each with exactly the fields SecurityEvents::EVENTS
 * lists (the same in every language, test-vectors/security-events-v1.json): unsigned_response_accepted (once
 * per client, then one warning through the logger), response_signature_latched, response_verification_failed,
 * vault_key_pinned, vault_key_verified, vault_key_changed, address_verification_failed. The callable is called
 * before the error is thrown, and an exception from it is ignored so it can never hide the error.
 *
 * @internal Not part of the SDK's API: call() and paginate() take any operation and skip the contract checks
 *           of the client methods (Vaultody\Sdk\Api\*), which are the only supported way to call the API.
 */
final class Transport
{
    public const DEFAULT_BASE_URL = 'https://rest.vaultody.com';
    public const MAX_REQUEST_BODY_BYTES = 1048576;
    /** How long a confirmation that the key pair is active counts before it is asked again. */
    public const KEY_PAIR_CONFIRMATION_SECONDS = 600;
    public const RESPONSE_SIGNATURE_MODES = ['required', 'when-present'];
    /**
     * The response-signature mode when none is given (responseSignature, VAULTODY_RESPONSE_SIGNATURE): 'when-present'
     * while production does not sign responses (release candidates), 'required' from the stable release on. A client
     * with response-signing roots is strict whatever this says. One of the two build defaults a stable release
     * changes: the release guard (scripts/release/guard.mjs) reads it from this line, refuses a commit where it differs
     * from Node's and Python's, and a stable release where it is still 'when-present'.
     */
    public const DEFAULT_RESPONSE_SIGNATURE = 'when-present';
    /**
     * Whether the API answers every address it derives with its derivation path (accountIndex, isChange,
     * addressIndex). false while those fields are hidden; the release that ships after they are public sets it to true
     * (the guard requires that of a stable release). It is the default of the option requireAddressPaths: with it on,
     * generateDepositAddress refuses an address of a vault with MPC keys that comes without its path.
     */
    public const ADDRESS_PATHS_PUBLIC = false;

    private const OPTIONS = [
        'apiKey', 'apiSecret', 'passphrase', 'baseUrl', 'signer', 'privateKeyFile', 'verifySignerSignatures',
        'responseSignature', 'roots', 'vaultKeysFile', 'vaultKeyStore', 'pinnedVaultKeys', 'requireAddressPaths', 'onSecurityEvent', 'logger',
        'maxRequestsPerSecond', 'timeoutSeconds', 'connectTimeoutSeconds', 'caBundle', 'httpClient', 'apiVersion', 'maxClockSkewSeconds',
        'clock', 'monotonic', 'sleep', 'random', 'embeddedRoots', 'sdkVersion',
    ];
    // A stable release: X.Y.Z, without -rc.N.
    private const STABLE_VERSION = '/^[0-9]+\.[0-9]+\.[0-9]+$/D';
    private const WHEN_PRESENT_IGNORED = '\'responseSignature\' => \'when-present\' is ignored: response-signing roots are configured, so every response must be signed';
    private const LOOPBACK_HOST = '/^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])$/D';
    private const BASE_PATH = '/^(?:\/[A-Za-z0-9._~-]+)*$/D';

    // The credentials are held so that no dump, cast, export, JSON or serialisation of this object shows them.
    private \SensitiveParameterValue $apiKey;
    private \SensitiveParameterValue $apiSecret;
    private \SensitiveParameterValue $passphrase;
    private string $origin;
    private string $basePath;
    private ?RequestSigner $signer = null;
    private ?SigningKey $signerPublicKey = null;
    private bool $verifySignerSignatures;
    /** The response-signature mode in force (responseSignatureConfig). */
    private string $mode;
    /** Whether response-signing roots are configured: then the mode is 'required' and a signed read precedes the first write. */
    private bool $rootsConfigured;
    /** @var list<\Vaultody\Sdk\Verify\Root>|null the roots a signature is checked with; null: the ones this build embeds */
    private ?array $roots;
    private bool $requireAddressPaths;
    private int $maxClockSkewSeconds;
    private ?VaultKeyStore $store = null;
    /**
     * Pins given in configuration (pinnedVaultKeys), by vault id: they count as verified, are compared with every
     * vault list like stored pins, are never written to the store and take the place of a stored pin of the same
     * vault. Held like the credentials, since an xpub reveals every address of its vault: no dump, export or
     * cast shows them.
     */
    private \SensitiveParameterValue $configuredPins;
    /** @var (callable(array<string, mixed>): void)|null */
    private $onSecurityEvent;
    /** An object with warning(string $message), such as a PSR-3 logger; null: error_log() */
    private ?object $logger = null;
    private HttpClient $http;
    private RateLimiter $limiter;
    private string $apiVersion;
    private string $userAgent;
    /** @var callable(): int */
    private $clock;
    /** @var callable(): float */
    private $monotonic;
    /** @var callable(int): void */
    private $sleepMs;
    /** @var callable(): float */
    private $random;

    private ?bool $latched = null;
    /** Whether the signed read before the first write was answered (signedReadBeforeWrite). */
    private bool $signedReadDone = false;
    private ?float $keyPairConfirmedAt = null;
    private bool $unsignedReported = false;
    /** @var array<string, true> vaults seen in a vault list without MPC keys (SMART, AUTOMATION) */
    private array $keylessVaults = [];
    private ?AddressVerifier $addressVerifier = null;

    /**
     * @param array<string, mixed> $options
     *  - apiKey, apiSecret, passphrase: the API key's credentials (required)
     *  - baseUrl: https://rest.vaultody.com by default; https only, plain http only to this machine
     *  - signer (RequestSigner) or privateKeyFile (path): the key pair registered on the API key, if any
     *  - verifySignerSignatures (true): check every key-pair signature against the public key before sending
     *  - responseSignature: 'when-present' or 'required'; when not given, VAULTODY_RESPONSE_SIGNATURE, else the build
     *    default (DEFAULT_RESPONSE_SIGNATURE). 'when-present' accepts a response with no signature headers until
     *    the first signed one from this API origin, then refuses unsigned ones for good (stored with the pins);
     *    'required' refuses unsigned responses from the start. A client with response-signing roots (the roots
     *    option, or the roots a stable release embeds) is always 'required': a 'when-present' given is then
     *    ignored, with one warning when the client is made
     *  - roots: response-signing root keys to trust instead of the embedded ones (test environments only). With
     *    them every response must be signed, and the first write is preceded by one signed read
     *  - vaultKeysFile (or VAULTODY_VAULT_KEYS_FILE) or vaultKeyStore: where vault xpub pins live. Required for
     *    every operation that returns addresses or vault keys: without it those fail with ConfigurationError
     *    before anything is sent
     *  - pinnedVaultKeys: vault xpubs you pin yourself, a list of ['vaultId' => ..., 'type' => 'main'|'test',
     *    'keys' => ['ECDSA' => xpub|null, 'EDDSA' => xpub|null]] for this API origin. Each counts as verified, is
     *    compared with every vault list like a stored pin (any difference is the alarm), is never written to the
     *    store and takes the place of a stored pin of the same vault. The store is still required.
     *  - requireAddressPaths (ADDRESS_PATHS_PUBLIC by default): refuse with path_missing an address that
     *    generateDepositAddress answers without its derivation path, for a vault with MPC keys on a chain this SDK
     *    derives
     *  - onSecurityEvent: callable(array $event): void
     *  - logger: an object with a warning(string $message) method (a PSR-3 LoggerInterface fits), for the
     *    warnings the client gives when it first accepts an unsigned response or ignores a 'when-present', and
     *    for security events when there is no onSecurityEvent; error_log() by default
     *  - maxRequestsPerSecond (5), timeoutSeconds (30), connectTimeoutSeconds (10), caBundle (a CA file)
     *  - httpClient: an HttpClient to send with instead of curl
     * @throws ConfigurationError
     */
    public function __construct(#[\SensitiveParameter] array $options)
    {
        foreach (array_keys($options) as $name) {
            if (!in_array($name, self::OPTIONS, true)) {
                throw new ConfigurationError(sprintf('unknown option %s', json_encode($name)));
            }
        }

        try {
            Keys::requireCredentials($options);
        } catch (UsageError $error) {
            throw new ConfigurationError($error->getMessage(), 0, $error);
        }
        $this->apiKey = new \SensitiveParameterValue($options['apiKey']);
        $this->apiSecret = new \SensitiveParameterValue($options['apiSecret']);
        $this->passphrase = new \SensitiveParameterValue($options['passphrase']);

        [$this->origin, $this->basePath] = self::readBaseUrl($options['baseUrl'] ?? self::DEFAULT_BASE_URL);

        $this->readSigner($options);
        $this->verifySignerSignatures = (bool) ($options['verifySignerSignatures'] ?? true);

        // Unsupported, for tests only: embeddedRoots stands for the roots this build embeds (in the form roots takes),
        // and sdkVersion for its version, the two the mode depends on.
        try {
            $roots = Roots::parse($options['roots'] ?? null);
            $embedded = isset($options['embeddedRoots']) ? (Roots::parse($options['embeddedRoots']) ?? []) : Roots::embedded();
        } catch (VerifyConfigurationError $error) {
            throw new ConfigurationError($error->getMessage(), 0, $error);
        }
        $this->roots = $roots ?? (isset($options['embeddedRoots']) ? $embedded : null);
        $version = $options['sdkVersion'] ?? Version::SDK_VERSION;
        if (!is_string($version)) {
            throw new ConfigurationError('sdkVersion must be a version string');
        }
        $option = $options['responseSignature'] ?? null;
        if ($option === null) {
            $fromEnvironment = getenv('VAULTODY_RESPONSE_SIGNATURE');
            $option = is_string($fromEnvironment) && $fromEnvironment !== '' ? $fromEnvironment : null;
        }
        if ($option !== null && !in_array($option, self::RESPONSE_SIGNATURE_MODES, true)) {
            throw new ConfigurationError('responseSignature must be "required" or "when-present"');
        }
        $this->rootsConfigured = self::rootsConfigured($roots !== null, $embedded !== [], $version);
        [$this->mode, $whenPresentIgnored] = self::responseSignatureConfig($option, $roots !== null, $embedded !== [], $version, self::DEFAULT_RESPONSE_SIGNATURE);
        $this->maxClockSkewSeconds = (int) ($options['maxClockSkewSeconds'] ?? ResponseVerifier::DEFAULT_MAX_CLOCK_SKEW_SECONDS);

        $requireAddressPaths = $options['requireAddressPaths'] ?? self::ADDRESS_PATHS_PUBLIC;
        if (!is_bool($requireAddressPaths)) {
            throw new ConfigurationError('requireAddressPaths must be true or false');
        }
        $this->requireAddressPaths = $requireAddressPaths;

        if (isset($options['vaultKeyStore'])) {
            if (!$options['vaultKeyStore'] instanceof VaultKeyStore) {
                throw new ConfigurationError('vaultKeyStore must be a VaultKeyStore');
            }
            $this->store = $options['vaultKeyStore'];
        } else {
            $file = $options['vaultKeysFile'] ?? (getenv('VAULTODY_VAULT_KEYS_FILE') ?: null);
            if ($file !== null) {
                if (!is_string($file)) {
                    throw new ConfigurationError('vaultKeysFile must be a file path');
                }
                $this->store = new FileVaultKeyStore($file);
            }
        }
        $this->configuredPins = new \SensitiveParameterValue(self::readPinnedVaultKeys($options['pinnedVaultKeys'] ?? null));

        if (isset($options['onSecurityEvent']) && !is_callable($options['onSecurityEvent'])) {
            throw new ConfigurationError('onSecurityEvent must be callable');
        }
        $this->onSecurityEvent = $options['onSecurityEvent'] ?? null;
        if (isset($options['logger'])) {
            if (!is_object($options['logger']) || !method_exists($options['logger'], 'warning')) {
                throw new ConfigurationError('logger must be an object with a warning(string $message) method, such as a PSR-3 logger');
            }
            $this->logger = $options['logger'];
        }
        if ($whenPresentIgnored) {
            $this->warn(self::WHEN_PRESENT_IGNORED);
        }

        $this->clock = $options['clock'] ?? static fn (): int => time();
        $this->monotonic = $options['monotonic'] ?? static fn (): float => hrtime(true) / 1e9;
        $this->sleepMs = $options['sleep'] ?? static function (int $ms): void {
            if ($ms > 0) {
                usleep($ms * 1000);
            }
        };
        $this->random = $options['random'] ?? static fn (): float => random_int(0, PHP_INT_MAX - 1) / PHP_INT_MAX;

        $perSecond = (float) ($options['maxRequestsPerSecond'] ?? 5);
        $this->limiter = new RateLimiter($perSecond, max(1.0, $perSecond), $this->monotonic, $this->sleepMs);

        if (isset($options['httpClient'])) {
            if (!$options['httpClient'] instanceof HttpClient) {
                throw new ConfigurationError('httpClient must be an HttpClient');
            }
            $this->http = $options['httpClient'];
        } else {
            $this->http = new CurlHttpClient(
                (int) round(1000 * (float) ($options['timeoutSeconds'] ?? 30)),
                (int) round(1000 * (float) ($options['connectTimeoutSeconds'] ?? 10)),
                $options['caBundle'] ?? null,
            );
        }

        // Pinned per release; overriding it is unsupported and exists for tests.
        $this->apiVersion = $options['apiVersion'] ?? Version::API_VERSION;
        if (!Keys::isApiVersion($this->apiVersion)) {
            throw new ConfigurationError('apiVersion must be a date, YYYY-MM-DD');
        }
        $this->userAgent = sprintf('vaultody-sdk-php/%s (php/%s; %s)', Version::SDK_VERSION, PHP_VERSION, PHP_OS_FAMILY);
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return [
            'origin' => $this->origin,
            'apiKey' => '[redacted]',
            'signer' => $this->signerPublicKey?->fingerprint,
            'responseSignature' => $this->mode,
            'vaultKeyStore' => $this->store === null ? null : get_class($this->store),
            // A count only: an xpub reveals every address of its vault.
            'pinnedVaultKeys' => count($this->configuredPins()),
        ];
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new \LogicException('the transport holds credentials and is not serialisable');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('the transport holds credentials and is not serialisable');
    }

    /** The API origin pins and the response-signature latch are kept under, such as https://rest.vaultody.com. */
    public function origin(): string
    {
        return $this->origin;
    }

    /** The response-signature mode in force: 'required' or 'when-present'. */
    public function responseSignature(): string
    {
        return $this->mode;
    }

    /**
     * The response-signature mode in force, and whether a 'when-present' that was given is ignored (the client then
     * warns once): test-vectors/response-mode-v1.json, config. Roots configured make it 'required'; otherwise the
     * option decides, else the build default.
     *
     * @internal
     * @param ?string $option the responseSignature option, else VAULTODY_RESPONSE_SIGNATURE; null when neither is given
     * @param bool $rootsOption whether the roots option is given
     * @param bool $embeddedRoots whether the build embeds at least one response-signing root
     * @param string $version the SDK version
     * @param string $buildDefault DEFAULT_RESPONSE_SIGNATURE
     * @return array{0: string, 1: bool}
     */
    public static function responseSignatureConfig(?string $option, bool $rootsOption, bool $embeddedRoots, string $version, string $buildDefault): array
    {
        if (self::rootsConfigured($rootsOption, $embeddedRoots, $version)) {
            return ['required', $option === 'when-present'];
        }

        return [$option ?? $buildDefault, false];
    }

    /**
     * Roots are configured when the roots option is given, or when a stable release embeds a root. A release
     * candidate that embeds one is not strict for that alone: it bridges to signing through the latch.
     */
    private static function rootsConfigured(bool $rootsOption, bool $embeddedRoots, string $version): bool
    {
        return $rootsOption || ($embeddedRoots && preg_match(self::STABLE_VERSION, $version) === 1);
    }

    /**
     * Makes one call: signed, verified, retried by the rules, checked.
     *
     * @param array<string, mixed> $params flat: path, query and body fields by name, and context
     * @throws VaultodyError
     */
    public function call(Operation $operation, array $params = []): Item|Page
    {
        [$target, $body] = $this->build($operation, $params);
        if (($operation->addresses !== null || $operation->vaultList) && $this->store === null) {
            throw new ConfigurationError(sprintf('%s returns vault addresses or keys, which are checked against pinned vault xpubs: '
                . 'set vaultKeysFile to a file path the PHP process can write (every PHP-FPM request is a new process, so the pins must '
                . 'outlive it), or pass a vaultKeyStore', $operation->operationId));
        }
        if ($operation->retry === 'write') {
            $this->signedReadBeforeWrite();
        }

        [$envelope, $verdict] = $this->execute($operation, $target, $body);

        $meta = new Meta($envelope['requestId'], $envelope['apiVersion'], $envelope['context'], $envelope['replayed'], $verdict['verified'] ? 'verified' : 'absent');
        $result = $envelope['kind'] === 'item'
            ? new Item($envelope['item'], $meta)
            : new Page(
                $envelope['items'],
                $envelope['paging'],
                $envelope['limit'],
                $envelope['hasMore'] ?? false,
                $envelope['startingAfter'] ?? null,
                $envelope['offset'] ?? null,
                $envelope['total'] ?? null,
                $meta,
            );

        if ($operation->vaultList) {
            if (!$result instanceof Page) {
                throw new ApiError(200, null, 'the vault list answered something that is not a list', $meta->requestId, $meta->apiVersion, $meta->replayed);
            }
            $result = self::withMeta($result, $result->meta->withVaultKeys($this->observeVaultList($result, $verdict, (string) ($params['networkType'] ?? ''))));
        }
        if ($operation->addresses !== null) {
            $checks = $this->checkAddresses($operation, $params, $result instanceof Item ? [$result->data] : $result->items);
            $result = self::withMeta($result, $result->meta->withAddressChecks($checks));
        }

        return $result;
    }

    private static function withMeta(Item|Page $result, Meta $meta): Item|Page
    {
        return $result instanceof Item
            ? new Item($result->data, $meta)
            : new Page($result->items, $result->paging, $result->limit, $result->hasMore, $result->startingAfter, $result->offset, $result->total, $meta);
    }

    /**
     * Every item of a list operation, page by page; each page is an ordinary call (signed, verified,
     * checked). The generator's getReturn() says why it stopped: end, empty_page or max_items.
     *
     * @param array<string, mixed> $params as for call(); limit sets the page size (the operation's maximum by default)
     * @return \Generator<int, mixed, mixed, string>
     */
    public function paginate(Operation $operation, array $params = [], ?int $maxItems = null): \Generator
    {
        if ($operation->paging === 'none') {
            throw new \InvalidArgumentException(sprintf('%s is not a list', $operation->operationId));
        }
        $limit = $params['limit'] ?? null;
        unset($params['startingAfter'], $params['offset'], $params['limit']);

        return Pagination::paginate([
            'paging' => $operation->paging,
            'cursorField' => $operation->cursorField,
            'limit' => is_int($limit) ? $limit : null,
            'maxLimit' => $operation->maxLimit,
            'maxItems' => $maxItems,
        ], function (array $request) use ($operation, $params): array {
            $page = $this->call($operation, array_merge($params, array_filter($request, static fn (mixed $value): bool => $value !== null)));
            if (!$page instanceof Page) {
                throw new ApiError(200, null, 'a list operation answered a single item', $page->meta->requestId, $page->meta->apiVersion, $page->meta->replayed);
            }

            return ['items' => $page->items, 'hasMore' => $page->hasMore, 'total' => $page->total];
        });
    }

    /**
     * Whether writes may be resent after a timeout: 'keypair' when the configured key pair was confirmed
     * active through the signed list of the API key's signing keys (then the gateway's replay protection
     * always refuses a duplicate), 'legacy' otherwise. Asked when a write needs it, at most every 10 minutes;
     * a long-running worker can call it once at start.
     */
    public function keyMode(): string
    {
        if ($this->signer === null || $this->signerPublicKey === null) {
            return 'legacy';
        }
        $now = ($this->monotonic)();
        if ($this->keyPairConfirmedAt !== null && $now - $this->keyPairConfirmedAt < self::KEY_PAIR_CONFIRMATION_SECONDS) {
            return 'keypair';
        }
        try {
            $page = $this->call(CoreOperations::listApiKeySigningKeys());
        } catch (VaultodyError) {
            return 'legacy';
        }
        // An unsigned answer could have been made up on the way, so only a verified one counts.
        if (!$page instanceof Page || $page->meta->signature !== 'verified') {
            return 'legacy';
        }
        foreach ($page->items as $item) {
            if (is_array($item) && ($item['fingerprint'] ?? null) === $this->signerPublicKey->fingerprint && ($item['status'] ?? null) === 'active') {
                $this->keyPairConfirmedAt = ($this->monotonic)();

                return 'keypair';
            }
        }

        return 'legacy';
    }

    /**
     * Before the first write, a client with response-signing roots makes one signed read (the API key's signing keys)
     * unless its origin is latched already. Against an origin that does not sign, or a signature stripped from the
     * start, the read is refused and the write is never sent, instead of running and coming back as an answer that
     * can't be trusted. Any answer that passes its check settles it for this client; a network failure leaves it
     * open, and the write goes ahead with its own answer checked as always.
     *
     * @throws ResponseVerificationError|ConfigurationError the read's answer can't be trusted
     */
    private function signedReadBeforeWrite(): void
    {
        if (!$this->rootsConfigured || $this->signedReadDone) {
            return;
        }
        if ($this->latched()) {
            $this->signedReadDone = true;

            return;
        }
        try {
            $this->call(CoreOperations::listApiKeySigningKeys());
            $this->signedReadDone = true;
        } catch (ApiError) {
            // An error answer that passed its signature check: the origin signs.
            $this->signedReadDone = true;
        } catch (TransportError) {
            // Not settled: the write's own answer is checked as always.
        }
    }

    /**
     * @param array<string, mixed> $options
     * @throws ConfigurationError
     */
    private function readSigner(#[\SensitiveParameter] array $options): void
    {
        $signer = $options['signer'] ?? null;
        if ($signer !== null && isset($options['privateKeyFile'])) {
            throw new ConfigurationError('give either signer or privateKeyFile, not both');
        }
        try {
            if (isset($options['privateKeyFile'])) {
                $signer = KeyFileSigner::fromFile((string) $options['privateKeyFile']);
            }
            if ($signer === null) {
                return;
            }
            if (!$signer instanceof RequestSigner) {
                throw new ConfigurationError('signer must be a RequestSigner');
            }
            $public = SigningKey::inspectPublicKey($signer->publicKeyPem());
        } catch (SigningKeyError|UsageError $error) {
            throw new ConfigurationError('the signer\'s key is not usable: ' . $error->getMessage(), 0, $error);
        }
        if ($public->algorithm !== $signer->algorithm()) {
            throw new ConfigurationError(sprintf('the signer says %s, but its public key is %s', $signer->algorithm(), $public->algorithm));
        }
        $this->signer = $signer;
        $this->signerPublicKey = $public;
    }

    /** @return array<string, array{vaultId: string, type: string, keys: array{ECDSA: ?string, EDDSA: ?string}, status: string}> */
    private function configuredPins(): array
    {
        return $this->configuredPins->getValue();
    }

    /**
     * Reads pinnedVaultKeys: a list of ['vaultId', 'type', 'keys' => ['ECDSA', 'EDDSA']] with exactly these keys,
     * at least one xpub each and no vault twice. The messages name the entry, never an xpub.
     *
     * @return array<string, array{vaultId: string, type: string, keys: array{ECDSA: ?string, EDDSA: ?string}, status: string}>
     * @throws ConfigurationError
     */
    private static function readPinnedVaultKeys(#[\SensitiveParameter] mixed $entries): array
    {
        if ($entries === null) {
            return [];
        }
        if (!is_array($entries) || !array_is_list($entries)) {
            throw new ConfigurationError('pinnedVaultKeys must be a list of [\'vaultId\' => ..., \'type\' => \'main\'|\'test\', \'keys\' => [\'ECDSA\' => xpub|null, \'EDDSA\' => xpub|null]]');
        }
        $pins = [];
        foreach ($entries as $index => $entry) {
            $where = sprintf('pinnedVaultKeys[%d]', $index);
            if (!is_array($entry) || !self::hasExactly($entry, ['vaultId', 'type', 'keys'])) {
                throw new ConfigurationError(sprintf('%s must have exactly vaultId, type and keys', $where));
            }
            if (!is_string($entry['vaultId']) || $entry['vaultId'] === '') {
                throw new ConfigurationError(sprintf('%s: vaultId must be a non-empty string', $where));
            }
            if (!in_array($entry['type'], ['main', 'test'], true)) {
                throw new ConfigurationError(sprintf('%s: type must be "main" or "test"', $where));
            }
            $keys = $entry['keys'];
            if (!is_array($keys) || !self::hasExactly($keys, PinModel::ALGORITHMS)) {
                throw new ConfigurationError(sprintf('%s: keys must have exactly ECDSA and EDDSA, each an xpub or null', $where));
            }
            foreach (PinModel::ALGORITHMS as $algorithm) {
                if ($keys[$algorithm] !== null && (!is_string($keys[$algorithm]) || $keys[$algorithm] === '')) {
                    throw new ConfigurationError(sprintf('%s: keys.%s must be an xpub (a non-empty string) or null', $where, $algorithm));
                }
            }
            if (!PinModel::hasKeys($keys)) {
                throw new ConfigurationError(sprintf('%s: keys must hold at least one xpub', $where));
            }
            if (isset($pins[$entry['vaultId']])) {
                throw new ConfigurationError(sprintf('%s: vault %s is pinned twice', $where, $entry['vaultId']));
            }
            $pins[$entry['vaultId']] = [
                'vaultId' => $entry['vaultId'],
                'type' => $entry['type'],
                'keys' => ['ECDSA' => $keys['ECDSA'], 'EDDSA' => $keys['EDDSA']],
                'status' => PinModel::VERIFIED,
            ];
        }

        return $pins;
    }

    /**
     * @param array<mixed> $value
     * @param list<string> $keys
     */
    private static function hasExactly(array $value, array $keys): bool
    {
        if (count($value) !== count($keys)) {
            return false;
        }
        foreach ($keys as $key) {
            if (!array_key_exists($key, $value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array{string, string} the origin and the base path
     * @throws ConfigurationError
     */
    private static function readBaseUrl(mixed $baseUrl): array
    {
        $parts = is_string($baseUrl) ? parse_url($baseUrl) : false;
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new ConfigurationError('baseUrl must be an absolute URL such as https://rest.vaultody.com');
        }
        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        if ($scheme !== 'https' && !($scheme === 'http' && preg_match(self::LOOPBACK_HOST, $host) === 1)) {
            throw new ConfigurationError('baseUrl must be an https URL: requests carry the passphrase, so plain http is allowed only to this machine');
        }
        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) || str_contains($baseUrl, '?') || str_contains($baseUrl, '#')) {
            throw new ConfigurationError('baseUrl must not hold a user name, password, query or fragment');
        }
        $path = rtrim($parts['path'] ?? '', '/');
        if (preg_match(self::BASE_PATH, $path) !== 1) {
            throw new ConfigurationError('baseUrl must have a plain path, such as /v2, or none');
        }

        // The origin as Node's URL writes it: no port when it is the scheme's default.
        $port = $parts['port'] ?? null;
        if (($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80)) {
            $port = null;
        }

        return [$scheme . '://' . $host . ($port !== null ? ':' . $port : ''), $path];
    }

    /**
     * @param array<string, mixed> $params
     * @return array{string, string} the request target (path and query, without the base path) and the body
     * @throws ParameterError
     */
    private function build(Operation $operation, array $params): array
    {
        $context = $params['context'] ?? null;
        if ($context !== null && !is_string($context)) {
            throw new ParameterError('invalid_param', 'context must be a string');
        }
        $pathValues = [];
        $item = [];
        foreach ($params as $name => $value) {
            if ($name === 'context' || in_array($name, $operation->queryParams, true)) {
                continue;
            }
            if (in_array($name, $operation->pathParams, true)) {
                $pathValues[$name] = $value;
            } elseif ($operation->hasBody) {
                $item[$name] = $value;
            } else {
                throw new ParameterError('unknown_param', sprintf('%s takes no parameter %s', $operation->operationId, json_encode($name)));
            }
        }
        $query = [];
        foreach ($operation->queryParams as $name) {
            if ($name !== 'context') {
                $query[] = [$name, $params[$name] ?? null];
            }
        }
        if (!$operation->hasBody) {
            $query[] = ['context', $context];
        }
        $target = RequestTarget::build($operation->path, $pathValues, $query);

        $body = '';
        if ($operation->hasBody) {
            $envelope = ['data' => ['item' => $item === [] ? new \stdClass() : $item]];
            if ($context !== null) {
                $envelope = ['context' => $context] + $envelope;
            }
            try {
                $body = Json::encode($envelope);
            } catch (\JsonException $error) {
                throw new ParameterError('invalid_body', 'the parameters can\'t be written as JSON: ' . $error->getMessage());
            }
            if (strlen($body) > self::MAX_REQUEST_BODY_BYTES) {
                throw new ParameterError('body_too_large', sprintf('the request body is larger than %d bytes', self::MAX_REQUEST_BODY_BYTES));
            }
        }

        return [$target, $body];
    }

    /**
     * Signs one request: the HMAC v2 headers with a fresh timestamp and $nonce (the call's, when a write is
     * re-signed) or a fresh nonce, and the key-pair headers when a signer is set.
     *
     * @return array<string, string>
     * @throws ConfigurationError the signer failed or signed with another key
     */
    private function sign(Operation $operation, string $target, string $body, ?string $nonce = null): array
    {
        $queryAt = strpos($target, '?');
        $fields = Keys::requestFields($this->passphrase->getValue(), [
            'method' => $operation->method,
            'path' => $this->basePath . ($queryAt === false ? $target : substr($target, 0, $queryAt)),
            'query' => $queryAt === false ? '' : substr($target, $queryAt + 1),
            'body' => $body,
            'apiVersion' => $this->apiVersion,
            'timestamp' => (string) ($this->clock)(),
            'nonce' => $nonce,
        ]);
        $headers = Keys::signHmacV2Request(['apiKey' => $this->apiKey->getValue(), 'apiSecret' => $this->apiSecret->getValue(), 'passphrase' => $this->passphrase->getValue()], $fields);

        if ($this->signer !== null && $this->signerPublicKey !== null) {
            // The key-pair string carries the x-api-key the request is sent with.
            try {
                $message = Keys::keypairRequestMessage(['apiKey' => $this->apiKey->getValue()] + $fields);
            } catch (UsageError $error) {
                throw new ConfigurationError($error->getMessage(), 0, $error);
            }
            $headers[Keys::HEADERS['keypairSign']] = base64_encode($this->keypairSignature($message));
            $headers[Keys::HEADERS['keypairId']] = $this->signerPublicKey->fingerprint;
        }

        $headers['user-agent'] = $this->userAgent;
        $headers['accept'] = 'application/json';
        if ($operation->hasBody) {
            $headers['content-type'] = 'application/json';
        }

        return $headers;
    }

    /**
     * The signer's signature over a key-pair request message, in the form the gateway takes, checked against the
     * signer's public key before it is sent (unless verifySignerSignatures is off).
     *
     * @throws ConfigurationError the signer failed, answered in an unknown form, or signed with another key
     */
    private function keypairSignature(string $message): string
    {
        if ($this->signer === null || $this->signerPublicKey === null) {
            throw new ConfigurationError('no signer');
        }
        try {
            $signature = $this->normaliseSignature((string) $this->signer->sign($message));
        } catch (SignatureFormatError $error) {
            throw new ConfigurationError('the signer returned a signature in an unknown form: ' . $error->getMessage(), 0, $error);
        }
        if ($this->verifySignerSignatures && !$this->signerPublicKey->verifyBytes($message, $signature)) {
            throw new ConfigurationError(sprintf('the signer\'s signature does not verify with its public key %s; is it signing with another key?', $this->signerPublicKey->fingerprint));
        }

        return $signature;
    }

    /**
     * Ed25519: exactly 64 bytes. P-256: DER as the gateway requires; a signature of exactly 64 bytes is an IEEE
     * P1363 r || s, as Web Crypto, Azure Key Vault and some KMS APIs return it, and is converted, even when it starts
     * like DER: a DER signature of a P-256 key is 70 to 72 bytes in practice. Any other length is taken as DER.
     */
    private function normaliseSignature(string $signature): string
    {
        if ($this->signerPublicKey?->algorithm === SigningKey::ED25519) {
            if (strlen($signature) !== 64) {
                throw new SignatureFormatError(SignatureFormatError::INVALID_LENGTH, 'an Ed25519 signature is 64 bytes');
            }

            return $signature;
        }

        return strlen($signature) === 64 ? Keys::p1363ToDer($signature) : $signature;
    }

    /**
     * Sends a call until the retry rules say to stop.
     *
     * @return array{array<string, mixed>, array<string, mixed>} the envelope and the signature verdict
     * @throws VaultodyError
     */
    private function execute(Operation $operation, string $target, string $body): array
    {
        $isWrite = $operation->retry === 'write';
        $startedAt = ($this->monotonic)();
        $attempt = 0;
        $headers = null;
        // Kept on every retry of a write; null: a new one (the first signing, a read re-signed, or the one conflict
        // retry, after which the new nonce is the one kept).
        $keepNonce = null;
        $signedAt = $startedAt;
        $firstSentAt = null;
        $resends = 0;
        $mayHaveRun = false;
        $conflictRetried = false;

        while (true) {
            $attempt++;
            if ($headers === null) {
                $headers = $this->sign($operation, $target, $body, $keepNonce);
                $signedAt = ($this->monotonic)();
                $firstSentAt = null;
                $resends = 0;
            }
            $this->limiter->take();
            $firstSentAt ??= ($this->monotonic)();

            $transportError = null;
            $apiError = null;
            $envelope = null;
            $verdict = null;
            try {
                $response = $this->http->send(new HttpRequest($operation->method, $this->origin . $this->basePath . $target, $headers, $body, $isWrite));
            } catch (TransportError $error) {
                $response = null;
                $transportError = $error;
            }

            if ($response === null) {
                $outcome = ['type' => $transportError !== null && $transportError->sent === false ? 'not_sent' : 'sent_unknown'];
            } else {
                // Verified before anything in the body is read; a failure throws and is never retried.
                $verdict = $this->verifyResponse($operation, $target, $body, $headers, $response);
                try {
                    $envelope = Envelope::read($response->status, $response->headers, $response->body);
                } catch (ApiError $error) {
                    $apiError = $error;
                }
                $outcome = [
                    'type' => 'response',
                    'status' => $response->status,
                    'code' => $apiError?->code,
                    'replayed' => Envelope::replayed($response->headers),
                    'retryAfterSeconds' => self::retryAfter($response),
                ];
            }

            $thisMayHaveRun = $outcome['type'] === 'sent_unknown' || ($outcome['type'] === 'response' && $outcome['status'] >= 500 && $outcome['status'] <= 599);
            $keyMode = $isWrite && $thisMayHaveRun ? $this->keyMode() : 'legacy';
            $now = ($this->monotonic)();
            $decision = Retry::decide([
                'operation' => $operation->retry,
                'keyMode' => $keyMode,
                'attempt' => $attempt,
                'elapsedMs' => ($now - $startedAt) * 1000,
                'signedAgeMs' => ($now - $signedAt) * 1000,
                'sinceFirstSendMs' => ($now - $firstSentAt) * 1000,
                'resends' => $resends,
                'mayHaveRun' => $mayHaveRun,
                'conflictRetried' => $conflictRetried,
                'random' => ($this->random)(),
                'outcome' => $outcome,
            ]);

            switch ($decision['action']) {
                case 'return':
                    if ($apiError !== null) {
                        throw $apiError;
                    }
                    if ($envelope === null || $verdict === null) {
                        throw $transportError ?? new TransportError('no answer', 'unknown');
                    }

                    return [$envelope, $verdict];
                case 'fail':
                    throw $transportError ?? $apiError ?? new TransportError('no answer', 'unknown');
                case 'outcome_unknown':
                    throw new RequestOutcomeUnknownError(
                        $decision['inProgress'],
                        $headers[Keys::HEADERS['nonce']],
                        $headers[Keys::HEADERS['timestamp']],
                        $apiError?->requestId ?? ($envelope['requestId'] ?? null),
                        $apiError ?? $transportError,
                    );
                default:
                    if (in_array($outcome['code'] ?? null, Retry::CONFLICT_RETRY_CODES, true)) {
                        $conflictRetried = true;
                    }
                    ($this->sleepMs)($decision['delayMs']);
                    if ($decision['mode'] === 'resign') {
                        $keepNonce = $decision['nonce'] === 'same' ? $headers[Keys::HEADERS['nonce']] : null;
                        $headers = null;
                    } else {
                        $resends++;
                    }
            }
            $mayHaveRun = $mayHaveRun || $thisMayHaveRun;
        }
    }

    private static function retryAfter(HttpResponse $response): ?int
    {
        $value = $response->header('retry-after');

        return $value !== null && preg_match('/^[0-9]{1,5}$/D', $value) === 1 ? (int) $value : null;
    }

    /**
     * @param array<string, string> $headers the headers the request was sent with
     * @return array{verified: true, keyId: string, rootId: string, timestamp: int}|array{verified: false, reason: string}
     * @throws ResponseVerificationError|ConfigurationError
     */
    private function verifyResponse(Operation $operation, string $target, string $body, array $headers, HttpResponse $response): array
    {
        $now = (int) ($this->clock)();
        // The latch is read in every mode: a strict client latches too, so a release candidate sharing its store is
        // strict as well.
        $strict = $this->latched() || $this->mode === 'required';
        $verdict = null;
        $failure = null;
        try {
            $verdict = ResponseVerifier::verify(
                [
                    'method' => $operation->method,
                    'url' => $this->basePath . $target,
                    'body' => $body,
                    'apiSign' => $headers[Keys::HEADERS['sign']],
                    'keypairSign' => $headers[Keys::HEADERS['keypairSign']] ?? '',
                ],
                ['status' => $response->status, 'headers' => $response->headers, 'body' => $response->body],
                ['requireResponseSignature' => $strict, 'roots' => $this->roots, 'now' => $now, 'maxClockSkewSeconds' => $this->maxClockSkewSeconds],
            );
        } catch (ResponseSignatureError|VerifyConfigurationError $error) {
            $failure = $error;
        }

        // An answer that carries a signature, or part of one, latches the origin before anything is thrown, whether it
        // verifies or not: whoever strips the signature once the gateway signs can't keep this client lenient. The
        // latch names the root only when the answer verified.
        if (ResponseVerifier::isSigned($response->headers) && !$this->latched()) {
            $this->latch($verdict !== null && $verdict['verified'] ? $verdict['rootId'] : null, $now);
        }

        if ($failure instanceof ResponseSignatureError) {
            $this->securityEvent(['type' => 'response_verification_failed', 'origin' => $this->origin, 'operationId' => $operation->operationId, 'status' => $response->status, 'reason' => $failure->reason]);

            throw new ResponseVerificationError($failure->reason, $failure->getMessage(), $response->status, $failure);
        }
        if ($failure !== null) {
            // A setup error (no root keys to check a signed answer with), not a refused answer: no event.
            throw new ConfigurationError($failure->getMessage(), 0, $failure);
        }

        if (!$verdict['verified'] && !$this->unsignedReported) {
            $this->unsignedReported = true;
            $this->securityEvent(['type' => 'unsigned_response_accepted', 'origin' => $this->origin, 'operationId' => $operation->operationId]);
            $this->warn(sprintf('Vaultody API responses from %s are not signed: accepted unverified until the first signed one, after which this '
                . 'client refuses unsigned responses from this origin (\'responseSignature\' => \'required\' refuses them now)', $this->origin));
        }

        return $verdict;
    }

    /** Whether a signed response came from this origin before: then unsigned ones are refused. */
    private function latched(): bool
    {
        return $this->latched ??= $this->store !== null && $this->store->read($this->origin)['responseSignature'] !== null;
    }

    /**
     * Stores the latch for this origin (once; it is never cleared): when, and the root that verified the response,
     * or null when it did not verify.
     */
    private function latch(?string $rootId, int $latchedAt): void
    {
        $this->latched = true;
        if ($this->store === null || $this->store->read($this->origin)['responseSignature'] !== null) {
            return;
        }
        $latched = false;
        $stored = $this->store->update($this->origin, static function (array $state) use ($rootId, $latchedAt, &$latched): array {
            if ($state['responseSignature'] === null) {
                $state['responseSignature'] = ['latchedAt' => $latchedAt, 'rootId' => $rootId];
                $latched = true;
            }

            return $state;
        });
        if ($latched) {
            $latch = $stored['responseSignature'] ?? ['latchedAt' => $latchedAt, 'rootId' => $rootId];
            $this->securityEvent(['type' => 'response_signature_latched', 'origin' => $this->origin, 'rootId' => $latch['rootId'], 'latchedAt' => $latch['latchedAt']]);
        }
    }

    /** One warning line, through the logger option, else error_log(); a failing logger never breaks a call. */
    private function warn(string $message): void
    {
        try {
            if ($this->logger !== null) {
                $this->logger->warning($message);
            } else {
                error_log('vaultody-sdk: ' . $message);
            }
        } catch (\Throwable) {
            // a logger must not break a call
        }
    }

    /**
     * Compares one answer of the vault list with the pins, stores new and upgraded pins, and says per vault
     * what became of it.
     *
     * @param array<string, mixed> $verdict
     * @param string $networkType the vault type the list was asked for (main, test)
     * @return list<array{vaultId: string, status: string, outcome: string}> one per vault, in answer order
     */
    private function observeVaultList(Page $page, array $verdict, string $networkType): array
    {
        try {
            // Pins hold the type as Node does: lowercase (the API answers main / test).
            $vaults = array_map(static fn (array $vault): array => is_string($vault['type']) ? ['type' => strtolower($vault['type'])] + $vault : $vault, PinModel::readVaultList($page->items));
        } catch (\UnexpectedValueException $error) {
            throw new ApiError(200, null, 'the vault list can\'t be read: ' . $error->getMessage(), $page->meta->requestId, $page->meta->apiVersion, $page->meta->replayed, null, false, $error);
        }
        // A vault listed under the other type is refused, as in Node and Python: its pin would carry the wrong
        // type, and so would every address derived from it.
        $route = strtolower($networkType);
        foreach ($vaults as $vault) {
            if ($vault['type'] !== $route) {
                throw new ApiError(200, null, sprintf('vault %s is listed under %s vaults with type %s', $vault['vaultId'], $route, json_encode($vault['type'])), $page->meta->requestId, $page->meta->apiVersion, $page->meta->replayed);
            }
        }
        $evidence = $verdict['verified']
            ? ['signed' => true, 'rootId' => $verdict['rootId'], 'timestamp' => $verdict['timestamp'], 'now' => ($this->clock)()]
            : ['signed' => false, 'now' => ($this->clock)()];

        $store = $this->store;
        if ($store === null) {
            throw new ConfigurationError('no vault key store');
        }
        // A configured pin takes the place of a stored pin of the same vault. It counts as verified, so it is never
        // upgraded and never among the changes: nothing is written for it.
        $configured = $this->configuredPins();
        $observe = static function (array $state) use ($vaults, $evidence, $configured, &$result): array {
            $result = PinModel::observeVaults($configured + $state['vaults'], $vaults, $evidence);
            foreach ($result['changes'] as $pin) {
                $state['vaults'][$pin['vaultId']] = $pin;
            }

            return $state;
        };
        try {
            $result = null;
            $stored = $store->read($this->origin);
            $observe($stored);
            if ($result !== null && $result['changes'] !== []) {
                // Again under the store's lock, against what other processes may have pinned meanwhile.
                $stored = $store->update($this->origin, $observe);
                foreach ($result['changes'] as $pin) {
                    if (($stored['vaults'][$pin['vaultId']] ?? null) !== $pin) {
                        // The store did not keep what was just written (a custom store another writer changed
                        // meanwhile): nothing is returned, as in Node and Python; calling again reads afresh.
                        throw new VaultKeyStoreError('store_conflict', sprintf('the pin of vault %s changed in the store while this client wrote it; call again', $pin['vaultId']));
                    }
                }
            }
        } catch (VaultKeyChangedError $error) {
            $this->securityEvent(['type' => 'vault_key_changed', 'origin' => $this->origin, 'alarms' => $error->alarms]);

            throw $error;
        }

        $vaultKeys = [];
        foreach ($result['outcomes'] ?? [] as $outcome) {
            if ($outcome['outcome'] === PinModel::NOT_VERIFIABLE) {
                $this->keylessVaults[$outcome['vaultId']] = true;
            } elseif ($outcome['outcome'] === PinModel::PINNED) {
                $this->securityEvent(['type' => 'vault_key_pinned', 'origin' => $this->origin, 'vaultId' => $outcome['vaultId'], 'status' => $evidence['signed'] ? PinModel::VERIFIED : PinModel::UNVERIFIED]);
            } elseif ($outcome['outcome'] === PinModel::UPGRADED) {
                $this->securityEvent(['type' => 'vault_key_verified', 'origin' => $this->origin, 'vaultId' => $outcome['vaultId'], 'status' => PinModel::VERIFIED]);
            }
            $status = $outcome['outcome'] === PinModel::NOT_VERIFIABLE
                ? PinModel::NOT_VERIFIABLE
                : (($configured[$outcome['vaultId']] ?? $stored['vaults'][$outcome['vaultId']] ?? [])['status'] ?? PinModel::UNVERIFIED);
            $vaultKeys[] = ['vaultId' => $outcome['vaultId'], 'status' => $status, 'outcome' => $outcome['outcome']];
        }

        return $vaultKeys;
    }

    /**
     * Checks every address of an answer against its vault's pinned xpub. Any failure refuses the whole
     * answer.
     *
     * The security event address_verification_failed comes before any AddressVerificationError, as in Node and
     * Python.
     *
     * @param array<string, mixed> $params the call's params
     * @param list<mixed> $items
     * @return list<array{vaultId: string, address: string, status: string}> one per address, in answer order
     * @throws AddressVerificationError|VaultKeyChangedError|ConfigurationError
     */
    private function checkAddresses(Operation $operation, array $params, array $items): array
    {
        $vaultId = $params['vaultId'] ?? null;
        try {
            if (!is_string($vaultId) || $vaultId === '') {
                throw new AddressVerificationError('unknown_vault', sprintf('%s names no vault to check its addresses against', $operation->operationId));
            }

            $checks = [];
            foreach ($items as $item) {
                if (!is_array($item) || !is_string($item['address'] ?? null) || $item['address'] === '') {
                    throw new AddressVerificationError('invalid', 'an item of the answer has no address');
                }
                if ($operation->addresses === Operation::ADDRESSES_ADD_ASSET && isset($params['address']) && $item['address'] !== $params['address']) {
                    throw new AddressVerificationError('mismatch', 'the answer names another address than the one sent');
                }
                $checks[] = ['vaultId' => $vaultId, 'address' => $item['address'], 'status' => $this->checkAddress($operation, $vaultId, $params, $item)];
            }

            return $checks;
        } catch (AddressVerificationError $error) {
            $this->securityEvent(['type' => 'address_verification_failed', 'origin' => $this->origin, 'operationId' => $operation->operationId, 'vaultId' => is_string($vaultId) ? $vaultId : null, 'code' => $error->code]);

            throw $error;
        }
    }

    /**
     * @param array<string, mixed> $params
     * @param array<string, mixed> $item
     */
    private function checkAddress(Operation $operation, string $vaultId, array $params, array $item): string
    {
        // What the call asked for (the path of generateDepositAddress, the blockchain filter of a list): an item
        // that names another chain or network is refused, as in Node and Python.
        $requestedBlockchain = $operation->addresses === Operation::ADDRESSES_ADD_ASSET ? null : ($params['blockchain'] ?? null);
        $requestedNetwork = $operation->addresses === Operation::ADDRESSES_IN_PATH ? ($params['network'] ?? null) : null;
        $blockchain = $item['blockchain'] ?? $requestedBlockchain;
        $network = $item['network'] ?? $requestedNetwork;
        // Which vault list to look in first: the requested network's, else the item's (as Node and Python do).
        $hintNetwork = $requestedNetwork ?? $network;
        $typeHint = is_string($hintNetwork) ? ($hintNetwork === 'mainnet' ? 'main' : 'test') : null;

        // An address without its derivation path (an old row, a SMART vault) can't be checked. Once the API gives the
        // path of every address it derives (requireAddressPaths), a new deposit address without one, of a vault with
        // MPC keys on a chain this SDK derives, is refused instead: its path was left out on the way.
        if (!isset($item['accountIndex'], $item['isChange'], $item['addressIndex'])) {
            if (!PinModel::addressPathRequired($this->requireAddressPaths, $operation->operationId, is_string($blockchain) && Chains::describe($blockchain) !== null)) {
                return PinModel::NOT_VERIFIABLE;
            }
            $pin = $this->pinOf($vaultId, $typeHint);

            return PinModel::addressCheckStatus(['pin' => $pin, 'vaultHasKeys' => $pin !== null, 'pathFields' => false, 'derivation' => null, 'pathRequired' => true]);
        }

        $pin = $this->pinOf($vaultId, $typeHint);
        if ($pin === null) {
            return PinModel::NOT_VERIFIABLE;
        }
        if ($requestedBlockchain !== null && isset($item['blockchain']) && $item['blockchain'] !== $requestedBlockchain) {
            throw new AddressVerificationError('mismatch', sprintf('an address is on %s, but %s was asked for', json_encode($item['blockchain']), json_encode($requestedBlockchain)));
        }
        if ($requestedNetwork !== null && isset($item['network']) && $item['network'] !== $requestedNetwork) {
            throw new AddressVerificationError('network_mismatch', sprintf('an address is on %s, but %s was asked for', json_encode($item['network']), json_encode($requestedNetwork)));
        }
        $type = is_string($pin['type'] ?? null) ? strtolower($pin['type']) : '';
        if (!is_string($blockchain) || $blockchain === '') {
            throw new AddressVerificationError('unsupported', 'the answer does not say which blockchain the address is on, so it can\'t be checked');
        }
        if (!is_string($network) || $network === '') {
            $network = Chains::networkFor($blockchain, $type);
            if ($network === null) {
                throw new AddressVerificationError('unsupported', sprintf('%s is not a blockchain this SDK version can check', $blockchain));
            }
        }

        try {
            $this->addressVerifier ??= new AddressVerifier();
            $this->addressVerifier->verify(['type' => $type, 'keys' => $pin['keys']], [
                'blockchain' => $blockchain,
                'network' => $network,
                'address' => $item['address'],
                'accountIndex' => $item['accountIndex'],
                'isChange' => $item['isChange'],
                'addressIndex' => $item['addressIndex'],
                'addressFormat' => $item['addressFormat'] ?? null,
            ]);
        } catch (DerivationError $error) {
            throw new AddressVerificationError($error->reason, $error->getMessage(), $error);
        } catch (\InvalidArgumentException $error) {
            throw new AddressVerificationError('invalid', 'the address in the answer can\'t be checked: ' . $error->getMessage(), $error);
        }

        return ($pin['status'] ?? null) === PinModel::VERIFIED ? PinModel::VERIFIED : PinModel::UNVERIFIED;
    }

    /**
     * The pin of a vault: the configured one, else the stored one, pinning it first from the vault list if it is
     * not pinned yet. Null for a vault without MPC keys.
     *
     * @return array<string, mixed>|null
     * @throws AddressVerificationError unknown_vault when no vault list holds it
     */
    private function pinOf(string $vaultId, ?string $typeHint): ?array
    {
        $configured = $this->configuredPins();
        if (isset($configured[$vaultId])) {
            return $configured[$vaultId];
        }
        $store = $this->store ?? throw new ConfigurationError('no vault key store');
        $pin = $store->read($this->origin)['vaults'][$vaultId] ?? null;
        if ($pin !== null || isset($this->keylessVaults[$vaultId])) {
            return $pin;
        }

        // First sight: read the vault lists (every page goes through the whole pipeline and is compared with
        // the pins) until the vault is in one.
        foreach ($typeHint !== null ? [$typeHint] : ['main', 'test'] as $networkType) {
            foreach ($this->paginate(CoreOperations::listVaults(), ['networkType' => $networkType]) as $vault) {
                if (is_array($vault) && ($vault['id'] ?? null) === $vaultId) {
                    break 2;
                }
            }
        }

        $pin = $store->read($this->origin)['vaults'][$vaultId] ?? null;
        if ($pin === null && !isset($this->keylessVaults[$vaultId])) {
            throw new AddressVerificationError('unknown_vault', sprintf('vault %s is not in the vault list, so its addresses can\'t be checked', $vaultId));
        }

        return $pin;
    }

    /**
     * Hands an event, built into exactly its catalogued fields (SecurityEvents), to onSecurityEvent. With no
     * hook it is logged once as a warning, its JSON (it never holds a secret, an xpub or an address), as in Node
     * and Python; a hook that throws is logged, and never hides the error it was told about.
     *
     * @param array<string, mixed> $event
     */
    private function securityEvent(array $event): void
    {
        $event = SecurityEvents::build($event);
        if ($this->onSecurityEvent === null) {
            $this->warn('Vaultody security event: ' . json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR));

            return;
        }
        try {
            ($this->onSecurityEvent)($event);
        } catch (\Throwable) {
            $this->warn(sprintf('the security event hook raised on %s; the call still fails or continues as it would', $event['type']));
        }
    }
}
