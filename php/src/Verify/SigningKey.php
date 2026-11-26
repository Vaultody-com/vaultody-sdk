<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * One request-signing key, Ed25519 or ECDSA P-256: the public half always, the private half when it was read
 * from a private key. It applies the same reading rules as the Node module and the key registration, and
 * computes the fingerprint over the canonical SubjectPublicKeyInfo, so a compressed and an uncompressed
 * P-256 key give one fingerprint (test-vectors/request-keypair-v1.json).
 *
 * The private half never leaves this object: it is not in var_dump() or print_r() output, the object can't
 * be serialised, and no error carries key material.
 */
final class SigningKey
{
    public const ED25519 = 'ed25519';
    public const P256 = 'p-256';

    /** A key file is read only up to this size; an Ed25519 or P-256 PEM is a few hundred bytes. */
    public const MAX_KEY_FILE_BYTES = 16384;
    /** A registration reads a pasted public key only up to this length (a P-256 PEM is 178 characters). */
    public const MAX_PUBLIC_KEY_PEM_LENGTH = 1024;

    private const SUPPORTED = 'Only Ed25519 and ECDSA P-256 keys are supported.';
    // Any PEM private key, a PuTTY key file, or a JWK holding its private member "d": what a registration
    // refuses as private before it parses anything.
    private const PRIVATE_KEY_MARKERS = ['/PRIVATE KEY/i', '/PuTTY-User-Key-File/i', '/"d"\s*:/'];
    private const OPENSSH_PUBLIC_KEY = '/^(?:ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)|^---- BEGIN SSH2 PUBLIC KEY ----/';
    private const PEM_LABEL = '/-----BEGIN ([^-\n]{1,40})-----/';
    // Anything a PEM body can't hold. One character class, so the check is linear in the length of the text.
    private const NOT_PEM_BODY = '/[^A-Za-z0-9+\/=\s]/';
    private const BASE64_SHAPE = '/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/D';

    // Algorithm identifiers (the contents of the DER OBJECT IDENTIFIER)
    private const OID_ED25519 = '2b6570';
    private const OID_EC = '2a8648ce3d0201';
    private const OID_P256 = '2a8648ce3d030107';
    private const OID_NAMES = [
        '2a864886f70d010101' => 'an RSA key',
        '2a864886f70d01010a' => 'an RSA key',
        '2a8648ce380401' => 'a DSA key',
        '2a864886f70d010301' => 'a Diffie-Hellman key',
        '2b6571' => 'an Ed448 key',
        '2b656e' => 'an X25519 key',
        '2b656f' => 'an X448 key',
    ];
    private const CURVE_NAMES = [
        '2b81040022' => 'an ECDSA P-384 key',
        '2b81040023' => 'an ECDSA P-521 key',
        '2b8104000a' => 'a secp256k1 key',
        'secp384r1' => 'an ECDSA P-384 key',
        'secp521r1' => 'an ECDSA P-521 key',
        'secp256k1' => 'a secp256k1 key',
    ];
    // The canonical SubjectPublicKeyInfo headers: Ed25519 (then the 32-byte key) and P-256 with a named
    // curve and an uncompressed point (then x and y, 32 bytes each).
    private const ED25519_SPKI_PREFIX = '302a300506032b6570032100';
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d03010703420004';

    // Held so that no dump, cast, export, JSON or serialisation of this object shows it.
    private ?\SensitiveParameterValue $ed25519SecretKey;
    private ?\OpenSSLAsymmetricKey $p256PrivateKey;
    private ?\OpenSSLAsymmetricKey $p256PublicKey = null;

    private function __construct(
        /** 'public' or 'private': which halves were read */
        public readonly string $kind,
        /** 'ed25519' or 'p-256' */
        public readonly string $algorithm,
        /** the canonical SubjectPublicKeyInfo DER */
        public readonly string $spkiDer,
        /** "SHA256:" + base64 without padding of SHA-256 over the canonical SPKI DER: x-api-keypair-id */
        public readonly string $fingerprint,
        #[\SensitiveParameter] ?string $ed25519SecretKey = null,
        #[\SensitiveParameter] ?\OpenSSLAsymmetricKey $p256PrivateKey = null,
    ) {
        $this->ed25519SecretKey = $ed25519SecretKey === null ? null : new \SensitiveParameterValue($ed25519SecretKey);
        $this->p256PrivateKey = $p256PrivateKey;
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['kind' => $this->kind, 'algorithm' => $this->algorithm, 'fingerprint' => $this->fingerprint];
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new \LogicException('a signing key is not serialisable');
    }

    /** @param array<string, mixed> $data */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('a signing key is not serialisable');
    }

    public function __clone()
    {
        throw new \LogicException('a signing key is not cloneable');
    }

    /** The public half as canonical SPKI PEM. */
    public function publicKeyPem(): string
    {
        return self::pem('PUBLIC KEY', $this->spkiDer);
    }

    public function hasPrivateKey(): bool
    {
        return $this->ed25519SecretKey !== null || $this->p256PrivateKey !== null;
    }

    /**
     * Signs a message. Ed25519: the raw 64-byte signature; P-256: ECDSA over SHA-256, DER encoded.
     *
     * @throws SigningKeyError public_key when only the public half was read
     */
    public function sign(string $message): string
    {
        if ($this->ed25519SecretKey !== null) {
            return sodium_crypto_sign_detached($message, $this->ed25519SecretKey->getValue());
        }
        if ($this->p256PrivateKey !== null) {
            Encoding::clearOpensslErrors();
            $ok = openssl_sign($message, $signature, $this->p256PrivateKey, OPENSSL_ALGO_SHA256);
            Encoding::clearOpensslErrors();
            if (!$ok || !is_string($signature)) {
                throw new \RuntimeException('OpenSSL could not sign with the P-256 key');
            }

            return $signature;
        }

        throw new SigningKeyError(SigningKeyError::PUBLIC, 'This is a public key. Signing needs the private key (private.pem).');
    }

    /**
     * Verifies a signature the way the gateway and the registration do: canonical padded base64, Ed25519
     * exactly 64 bytes, P-256 DER only (IEEE P1363 r||s, and any DER OpenSSL would not write that way, is
     * refused).
     */
    public function verify(string $message, mixed $signatureBase64): bool
    {
        $signature = Encoding::strictBase64($signatureBase64);
        if ($signature === null) {
            return false;
        }

        return $this->verifyBytes($message, $signature);
    }

    /** As verify(), for the raw signature bytes. */
    public function verifyBytes(string $message, string $signature): bool
    {
        if ($this->algorithm === self::ED25519) {
            if (strlen($signature) !== 64) {
                return false;
            }
            try {
                return sodium_crypto_sign_verify_detached($signature, $message, substr($this->spkiDer, -32));
            } catch (\SodiumException) {
                return false;
            }
        }

        Encoding::clearOpensslErrors();
        $this->p256PublicKey ??= openssl_pkey_get_public($this->publicKeyPem()) ?: null;
        $ok = $this->p256PublicKey !== null && openssl_verify($message, $signature, $this->p256PublicKey, OPENSSL_ALGO_SHA256) === 1;
        Encoding::clearOpensslErrors();

        return $ok;
    }

    /**
     * Reads one signing key in PEM: a public key ("BEGIN PUBLIC KEY", SubjectPublicKeyInfo) or a private key
     * ("BEGIN PRIVATE KEY", PKCS#8, or "BEGIN EC PRIVATE KEY", SEC1), Ed25519 or ECDSA P-256.
     *
     * With $accept 'public' it applies the rules a registration applies to a pasted key, in the same order:
     * anything private is refused before it is parsed, then a text that is too long, OpenSSH keys,
     * certificates, several blocks and other PEM types, then keys of any other type.
     *
     * @param 'public'|'private'|'any' $accept which halves to take
     * @throws SigningKeyError
     */
    public static function read(#[\SensitiveParameter] string $text, string $accept = 'any'): self
    {
        if (!in_array($accept, ['public', 'private', 'any'], true)) {
            throw new \InvalidArgumentException('accept must be "public", "private" or "any"');
        }
        if (trim($text) === '') {
            throw self::invalid('it is empty');
        }
        if ($accept === 'public') {
            foreach (self::PRIVATE_KEY_MARKERS as $marker) {
                if (preg_match($marker, $text) === 1) {
                    throw self::privateWherePublic();
                }
            }
            if (strlen($text) > self::MAX_PUBLIC_KEY_PEM_LENGTH) {
                throw self::invalid(sprintf('it is longer than %d characters', self::MAX_PUBLIC_KEY_PEM_LENGTH));
            }
        }
        if (strlen($text) > self::MAX_KEY_FILE_BYTES) {
            throw self::invalid('it is far longer than an Ed25519 or P-256 key');
        }

        $pem = trim((string) preg_replace('/\r\n?/', "\n", $text));
        if (preg_match('/PuTTY-User-Key-File/i', $pem) === 1) {
            throw self::invalid('it is a PuTTY key file; use a PEM key');
        }
        if (preg_match(self::OPENSSH_PUBLIC_KEY, $pem) === 1) {
            throw self::invalid('it is an OpenSSH public key; use a PEM public key (BEGIN PUBLIC KEY)');
        }

        preg_match_all(self::PEM_LABEL, $pem, $matches);
        $labels = $matches[1];
        if (in_array('CERTIFICATE', $labels, true) || in_array('TRUSTED CERTIFICATE', $labels, true)) {
            throw self::invalid('it is a certificate, not a key');
        }
        if ($labels === []) {
            throw self::invalid('it is not a PEM key (BEGIN PUBLIC KEY or BEGIN PRIVATE KEY)');
        }
        if (count($labels) > 1) {
            throw self::invalid('it holds more than one PEM block');
        }

        $label = $labels[0];
        if ($label === 'RSA PUBLIC KEY' || $label === 'RSA PRIVATE KEY') {
            throw new SigningKeyError(SigningKeyError::UNSUPPORTED_ALGORITHM, 'This is an RSA key. ' . self::SUPPORTED);
        }
        // PKCS#8 encrypted, or a SEC1 key with the legacy OpenSSL encryption headers
        if ($label === 'ENCRYPTED PRIVATE KEY' || preg_match('/^Proc-Type:\s*4,ENCRYPTED/m', $pem) === 1) {
            throw new SigningKeyError(SigningKeyError::ENCRYPTED, 'This private key is protected by a passphrase, which the SDK does not read. '
                . 'Use an unencrypted copy, for example from "openssl pkey -in encrypted.pem -out private.pem".');
        }
        if ($label === 'OPENSSH PRIVATE KEY') {
            throw self::invalid('it is an OpenSSH private key; generate a PEM key pair with openssl');
        }

        if ($label === 'PUBLIC KEY') {
            if ($accept === 'private') {
                throw new SigningKeyError(SigningKeyError::PUBLIC, 'This is a public key. Signing needs the private key (private.pem).');
            }
            $body = self::pemContents($pem, 'PUBLIC KEY');
            if ($body === null) {
                throw self::invalid('it is not a PEM public key (BEGIN PUBLIC KEY)');
            }

            return self::fromSpki(self::pemBody($body));
        }

        if ($label === 'PRIVATE KEY' || $label === 'EC PRIVATE KEY') {
            if ($accept === 'public') {
                throw self::privateWherePublic();
            }

            return self::fromPrivatePem($pem, $label);
        }

        throw self::invalid('it is not a PEM key (BEGIN PUBLIC KEY or BEGIN PRIVATE KEY)');
    }

    /**
     * Reads a key file without reading past a sane size.
     *
     * @param 'public'|'private'|'any' $accept
     * @throws UsageError the file can't be read
     * @throws SigningKeyError
     */
    public static function readFile(string $path, string $accept = 'private'): self
    {
        if (!is_file($path)) {
            throw new UsageError(sprintf('cannot read the key file %s: not a file', json_encode($path)));
        }
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            throw new UsageError(sprintf('cannot read the key file %s', json_encode($path)));
        }
        try {
            $stat = fstat($handle);
            if ($stat !== false && $stat['size'] > self::MAX_KEY_FILE_BYTES) {
                throw self::invalid('the file is far larger than an Ed25519 or P-256 key');
            }
            $text = stream_get_contents($handle, self::MAX_KEY_FILE_BYTES + 1);
        } finally {
            fclose($handle);
        }
        if (!is_string($text) || strlen($text) > self::MAX_KEY_FILE_BYTES) {
            throw self::invalid('the file is far larger than an Ed25519 or P-256 key');
        }

        return self::read($text, $accept);
    }

    /**
     * The checks a registration applies to a pasted public key, giving the canonical key and fingerprint.
     *
     * @throws SigningKeyError
     */
    public static function inspectPublicKey(string $text): self
    {
        return self::read($text, 'public');
    }

    /** "SHA256:" + base64 without padding of SHA-256 over a canonical SPKI DER: 50 characters. */
    public static function fingerprintOf(string $spkiDer): string
    {
        return 'SHA256:' . rtrim(base64_encode(hash('sha256', $spkiDer, true)), '=');
    }

    /** PEM text of DER bytes, in 64-character lines as OpenSSL and Node write it. */
    public static function pem(string $label, string $der): string
    {
        return '-----BEGIN ' . $label . "-----\n" . chunk_split(base64_encode($der), 64, "\n") . '-----END ' . $label . "-----\n";
    }

    /**
     * What lies between "-----BEGIN <label>-----" at the very start of $pem and "-----END <label>-----" at its very end,
     * or null when $pem is not that one block or holds anything but base64 and whitespace in between. Read with
     * string functions and one character class, never a pattern that backtracks: a long run of whitespace in a
     * pasted key costs linear time.
     */
    private static function pemContents(#[\SensitiveParameter] string $pem, string $label): ?string
    {
        $begin = '-----BEGIN ' . $label . '-----';
        $end = '-----END ' . $label . '-----';
        if (strlen($pem) < strlen($begin) + strlen($end) || !str_starts_with($pem, $begin) || !str_ends_with($pem, $end)) {
            return null;
        }
        $inner = substr($pem, strlen($begin), strlen($pem) - strlen($begin) - strlen($end));

        return preg_match(self::NOT_PEM_BODY, $inner) === 0 ? $inner : null;
    }

    private static function pemBody(string $body): string
    {
        $base64 = (string) preg_replace('/\s+/', '', $body);
        $der = $base64 === '' || preg_match(self::BASE64_SHAPE, $base64) !== 1 ? false : base64_decode($base64, true);
        if (!is_string($der) || $der === '') {
            throw self::invalid('the PEM body is not base64');
        }

        return $der;
    }

    /**
     * A SubjectPublicKeyInfo to a key, canonical form and fingerprint.
     *
     * @throws SigningKeyError
     */
    private static function fromSpki(string $spki): self
    {
        try {
            $info = Der::elements(Der::only($spki, Der::SEQUENCE));
            if (count($info) !== 2 || $info[0][0] !== Der::SEQUENCE || $info[1][0] !== Der::BIT_STRING) {
                throw new \UnexpectedValueException('not a SubjectPublicKeyInfo');
            }
            $algorithm = Der::elements($info[0][1]);
            if ($algorithm === [] || $algorithm[0][0] !== Der::OID) {
                throw new \UnexpectedValueException('no algorithm');
            }
            $oid = bin2hex($algorithm[0][1]);
            $bits = $info[1][1];
            if ($bits === '' || $bits[0] !== "\0") {
                throw new \UnexpectedValueException('unused bits in the key');
            }
            $point = substr($bits, 1);
        } catch (\UnexpectedValueException) {
            throw self::invalid('it is not a valid public key');
        }

        if ($oid === self::OID_ED25519) {
            if (count($algorithm) !== 1 || strlen($point) !== 32) {
                throw self::invalid('it is not a valid public key');
            }

            return self::describeEd25519('public', $point, null);
        }
        if ($oid === self::OID_EC) {
            $curve = count($algorithm) === 2 && $algorithm[1][0] === Der::OID ? bin2hex($algorithm[1][1]) : null;
            if ($curve !== self::OID_P256) {
                throw new SigningKeyError(SigningKeyError::UNSUPPORTED_ALGORITHM, sprintf('This is %s. %s', self::CURVE_NAMES[$curve] ?? 'an ECDSA key on another curve', self::SUPPORTED));
            }
            // OpenSSL checks that the point is on the curve, and decompresses a compressed one.
            Encoding::clearOpensslErrors();
            $key = openssl_pkey_get_public(self::pem('PUBLIC KEY', $spki));
            $details = $key === false ? false : openssl_pkey_get_details($key);
            Encoding::clearOpensslErrors();
            if ($details === false || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
                throw self::invalid('it is not a valid public key');
            }

            return self::describeP256('public', $details['ec']['x'], $details['ec']['y'], null);
        }

        throw new SigningKeyError(SigningKeyError::UNSUPPORTED_ALGORITHM, sprintf('This is %s. %s', self::OID_NAMES[$oid] ?? 'a key of another type', self::SUPPORTED));
    }

    /** @throws SigningKeyError */
    private static function fromPrivatePem(#[\SensitiveParameter] string $pem, string $label): self
    {
        $body = self::pemContents($pem, $label);
        if ($body === null) {
            throw self::invalid('it is not a valid private key');
        }
        $der = self::pemBody($body);

        if ($label === 'PRIVATE KEY') {
            // PKCS#8: version, algorithm, the private key as an OCTET STRING, then optional attributes and
            // public key. Ed25519 is read here, because PHP's OpenSSL binding can't sign with it before 8.4;
            // everything else goes to OpenSSL below.
            try {
                $info = Der::elements(Der::only($der, Der::SEQUENCE));
                if (count($info) < 3 || $info[0][0] !== Der::INTEGER || $info[1][0] !== Der::SEQUENCE || $info[2][0] !== Der::OCTET_STRING) {
                    throw new \UnexpectedValueException('not PKCS#8');
                }
                $algorithm = Der::elements($info[1][1]);
                if ($algorithm === [] || $algorithm[0][0] !== Der::OID) {
                    throw new \UnexpectedValueException('no algorithm');
                }
                $oid = bin2hex($algorithm[0][1]);
            } catch (\UnexpectedValueException) {
                throw self::invalid('it is not a valid private key');
            }

            if ($oid === self::OID_ED25519) {
                try {
                    $seed = Der::only($info[2][1], Der::OCTET_STRING);
                } catch (\UnexpectedValueException) {
                    throw self::invalid('it is not a valid private key');
                }
                if (count($algorithm) !== 1 || strlen($seed) !== 32) {
                    throw self::invalid('it is not a valid private key');
                }
                $pair = sodium_crypto_sign_seed_keypair($seed);
                sodium_memzero($seed);
                $secret = sodium_crypto_sign_secretkey($pair);
                $public = sodium_crypto_sign_publickey($pair);
                sodium_memzero($pair);
                $key = self::describeEd25519('private', $public, $secret);
                sodium_memzero($secret);

                return $key;
            }
            if ($oid !== self::OID_EC) {
                throw new SigningKeyError(SigningKeyError::UNSUPPORTED_ALGORITHM, sprintf('This is %s. %s', self::OID_NAMES[$oid] ?? 'a key of another type', self::SUPPORTED));
            }
        }

        Encoding::clearOpensslErrors();
        $key = openssl_pkey_get_private($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        Encoding::clearOpensslErrors();
        if ($key === false || $details === false || !isset($details['ec']['x'], $details['ec']['y'])) {
            throw self::invalid('it is not a valid private key');
        }
        $curve = $details['ec']['curve_name'] ?? null;
        if ($curve !== 'prime256v1') {
            throw new SigningKeyError(SigningKeyError::UNSUPPORTED_ALGORITHM, sprintf('This is %s. %s', self::CURVE_NAMES[$curve] ?? 'an ECDSA key on another curve', self::SUPPORTED));
        }

        return self::describeP256('private', $details['ec']['x'], $details['ec']['y'], $key);
    }

    private static function describeEd25519(string $kind, string $publicKey, #[\SensitiveParameter] ?string $secretKey): self
    {
        $spki = (string) hex2bin(self::ED25519_SPKI_PREFIX) . $publicKey;

        return new self($kind, self::ED25519, $spki, self::fingerprintOf($spki), $secretKey, null);
    }

    private static function describeP256(string $kind, string $x, string $y, #[\SensitiveParameter] ?\OpenSSLAsymmetricKey $privateKey): self
    {
        // OpenSSL gives the coordinates without leading zero bytes; the canonical point has 32 bytes each.
        $spki = (string) hex2bin(self::P256_SPKI_PREFIX) . str_pad($x, 32, "\0", STR_PAD_LEFT) . str_pad($y, 32, "\0", STR_PAD_LEFT);

        return new self($kind, self::P256, $spki, self::fingerprintOf($spki), null, $privateKey);
    }

    private static function invalid(string $reason): SigningKeyError
    {
        return new SigningKeyError(SigningKeyError::INVALID, 'This is not a usable signing key: ' . $reason . '.');
    }

    private static function privateWherePublic(): SigningKeyError
    {
        return new SigningKeyError(SigningKeyError::PRIVATE, 'This is a private key. Give the public key (public.pem) instead, '
            . 'and never share the private key with anyone, Vaultody included.');
    }
}
