<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Verify;

/**
 * Reading and checking root keys: the embedded ones and the `roots` option.
 */
final class Roots
{
    private const FINGERPRINT = '/^[0-9a-f]{64}$/D';
    // A P-256 SubjectPublicKeyInfo with a named curve and an uncompressed point is this fixed 27-byte header
    // (algorithm ecPublicKey, curve prime256v1, uncompressed-point marker) followed by the 64-byte point.
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d03010703420004';
    private const P256_SPKI_BYTES = 91;

    /** @var list<Root>|null */
    private static ?array $embedded = null;

    /**
     * Turns one configured root into the key that checks certificates and its id.
     *
     * Only a public key is accepted: a root's private key must never be on a client, and a certificate here
     * would mean something was mixed up. Only the one standard layout is accepted, the one Cloud KMS
     * publishes: a compressed point or explicit curve parameters would describe the same key with different
     * bytes and so a different id.
     *
     * @param mixed $entry a PEM string or ['pem' => ..., 'fingerprint' => ...]
     */
    public static function pinRoot(mixed $entry, string $label): Root
    {
        $pem = is_string($entry) ? $entry : (is_array($entry) ? ($entry['pem'] ?? null) : null);
        if (!is_string($pem) || trim($pem) === '') {
            throw new ConfigurationError($label . ' must be a public key in SPKI PEM form, or [\'pem\' => ...]');
        }

        preg_match_all('/-----BEGIN ([^-]*)-----/', $pem, $labels);
        if (count($labels[1]) !== 1 || $labels[1][0] !== 'PUBLIC KEY') {
            throw new ConfigurationError($label . ' must hold exactly one "PUBLIC KEY" PEM block');
        }
        if (preg_match('/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/', $pem, $body) !== 1) {
            throw new ConfigurationError($label . ' is not a readable public key');
        }
        $spki = base64_decode((string) preg_replace('/\s+/', '', $body[1]), true);

        Encoding::clearOpensslErrors();
        $key = openssl_pkey_get_public($pem);
        Encoding::clearOpensslErrors();
        if ($key === false) {
            throw new ConfigurationError($label . ' is not a readable public key');
        }
        if (!is_string($spki) || strlen($spki) !== self::P256_SPKI_BYTES
            || !str_starts_with($spki, (string) hex2bin(self::P256_SPKI_PREFIX))) {
            throw new ConfigurationError($label . ' must be a P-256 key in standard SPKI form (named curve, uncompressed point)');
        }

        $rootId = hash('sha256', $spki);
        $fingerprint = is_array($entry) ? ($entry['fingerprint'] ?? null) : null;
        if ($fingerprint !== null && $fingerprint !== '') {
            if (!is_string($fingerprint) || preg_match(self::FINGERPRINT, $fingerprint) !== 1) {
                throw new ConfigurationError($label . ' fingerprint must be 64 lowercase hex characters');
            }
            if ($fingerprint !== $rootId) {
                throw new ConfigurationError(sprintf('%s fingerprint %s does not match its key, whose SHA-256 SPKI fingerprint is %s', $label, $fingerprint, $rootId));
            }
        }

        return new Root($rootId, $key);
    }

    /**
     * Checks embedded roots. A slot is either fully empty or holds a key together with the fingerprint
     * published for it; anything in between, or a fingerprint that does not match its key, is refused.
     *
     * @param array<string, array{pem?: string, fingerprint?: string}> $slots
     * @return list<Root>
     */
    public static function loadEmbedded(array $slots): array
    {
        $pinned = [];
        foreach (['current', 'next'] as $slot) {
            $entry = $slots[$slot] ?? [];
            $hasPem = is_string($entry['pem'] ?? null) && $entry['pem'] !== '';
            $hasFingerprint = is_string($entry['fingerprint'] ?? null) && $entry['fingerprint'] !== '';
            if (!$hasPem && !$hasFingerprint) {
                continue;
            }
            if (!$hasPem || !$hasFingerprint) {
                throw new ConfigurationError(sprintf('embedded root "%s" has %s', $slot, $hasPem ? 'a key but no fingerprint' : 'a fingerprint but no key'));
            }
            $pinned[] = self::pinRoot($entry, sprintf('embedded root "%s"', $slot));
        }

        return $pinned;
    }

    /**
     * The roots embedded in this package, checked once per process.
     *
     * @return list<Root>
     */
    public static function embedded(): array
    {
        return self::$embedded ??= self::loadEmbedded(['current' => EmbeddedRoots::CURRENT, 'next' => EmbeddedRoots::NEXT]);
    }

    private static function isEmptyEntry(mixed $entry): bool
    {
        if ($entry === null || $entry === '') {
            return true;
        }

        return is_array($entry) && in_array($entry['pem'] ?? null, [null, ''], true)
            && in_array($entry['fingerprint'] ?? null, [null, ''], true);
    }

    /**
     * Reads the `roots` option without requiring it to hold a key: a malformed entry is a setup mistake and
     * throws at once, but empty slots are allowed ("next" exists only around a rotation), because whether a
     * root is needed at all depends on the response.
     *
     * @return list<Root>|null null when the option is not given
     */
    public static function parse(mixed $roots): ?array
    {
        if ($roots === null) {
            return null;
        }
        if ($roots instanceof Root) {
            return [$roots];
        }

        if (is_string($roots) || (is_array($roots) && array_key_exists('pem', $roots))) {
            $entries = [['roots', $roots]];
        } elseif (is_array($roots) && array_is_list($roots)) {
            $entries = [];
            foreach ($roots as $index => $entry) {
                $entries[] = [sprintf('roots[%d]', $index), $entry];
            }
        } elseif (is_array($roots)) {
            $entries = [];
            foreach ($roots as $name => $entry) {
                $entries[] = [sprintf('roots.%s', $name), $entry];
            }
        } else {
            throw new ConfigurationError('`roots` must be a PEM string, [\'pem\' => ...], a list of those, or [\'current\' => ..., \'next\' => ...]');
        }

        $pinned = [];
        foreach ($entries as [$label, $entry]) {
            if ($entry instanceof Root) {
                $pinned[] = $entry;
            } elseif (!self::isEmptyEntry($entry)) {
                $pinned[] = self::pinRoot($entry, $label);
            }
        }

        return $pinned;
    }

    /**
     * The roots to check a signed response against: the parsed option when given, else the embedded ones.
     * Having none is a setup mistake and is reported as one, never treated as "nothing to check". Called
     * only once a response carries a signature, so an unsigned response never needs a root.
     *
     * @param list<Root>|null $parsed
     * @return list<Root>
     */
    public static function require(?array $parsed): array
    {
        if ($parsed === null) {
            $embedded = self::embedded();
            if ($embedded === []) {
                throw new ConfigurationError('no root keys are configured: this build of vaultody/sdk embeds no root, '
                    . 'so pass them in the `roots` option. Refusing to treat any response as verified.');
            }

            return $embedded;
        }
        if ($parsed === []) {
            throw new ConfigurationError('the `roots` option holds no keys. Refusing to treat any response as verified.');
        }

        return $parsed;
    }
}
