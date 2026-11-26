<?php

declare(strict_types=1);

namespace Vaultody\Sdk\VaultKeys;

use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\VaultKeyStoreError;

/**
 * Pins in one JSON file at a path the application chooses, in the layout every SDK shares
 * (docs/vault-keys-file.md, test-vectors/vault-keys-file-v1.json). PHP needs an explicit path: under PHP-FPM
 * every request is a new process, so pins must outlive the process to protect anything.
 *
 * - The file holds xpubs, which reveal every address of a vault: it is written with mode 0600 in a directory
 *   created with mode 0700, and refused when the group or others can write it.
 * - A file that exists but can't be read, or does not match the layout exactly (an unknown field, a wrong
 *   type, another format tag), is an error, never an empty store. A missing file is an empty store.
 * - Every change is a read, merge and write while holding <file>.lock, created exclusively and removed
 *   afterwards: the lock protocol of every SDK, so PHP workers and Node or Python processes can share the
 *   file. Readers take no lock: a write goes to a temporary file in the same directory, is flushed to disk,
 *   and replaces the file with rename(), so a reader sees the old or the new file, never half of one.
 * - The bytes written are canonical (keys sorted, two-space indent): the same in every language.
 *
 * Format: {"format": "vaultody vault keys v1", "origins": {origin: {"responseSignature": null|{latchedAt, rootId|null},
 * "vaults": {vaultId: pin}, "audit": [{vaultId, at, reason, removed}]}}}
 */
final class FileVaultKeyStore implements VaultKeyStore
{
    public const FORMAT = 'vaultody vault keys v1';
    public const MAX_FILE_BYTES = 16 * 1024 * 1024;
    /** The largest time the file holds: 2^53 − 1, so every language reads it as an exact integer. */
    public const MAX_TIME = 9007199254740991;
    private const LOCK_STALE_SECONDS = 30;
    private const LOCK_TIMEOUT_SECONDS = 10;
    private const LOCK_RETRY_MICROSECONDS = 20000;
    private const ORIGIN = '/^https?:\/\/[^\/?#@\s]+$/Du';
    private const ALGORITHMS = ['ECDSA', 'EDDSA'];

    public function __construct(private readonly string $path)
    {
        if ($path === '' || str_contains($path, "\0")) {
            throw new ConfigurationError('the vault key file path must be a non-empty file path');
        }
    }

    public function path(): string
    {
        return $this->path;
    }

    /** The state of an origin before anything was stored for it. */
    public static function emptyState(): array
    {
        return ['responseSignature' => null, 'vaults' => [], 'audit' => []];
    }

    public function read(string $origin): array
    {
        return self::stateOf($this->load(), $origin);
    }

    public function update(string $origin, callable $change): array
    {
        $this->ensureDirectory();
        $release = $this->lock();
        try {
            $document = $this->load();
            $state = self::checkState($origin, $change(self::stateOf($document, $origin)));
            $before = self::encode($document);
            if (isset($document['origins'][$origin]) || $state !== self::emptyState()) {
                $document['origins'][$origin] = $state;
            }
            $text = self::encode($document);
            if ($text !== $before) {
                $this->write($text);
            }

            return $state;
        } finally {
            $release();
        }
    }

    /**
     * Checks the state a change returned for an origin, as the file would hold it.
     *
     * @return array{responseSignature: ?array{latchedAt: int, rootId: ?string}, vaults: array<string, array<string, mixed>>, audit: list<array<string, mixed>>}
     * @throws VaultKeyStoreError invalid_pin: the state can't be stored (a malformed pin or latch)
     * @throws \UnexpectedValueException the change did not return a state at all
     */
    public static function checkState(string $origin, mixed $state): array
    {
        if (!is_array($state) || count($state) !== 3 || !array_key_exists('responseSignature', $state)
            || !array_key_exists('vaults', $state) || !array_key_exists('audit', $state)) {
            throw new \UnexpectedValueException('a vault key store change must return [responseSignature, vaults, audit]');
        }
        try {
            $checked = self::document(self::tree(['format' => self::FORMAT, 'origins' => [$origin => $state]]));
        } catch (VaultKeyStoreError $error) {
            throw new VaultKeyStoreError('invalid_pin', 'the pins or latch to store are malformed: ' . $error->getMessage(), $error);
        }

        return $checked['origins'][$origin];
    }

    /**
     * Reads the bytes of a vault key file into the document, checked against the layout.
     *
     * @return array{format: string, origins: array<string, array<string, mixed>>}
     * @throws VaultKeyStoreError not_json, unknown_format or malformed
     */
    public static function parse(string $bytes): array
    {
        if ($bytes === '' || str_starts_with($bytes, "\xEF\xBB\xBF") || preg_match('//u', $bytes) !== 1) {
            throw new VaultKeyStoreError('not_json', 'the vault key file is not UTF-8 JSON (empty, a byte-order mark, or invalid UTF-8)');
        }
        try {
            $tree = json_decode($bytes, false, 64, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException $error) {
            throw new VaultKeyStoreError('not_json', 'the vault key file is not JSON: ' . $error->getMessage());
        }
        if (!$tree instanceof \stdClass || !property_exists($tree, 'format') || $tree->format !== self::FORMAT) {
            throw new VaultKeyStoreError('unknown_format', sprintf('the file is not a "%s" file', self::FORMAT));
        }

        return self::document($tree);
    }

    /**
     * The canonical bytes of a document: UTF-8, keys sorted at every level, two-space indent, "/" and
     * non-ASCII characters not escaped, a final newline. Every SDK writes the same bytes for the same content.
     *
     * @param array<string, mixed> $document
     * @throws VaultKeyStoreError malformed: the document does not match the layout
     */
    public static function encode(array $document): string
    {
        $tree = self::tree($document);
        self::document($tree);
        $json = json_encode(self::sorted($tree), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR);

        // PHP indents with four spaces; the canonical form has two. JSON strings hold no raw newline, so every
        // line starts with indentation only.
        return preg_replace_callback('/^( +)/m', static fn (array $m): string => str_repeat(' ', intdiv(strlen($m[1]), 2)), $json) . "\n";
    }

    // -- reading the file ---------------------------------------------------------------------------

    /** @return array{format: string, origins: array<string, array<string, mixed>>} */
    private function load(): array
    {
        clearstatcache(true, $this->path);
        if (is_link($this->path)) {
            throw new VaultKeyStoreError('not_regular_file', sprintf('the vault key file %s is a symbolic link; refusing to follow it', json_encode($this->path)));
        }
        if (!file_exists($this->path)) {
            return ['format' => self::FORMAT, 'origins' => []];
        }
        if (!is_file($this->path)) {
            throw new VaultKeyStoreError('not_regular_file', sprintf('the vault key file %s is not a regular file', json_encode($this->path)));
        }
        $mode = @fileperms($this->path);
        if (PHP_OS_FAMILY !== 'Windows' && $mode !== false && ($mode & 0022) !== 0) {
            throw new VaultKeyStoreError('insecure_permissions', sprintf('the vault key file %s is writable by other users; set its mode to 0600 (chmod 600) before using it', json_encode($this->path)));
        }
        $size = @filesize($this->path);
        if ($size !== false && $size > self::MAX_FILE_BYTES) {
            throw new VaultKeyStoreError('too_large', sprintf('the vault key file %s is larger than 16 MiB', json_encode($this->path)));
        }
        $bytes = @file_get_contents($this->path);
        if (!is_string($bytes)) {
            throw new VaultKeyStoreError('unreadable', sprintf('the vault key file %s can\'t be read; refusing to treat it as empty', json_encode($this->path)));
        }
        if (strlen($bytes) > self::MAX_FILE_BYTES) {
            throw new VaultKeyStoreError('too_large', sprintf('the vault key file %s is larger than 16 MiB', json_encode($this->path)));
        }

        return self::parse($bytes);
    }

    /**
     * @param array{format: string, origins: array<string, array<string, mixed>>} $document
     * @return array{responseSignature: ?array{latchedAt: int, rootId: ?string}, vaults: array<string, array<string, mixed>>, audit: list<array<string, mixed>>}
     */
    private static function stateOf(array $document, string $origin): array
    {
        return $document['origins'][$origin] ?? self::emptyState();
    }

    // -- the layout, checked on a decoded tree (objects as stdClass, so {} and [] differ) ------------

    /** @return array{format: string, origins: array<string, array<string, mixed>>} */
    private static function document(mixed $tree): array
    {
        if (!$tree instanceof \stdClass || !property_exists($tree, 'format') || $tree->format !== self::FORMAT) {
            throw new VaultKeyStoreError('unknown_format', sprintf('the file is not a "%s" file', self::FORMAT));
        }
        self::fields($tree, ['format', 'origins'], 'the file');
        if (!$tree->origins instanceof \stdClass) {
            throw self::malformed('origins is not an object');
        }
        $origins = [];
        foreach (get_object_vars($tree->origins) as $origin => $entry) {
            $origin = (string) $origin;
            if (preg_match(self::ORIGIN, $origin) !== 1) {
                throw self::malformed(sprintf('%s is not an API origin (scheme://host[:port])', json_encode($origin)));
            }
            $origins[$origin] = self::originEntry($entry, $origin);
        }

        return ['format' => self::FORMAT, 'origins' => $origins];
    }

    /** @return array{responseSignature: ?array{latchedAt: int, rootId: ?string}, vaults: array<string, array<string, mixed>>, audit: list<array<string, mixed>>} */
    private static function originEntry(mixed $entry, string $origin): array
    {
        $where = 'origin ' . $origin;
        self::fields($entry, ['responseSignature', 'vaults', 'audit'], $where);

        $latch = null;
        if ($entry->responseSignature !== null) {
            self::fields($entry->responseSignature, ['latchedAt', 'rootId'], $where . ' responseSignature');
            // rootId is null when the answer that latched the origin did not verify (refused, or no root to check it).
            $latch = [
                'latchedAt' => self::time($entry->responseSignature->latchedAt, $where . ' responseSignature.latchedAt'),
                'rootId' => $entry->responseSignature->rootId === null ? null : self::text($entry->responseSignature->rootId, $where . ' responseSignature.rootId'),
            ];
        }

        if (!$entry->vaults instanceof \stdClass) {
            throw self::malformed($where . ': vaults is not an object');
        }
        $vaults = [];
        foreach (get_object_vars($entry->vaults) as $vaultId => $pin) {
            $vaults[(string) $vaultId] = self::pin($pin, (string) $vaultId, $where);
        }

        if (!is_array($entry->audit) || !array_is_list($entry->audit)) {
            throw self::malformed($where . ': audit is not a list');
        }
        $audit = [];
        foreach ($entry->audit as $index => $record) {
            $at = sprintf('%s audit[%d]', $where, $index);
            self::fields($record, ['vaultId', 'at', 'reason', 'removed'], $at);
            if (!is_string($record->reason) || preg_match('/(*UCP)\S/u', $record->reason) !== 1) {
                throw self::malformed($at . ': reason is empty');
            }
            if (!is_bool($record->removed)) {
                throw self::malformed($at . ': removed is not true or false');
            }
            $audit[] = ['vaultId' => self::text($record->vaultId, $at . '.vaultId'), 'at' => self::time($record->at, $at . '.at'), 'reason' => $record->reason, 'removed' => $record->removed];
        }

        return ['responseSignature' => $latch, 'vaults' => $vaults, 'audit' => $audit];
    }

    /** @return array<string, mixed> */
    private static function pin(mixed $pin, string $vaultId, string $where): array
    {
        $where .= ' vault ' . $vaultId;
        self::fields($pin, ['vaultId', 'type', 'keys', 'status', 'firstSeenAt', 'verifiedAt', 'verification'], $where);
        if ($vaultId === '' || $pin->vaultId !== $vaultId) {
            throw self::malformed($where . ': the pin is stored under another vault id');
        }
        if (!in_array($pin->type, ['main', 'test'], true)) {
            throw self::malformed($where . ': type is not main or test');
        }
        self::fields($pin->keys, self::ALGORITHMS, $where . ' keys');
        $keys = [];
        foreach (self::ALGORITHMS as $algorithm) {
            $keys[$algorithm] = $pin->keys->{$algorithm} === null ? null : self::text($pin->keys->{$algorithm}, $where . ' keys.' . $algorithm);
        }
        if ($keys['ECDSA'] === null && $keys['EDDSA'] === null) {
            throw self::malformed($where . ': the pin holds no xpub');
        }
        if (!in_array($pin->status, [PinModel::VERIFIED, PinModel::UNVERIFIED], true)) {
            throw self::malformed($where . ': status is not verified or unverified');
        }
        $firstSeenAt = self::time($pin->firstSeenAt, $where . ' firstSeenAt');
        if ($pin->status === PinModel::VERIFIED) {
            $verifiedAt = self::time($pin->verifiedAt, $where . ' verifiedAt');
            self::fields($pin->verification, ['rootId', 'timestamp'], $where . ' verification');
            $verification = [
                'rootId' => self::text($pin->verification->rootId, $where . ' verification.rootId'),
                'timestamp' => self::time($pin->verification->timestamp, $where . ' verification.timestamp'),
            ];
        } else {
            if ($pin->verifiedAt !== null || $pin->verification !== null) {
                throw self::malformed($where . ': an unverified pin has a verification');
            }
            $verifiedAt = null;
            $verification = null;
        }

        return [
            'vaultId' => $vaultId,
            'type' => $pin->type,
            'keys' => $keys,
            'status' => $pin->status,
            'firstSeenAt' => $firstSeenAt,
            'verifiedAt' => $verifiedAt,
            'verification' => $verification,
        ];
    }

    /**
     * An object with exactly these fields.
     *
     * @param list<string> $names
     */
    private static function fields(mixed $object, array $names, string $where): void
    {
        if (!$object instanceof \stdClass) {
            throw self::malformed($where . ' is not an object');
        }
        $present = array_map('strval', array_keys(get_object_vars($object)));
        sort($present, SORT_STRING);
        $wanted = $names;
        sort($wanted, SORT_STRING);
        if ($present !== $wanted) {
            throw self::malformed(sprintf('%s has the fields %s, not %s', $where, implode(', ', $present), implode(', ', $wanted)));
        }
    }

    private static function time(mixed $value, string $where): int
    {
        // JSON_BIGINT_AS_STRING turns an integer too large for PHP into a string, and a fraction or an
        // exponent gives a float: neither is a time.
        if (!is_int($value) || $value < 0 || $value > self::MAX_TIME) {
            throw self::malformed($where . ' is not a time (an integer number of seconds)');
        }

        return $value;
    }

    private static function text(mixed $value, string $where): string
    {
        if (!is_string($value) || $value === '') {
            throw self::malformed($where . ' is not a non-empty string');
        }

        return $value;
    }

    private static function malformed(string $message): VaultKeyStoreError
    {
        return new VaultKeyStoreError('malformed', 'the vault key file does not match its layout: ' . $message);
    }

    // -- writing ------------------------------------------------------------------------------------

    /**
     * The document as a JSON tree: every array at a place the layout has an object becomes an object (so an
     * empty map is written {}), lists stay lists. Anything else is left for document() to refuse.
     */
    private static function tree(array $document): \stdClass
    {
        $object = static fn (mixed $value): mixed => is_array($value) ? (object) $value : $value;
        $tree = (object) $document;
        if (isset($tree->origins) && is_array($tree->origins)) {
            $origins = new \stdClass();
            foreach ($tree->origins as $origin => $entry) {
                if (is_array($entry)) {
                    $entry = (object) $entry;
                    if (property_exists($entry, 'responseSignature')) {
                        $entry->responseSignature = $object($entry->responseSignature);
                    }
                    if (isset($entry->vaults) && is_array($entry->vaults)) {
                        $vaults = new \stdClass();
                        foreach ($entry->vaults as $vaultId => $pin) {
                            if (is_array($pin)) {
                                $pin = (object) $pin;
                                if (isset($pin->keys)) {
                                    $pin->keys = $object($pin->keys);
                                }
                                if (isset($pin->verification)) {
                                    $pin->verification = $object($pin->verification);
                                }
                            }
                            $vaults->{(string) $vaultId} = $pin;
                        }
                        $entry->vaults = $vaults;
                    }
                    if (isset($entry->audit) && is_array($entry->audit) && array_is_list($entry->audit)) {
                        $entry->audit = array_map($object, $entry->audit);
                    } elseif (isset($entry->audit) && is_array($entry->audit)) {
                        $entry->audit = (object) $entry->audit;
                    }
                }
                $origins->{(string) $origin} = $entry;
            }
            $tree->origins = $origins;
        }

        return $tree;
    }

    /** Objects with their keys sorted (as strings), at every level; lists keep their order. */
    private static function sorted(mixed $value): mixed
    {
        if ($value instanceof \stdClass) {
            $fields = get_object_vars($value);
            ksort($fields, SORT_STRING);
            $sorted = new \stdClass();
            foreach ($fields as $name => $field) {
                $sorted->{(string) $name} = self::sorted($field);
            }

            return $sorted;
        }
        if (is_array($value)) {
            return array_map(self::sorted(...), $value);
        }

        return $value;
    }

    private function ensureDirectory(): void
    {
        $directory = dirname($this->path);
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new VaultKeyStoreError('unwritable', sprintf('cannot create the directory of the vault key file %s', json_encode($this->path)));
        }
    }

    /**
     * Takes <file>.lock, created exclusively: the protocol every SDK uses on a shared file (no flock(): Node.js
     * has none). A lock older than 30 seconds was left by a process that died, and is removed.
     *
     * @return \Closure(): void releases the lock
     */
    private function lock(): \Closure
    {
        $lockFile = $this->path . '.lock';
        $started = microtime(true);
        $missing = 0;
        while (true) {
            $previousMask = umask(0077);
            try {
                $handle = @fopen($lockFile, 'x');
            } finally {
                umask($previousMask);
            }
            if ($handle !== false) {
                fwrite($handle, (string) getmypid());
                fclose($handle);

                return static function () use ($lockFile): void {
                    @unlink($lockFile);
                };
            }
            clearstatcache(true, $lockFile);
            $mtime = @filemtime($lockFile);
            if ($mtime === false) {
                // Released in the meantime, or it can't be created at all.
                if (++$missing > 50) {
                    throw new VaultKeyStoreError('unwritable', sprintf('cannot create the lock file of the vault key file %s', json_encode($this->path)));
                }
                continue;
            }
            $missing = 0;
            if (time() - $mtime > self::LOCK_STALE_SECONDS) {
                @unlink($lockFile);
                continue;
            }
            if (microtime(true) - $started > self::LOCK_TIMEOUT_SECONDS) {
                throw new VaultKeyStoreError('locked', sprintf('the vault key file %s stayed locked for %d s (%s)', json_encode($this->path), self::LOCK_TIMEOUT_SECONDS, $lockFile));
            }
            usleep(self::LOCK_RETRY_MICROSECONDS);
        }
    }

    private function write(string $text): void
    {
        $temporary = $this->path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        $previousMask = umask(0077);
        try {
            $handle = @fopen($temporary, 'x');
        } finally {
            umask($previousMask);
        }
        if ($handle === false) {
            throw new VaultKeyStoreError('unwritable', sprintf('cannot write the vault key file %s', json_encode($this->path)));
        }
        try {
            $written = fwrite($handle, $text) === strlen($text) && fflush($handle) && fsync($handle);
        } finally {
            fclose($handle);
        }
        if (!$written || !@chmod($temporary, 0600) || !@rename($temporary, $this->path)) {
            @unlink($temporary);
            throw new VaultKeyStoreError('unwritable', sprintf('cannot write the vault key file %s', json_encode($this->path)));
        }
    }
}
