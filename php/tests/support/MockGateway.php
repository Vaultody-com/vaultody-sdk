<?php

declare(strict_types=1);

/**
 * Starts mock-gateway.php under PHP's built-in server on a free local port and drives it: what it answers,
 * and what it received. One instance serves a whole test file; reset() clears it between tests.
 */
final class MockGateway
{
    /** @var resource|null */
    private $process = null;

    private function __construct(public readonly string $dir, public readonly int $port)
    {
    }

    public static function start(): self
    {
        $dir = sys_get_temp_dir() . '/vaultody-mock-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $server = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr((string) stream_socket_get_name($server, false), strrpos((string) stream_socket_get_name($server, false), ':') + 1);
        fclose($server);

        $gateway = new self($dir, $port);
        $gateway->reset();
        $gateway->process = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/mock-gateway.php'],
            [0 => ['pipe', 'r'], 1 => ['file', $dir . '/server.log', 'a'], 2 => ['file', $dir . '/server.log', 'a']],
            $pipes,
            null,
            ['MOCK_DIR' => $dir, 'PHP_CLI_SERVER_WORKERS' => '4', 'PATH' => (string) getenv('PATH')],
        );
        for ($i = 0; $i < 100; $i++) {
            $socket = @fsockopen('127.0.0.1', $port, $errno, $error, 0.1);
            if ($socket !== false) {
                fclose($socket);

                return $gateway;
            }
            usleep(50000);
        }
        throw new RuntimeException('the mock gateway did not start: ' . (string) @file_get_contents($dir . '/server.log'));
    }

    public function url(): string
    {
        return 'http://127.0.0.1:' . $this->port;
    }

    /** Clears the script, the vault lists, the replay records and the request log. */
    public function reset(): void
    {
        $this->write(['script' => [], 'vaults' => ['main' => [], 'test' => []], 'signingKeys' => [], 'nonces' => new stdClass()]);
        file_put_contents($this->dir . '/requests.jsonl', '');
    }

    /** @param list<array<string, mixed>> $answers answered in order to requests other than the vault lists and signing keys */
    public function script(array $answers): void
    {
        $this->change(static fn (array $state): array => ['script' => $answers] + $state);
    }

    /** @param array<string, mixed> $values */
    public function set(array $values): void
    {
        $this->change(static fn (array $state): array => $values + $state);
    }

    /** @return list<array<string, mixed>> */
    public function requests(): array
    {
        $lines = array_filter(explode("\n", (string) file_get_contents($this->dir . '/requests.jsonl')));

        return array_values(array_map(static fn (string $line): array => json_decode($line, true), $lines));
    }

    /** @param list<string> $paths @return list<array<string, mixed>> requests other than to these paths */
    public function requestsExcept(array $paths): array
    {
        return array_values(array_filter($this->requests(), static fn (array $request): bool => !in_array($request['path'], $paths, true)
            && preg_match('#^/vaults/(main|test)$#', $request['path']) !== 1));
    }

    public function stop(): void
    {
        if ($this->process !== null) {
            proc_terminate($this->process);
            proc_close($this->process);
            $this->process = null;
        }
    }

    public function __destruct()
    {
        $this->stop();
    }

    /** @param callable(array<string, mixed>): array<string, mixed> $change */
    private function change(callable $change): void
    {
        $lock = fopen($this->dir . '/lock', 'c');
        flock($lock, LOCK_EX);
        $this->write($change(json_decode((string) file_get_contents($this->dir . '/state.json'), true)));
        flock($lock, LOCK_UN);
        fclose($lock);
    }

    /** @param array<string, mixed> $state */
    private function write(array $state): void
    {
        if (isset($state['nonces']) && $state['nonces'] === []) {
            $state['nonces'] = new stdClass();
        }
        file_put_contents($this->dir . '/state.json', json_encode($state, JSON_UNESCAPED_SLASHES));
    }
}
