<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Http;

/** One request exactly as it goes on the wire. */
final class HttpRequest
{
    /**
     * @param string $url the absolute URL; its path and query are exactly what was signed
     * @param array<string, string> $headers name => value
     * @param bool $freshConnection open a new connection and close it afterwards. Set for writes: an HTTP
     *        client may silently send a request again on a kept-alive connection that turned out to be closed,
     *        and a write must never be sent twice behind the SDK's back.
     */
    public function __construct(
        public readonly string $method,
        public readonly string $url,
        public readonly array $headers,
        public readonly string $body = '',
        public readonly bool $freshConnection = false,
    ) {
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        // The headers carry the API key and passphrase.
        return ['method' => $this->method, 'url' => $this->url, 'headers' => array_keys($this->headers)];
    }
}
