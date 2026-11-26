<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Http;

/** One response as received: the body is the raw bytes after any Content-Encoding is removed. */
final class HttpResponse
{
    /**
     * @param array<string, list<string>> $headers lower-case name => every value received
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }

    public function header(string $name): ?string
    {
        $values = $this->headers[strtolower($name)] ?? [];

        return count($values) === 1 ? $values[0] : null;
    }
}
