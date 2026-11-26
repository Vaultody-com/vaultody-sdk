<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Http;

use Vaultody\Sdk\Exception\TransportError;

/**
 * Sends one request. An implementation must not follow redirects, must not retry by itself, must verify TLS,
 * and must say whether a failed request may have been sent (TransportError::$sent).
 */
interface HttpClient
{
    /** @throws TransportError */
    public function send(HttpRequest $request): HttpResponse;
}
