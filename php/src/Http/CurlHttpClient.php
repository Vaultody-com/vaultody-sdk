<?php

declare(strict_types=1);

namespace Vaultody\Sdk\Http;

use Vaultody\Sdk\Exception\ConfigurationError;
use Vaultody\Sdk\Exception\TransportError;
use Vaultody\Sdk\TransportErrors;

/**
 * The HTTP client on PHP's curl extension. TLS verification is always on (a custom CA bundle may be given,
 * switching verification off may not), redirects are never followed, the decoded response body is capped,
 * and only https is spoken, or plain http to this machine.
 */
final class CurlHttpClient implements HttpClient
{
    public const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

    /** @var \CurlHandle|null kept for connection reuse between reads */
    private ?\CurlHandle $handle = null;

    public function __construct(
        private readonly int $timeoutMs = 30000,
        private readonly int $connectTimeoutMs = 10000,
        private readonly ?string $caBundle = null,
        private readonly int $maxResponseBytes = self::MAX_RESPONSE_BYTES,
    ) {
        if (!extension_loaded('curl')) {
            throw new ConfigurationError('the curl extension is required');
        }
        if ($caBundle !== null && !is_file($caBundle)) {
            throw new ConfigurationError(sprintf('the CA bundle %s is not a file', json_encode($caBundle)));
        }
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $plainHttp = str_starts_with($request->url, 'http://');
        $handle = $request->freshConnection || $this->handle === null ? curl_init() : $this->handle;
        if ($handle === false) {
            throw new TransportError('curl could not start', false);
        }
        curl_reset($handle);

        $headers = [];
        $body = '';
        $tooLarge = false;
        $lines = [];
        foreach ($request->headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        // No "Expect: 100-continue" round trip; the body goes with the request.
        $lines[] = 'Expect:';

        $options = [
            CURLOPT_URL => $request->url,
            CURLOPT_CUSTOMREQUEST => $request->method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => $plainHttp ? CURLPROTO_HTTP : CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_TIMEOUT_MS => $this->timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $this->connectTimeoutMs,
            CURLOPT_NOSIGNAL => true,
            // Every encoding curl can decode is accepted; the signature covers the decoded bytes.
            CURLOPT_ENCODING => '',
            CURLOPT_FRESH_CONNECT => $request->freshConnection,
            CURLOPT_FORBID_REUSE => $request->freshConnection,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$headers): int {
                $trimmed = rtrim($line, "\r\n");
                if (str_starts_with($trimmed, 'HTTP/')) {
                    // A new response (after a 1xx): its headers replace the previous ones.
                    $headers = [];
                } elseif (($colon = strpos($trimmed, ':')) !== false) {
                    $headers[strtolower(trim(substr($trimmed, 0, $colon)))][] = trim(substr($trimmed, $colon + 1));
                }

                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($curl, string $chunk) use (&$body, &$tooLarge): int {
                if (strlen($body) + strlen($chunk) > $this->maxResponseBytes) {
                    $tooLarge = true;

                    return 0;
                }
                $body .= $chunk;

                return strlen($chunk);
            },
        ];
        if ($this->caBundle !== null) {
            $options[CURLOPT_CAINFO] = $this->caBundle;
        }
        if ($request->method !== 'GET' || $request->body !== '') {
            $options[CURLOPT_POSTFIELDS] = $request->body;
        }
        curl_setopt_array($handle, $options);

        $ok = curl_exec($handle);
        $errno = curl_errno($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        // A fresh-connection handle is dropped here (FORBID_REUSE already closed its connection); any other
        // is kept so the next read can reuse its connection.
        if (!$request->freshConnection) {
            $this->handle = $handle;
        }

        if ($tooLarge) {
            throw new TransportError(sprintf('the response is larger than %d bytes', $this->maxResponseBytes), 'unknown', $errno);
        }
        if ($ok === false || $errno !== 0) {
            $sent = TransportErrors::classifyCurlErrno($errno)['sent'];

            throw new TransportError(sprintf('the request failed (curl error %d)', $errno), $sent, $errno);
        }

        return new HttpResponse($status, $headers, $body);
    }
}
