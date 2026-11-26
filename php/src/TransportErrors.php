<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

/**
 * Whether a request that failed on the network may have reached the gateway
 * (test-vectors/transport-errors-v1.json, the php rows). Only a failure that proves the request never left
 * counts as not sent; anything else is 'unknown', and a write in that state is never sent again as new.
 */
final class TransportErrors
{
    /** curl errors that happen before any byte of the request is written. */
    public const NOT_SENT_ERRNOS = [
        6,  // CURLE_COULDNT_RESOLVE_HOST
        7,  // CURLE_COULDNT_CONNECT
        35, // CURLE_SSL_CONNECT_ERROR: the TLS handshake failed
        60, // CURLE_PEER_FAILED_VERIFICATION: the server certificate was refused
    ];

    /** @return array{sent: false|'unknown'} */
    public static function classifyCurlErrno(int $errno): array
    {
        return ['sent' => in_array($errno, self::NOT_SENT_ERRNOS, true) ? false : 'unknown'];
    }
}
