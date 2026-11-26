<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

/**
 * Whether and how to try a call again after one attempt, without I/O (test-vectors/retry-v1.json).
 *
 * The rule that matters most: a write is never signed again with a new nonce once any attempt of it may
 * have reached the gateway, because the gateway's replay protection recognises a duplicate only by its
 * nonce. A resend of the same signed request is safe: within about 3 s the gateway answers it with the first
 * request's answer (x-api-replayed), later it refuses it (duplicate_api_request). Where the outcome can't be
 * learned, the caller gets RequestOutcomeUnknownError instead of a second transfer.
 *
 * Every retry of a write keeps the call's x-api-nonce (and its body): a resend is the same signed request, and a
 * re-signed write gets a fresh x-api-timestamp and fresh signatures over the same nonce, so the gateway's
 * idempotency (per API key and nonce) always sees one operation. One exception: the one immediate retry after
 * address_derivation_conflict or vault_accounts_creation_failed, which say that nothing was executed, is signed
 * again with a new nonce and the same body; with the same nonce the gateway would only replay the 409. A read
 * re-signed gets a new nonce. `nonce` in a retry decision says which: 'same' or 'new'.
 */
final class Retry
{
    public const MAX_ATTEMPTS = 5;
    public const BASE_DELAY_MS = 1000;
    public const MAX_DELAY_MS = 8000;
    public const DEADLINE_MS = 30000;
    /** The gateway replays the first answer to a duplicate for 3 s; resend only well inside that. */
    public const RESEND_WINDOW_MS = 2500;
    /** A signature is accepted for about 30 s (+10 s drift); a resend must arrive before that. */
    public const SIGNATURE_MAX_AGE_MS = 25000;

    /** The conflicts the docs say to retry at once: collisions with no side effect. */
    public const CONFLICT_RETRY_CODES = ['address_derivation_conflict', 'vault_accounts_creation_failed'];

    /** @return array<string, int> the constants, as test-vectors/retry-v1.json names them */
    public static function constants(): array
    {
        return [
            'maxAttempts' => self::MAX_ATTEMPTS,
            'baseDelayMs' => self::BASE_DELAY_MS,
            'maxDelayMs' => self::MAX_DELAY_MS,
            'deadlineMs' => self::DEADLINE_MS,
            'resendWindowMs' => self::RESEND_WINDOW_MS,
            'signatureMaxAgeMs' => self::SIGNATURE_MAX_AGE_MS,
        ];
    }

    /** Full jitter: a random delay up to min(cap, base x 2^(attempt - 1)), raised to a longer Retry-After. */
    public static function backoffMs(int $attempt, float $random, int|float|null $retryAfterSeconds): int
    {
        $ceiling = min(self::MAX_DELAY_MS, self::BASE_DELAY_MS * (2 ** max(0, $attempt - 1)));
        $jitter = (int) floor($random * $ceiling);
        $asked = $retryAfterSeconds !== null && $retryAfterSeconds > 0 ? (int) ceil($retryAfterSeconds * 1000) : 0;

        return max($jitter, $asked);
    }

    /**
     * @param array{operation: 'read'|'write', keyMode: 'keypair'|'legacy', attempt: int, elapsedMs: int|float, signedAgeMs: int|float,
     *              sinceFirstSendMs: int|float, resends: int, mayHaveRun: bool, conflictRetried: bool, random: float,
     *              outcome: array{type: string, status?: int, code?: ?string, replayed?: bool, retryAfterSeconds?: int|float|null}} $input
     *        keyMode keypair only when the key pair was confirmed active, so the gateway's replay protection is
     *        enforced; outcome type not_sent, sent_unknown, verification_failed or response
     * @return array{action: 'return'|'fail'}|array{action: 'retry', mode: 'resign'|'resend', nonce: 'same'|'new', delayMs: int}|array{action: 'outcome_unknown', inProgress: bool}
     */
    public static function decide(array $input): array
    {
        $isWrite = $input['operation'] === 'write';
        $outcome = $input['outcome'];
        $isResponse = $outcome['type'] === 'response';
        $status = $isResponse ? (int) $outcome['status'] : null;
        $code = $isResponse ? ($outcome['code'] ?? null) : null;
        $attempt = $input['attempt'];
        $elapsedMs = $input['elapsedMs'];
        $mayHaveRun = $input['mayHaveRun'];

        if ($outcome['type'] === 'verification_failed') {
            return ['action' => 'fail'];
        }
        if ($isResponse && $status >= 200 && $status <= 299) {
            return ['action' => 'return'];
        }

        $thisMayHaveRun = $outcome['type'] === 'sent_unknown' || ($isResponse && self::isServerError($status));
        $anyMayHaveRun = $mayHaveRun || $thisMayHaveRun;
        // What happens when no (further) retry is made
        $stop = static function () use ($isWrite, $anyMayHaveRun, $isResponse): array {
            if ($isWrite && $anyMayHaveRun) {
                return ['action' => 'outcome_unknown', 'inProgress' => false];
            }

            return ['action' => $isResponse ? 'return' : 'fail'];
        };
        $retry = static function (string $mode, int $delayMs, bool $newNonce = false) use ($attempt, $elapsedMs, $stop, $isWrite): array {
            if ($attempt >= self::MAX_ATTEMPTS || $elapsedMs + $delayMs > self::DEADLINE_MS) {
                return $stop();
            }

            return ['action' => 'retry', 'mode' => $mode, 'nonce' => $isWrite && !$newNonce ? 'same' : 'new', 'delayMs' => $delayMs];
        };

        if ($isWrite && $isResponse) {
            if ($code === 'duplicate_api_request_in_progress') {
                return ['action' => 'outcome_unknown', 'inProgress' => true];
            }
            if ($code === 'duplicate_api_request' && $input['resends'] > 0) {
                return ['action' => 'outcome_unknown', 'inProgress' => false];
            }
            if (($outcome['replayed'] ?? false) === true && self::isServerError($status)) {
                return ['action' => 'outcome_unknown', 'inProgress' => false];
            }
        }

        if ($isResponse && in_array($code, self::CONFLICT_RETRY_CODES, true)) {
            // Nothing was executed, so the one retry is a new operation: a new nonce, the same body.
            return !$input['conflictRetried'] && !($isWrite && $mayHaveRun) ? $retry('resign', 0, true) : ['action' => 'return'];
        }

        $transient = !$isResponse || $status === 429 || self::isServerError($status);
        if (!$transient) {
            return ['action' => 'return'];
        }

        $delayMs = self::backoffMs($attempt, $input['random'], $isResponse ? ($outcome['retryAfterSeconds'] ?? null) : null);
        if (!$isWrite) {
            return $retry('resign', $delayMs);
        }

        if ($thisMayHaveRun) {
            // Sent, outcome unknown: only an immediate resend of the same request can still learn it, and only
            // where a duplicate is certainly refused.
            if ($input['keyMode'] === 'keypair' && $input['resends'] === 0 && $input['sinceFirstSendMs'] < self::RESEND_WINDOW_MS) {
                return $retry('resend', 0);
            }

            return ['action' => 'outcome_unknown', 'inProgress' => false];
        }

        // Not sent, or a 429 (refused before the route): it did not run.
        if ($input['signedAgeMs'] + $delayMs < self::SIGNATURE_MAX_AGE_MS) {
            return $retry('resend', $delayMs);
        }
        if (!$mayHaveRun) {
            return $retry('resign', $delayMs);
        }

        return ['action' => 'outcome_unknown', 'inProgress' => false];
    }

    private static function isServerError(?int $status): bool
    {
        return $status !== null && $status >= 500 && $status <= 599;
    }
}
