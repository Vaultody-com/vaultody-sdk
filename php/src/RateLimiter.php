<?php

declare(strict_types=1);

namespace Vaultody\Sdk;

/**
 * A token bucket: at most $perSecond requests per second on average, bursts up to $burst. It is per client
 * object (under PHP-FPM, per request), so the gateway's 429 and the retry backoff remain the backstop.
 */
final class RateLimiter
{
    private float $tokens;
    private ?float $updatedAt = null;

    /**
     * @param callable(): float $now monotonic seconds
     * @param callable(int): void $sleepMs
     */
    public function __construct(
        private readonly float $perSecond,
        private readonly float $burst,
        private $now,
        private $sleepMs,
    ) {
        if ($perSecond <= 0 || $burst < 1) {
            throw new Exception\ConfigurationError('maxRequestsPerSecond must be above 0');
        }
        $this->tokens = $burst;
    }

    /** Waits until a request may go out, and takes its token. */
    public function take(): void
    {
        while (true) {
            $now = ($this->now)();
            if ($this->updatedAt !== null) {
                $this->tokens = min($this->burst, $this->tokens + ($now - $this->updatedAt) * $this->perSecond);
            }
            $this->updatedAt = $now;
            if ($this->tokens >= 1) {
                $this->tokens -= 1;

                return;
            }
            ($this->sleepMs)((int) ceil((1 - $this->tokens) / $this->perSecond * 1000));
        }
    }
}
