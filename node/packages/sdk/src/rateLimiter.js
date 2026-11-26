'use strict';

/**
 * A client-side token bucket: by default 5 requests a second with bursts of 5, the API's per-key limit. It is
 * per client instance, so several instances or processes sharing one API key can still meet a 429, which the
 * retries back off from.
 */
class RateLimiter {
    /**
     * @param {{ perSecond: number, burst?: number, clock: function(): number, sleep: function(number): Promise<void> }} options
     */
    constructor({ perSecond, burst = perSecond, clock, sleep }) {
        this.perSecond = perSecond;
        this.burst = Math.max(1, Math.floor(burst));
        this.clock = clock;
        this.sleep = sleep;
        this.tokens = this.burst;
        this.updatedAt = null;
        // Callers queue in order, so a burst is spread evenly and nobody waits forever.
        this.queue = Promise.resolve();
    }

    refill() {
        const now = this.clock();
        if (this.updatedAt !== null) {
            this.tokens = Math.min(this.burst, this.tokens + ((now - this.updatedAt) / 1000) * this.perSecond);
        }
        this.updatedAt = now;
    }

    /** Resolves when the caller may send one request. */
    take() {
        const turn = this.queue.then(async () => {
            this.refill();
            if (this.tokens < 1) {
                await this.sleep(Math.ceil(((1 - this.tokens) / this.perSecond) * 1000));
                this.refill();
            }
            this.tokens = Math.max(0, this.tokens - 1);
        });
        this.queue = turn.catch(() => {});

        return turn;
    }
}

module.exports = { RateLimiter };
