import { RateLimitOptions } from '../types.js';

interface ClientBucket {
  tokens: number;
  lastRefill: number;
}

/**
 * Lightweight sliding-window token-bucket rate limiter.
 * Edge and Node memory compliant with automatic TTL eviction.
 */
export class RateLimiter {
  private buckets = new Map<string, ClientBucket>();
  private requestsPerMinute: number;
  private burstLimit: number;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(options: RateLimitOptions = {}) {
    this.requestsPerMinute = options.requestsPerMinute || 120;
    this.burstLimit = options.burstLimit || this.requestsPerMinute;

    // Prune stale entries every 5 minutes if supported
    if (typeof setInterval !== 'undefined') {
      this.cleanupInterval = setInterval(() => this.pruneStale(), 5 * 60 * 1000);
      if (this.cleanupInterval && typeof this.cleanupInterval.unref === 'function') {
        this.cleanupInterval.unref();
      }
    }
  }

  public check(clientIp: string): { allowed: boolean; remaining: number } {
    if (!clientIp) return { allowed: true, remaining: this.burstLimit };

    const now = Date.now();
    let bucket = this.buckets.get(clientIp);

    if (!bucket) {
      bucket = { tokens: this.burstLimit, lastRefill: now };
      this.buckets.set(clientIp, bucket);
    }

    // Refill rate: tokens per millisecond
    const timePassed = now - bucket.lastRefill;
    const refillAmount = timePassed * (this.requestsPerMinute / 60000);

    bucket.tokens = Math.min(this.burstLimit, bucket.tokens + refillAmount);
    bucket.lastRefill = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, remaining: Math.floor(bucket.tokens) };
    }

    return { allowed: false, remaining: 0 };
  }

  private pruneStale(): void {
    const now = Date.now();
    for (const [ip, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > 10 * 60 * 1000) {
        this.buckets.delete(ip);
      }
    }
  }
}
