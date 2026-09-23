export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

/** In-process per-user limiter; production replicas should apply the same limit at the edge. */
export class UserRateLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(private readonly maxRequests = 60, private readonly windowMs = 60_000) {}

  check(userId: string, now = Date.now()): RateLimitResult {
    const key = userId || "anonymous";
    const recent = (this.hits.get(key) || []).filter((timestamp) => now - timestamp < this.windowMs);
    if (recent.length >= this.maxRequests) {
      const retryAfterSeconds = Math.max(1, Math.ceil((recent[0] + this.windowMs - now) / 1000));
      this.hits.set(key, recent);
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }
    recent.push(now);
    this.hits.set(key, recent);
    return { allowed: true, remaining: Math.max(0, this.maxRequests - recent.length), retryAfterSeconds: 0 };
  }
}
