/** The host's window is full for longer than the caller is willing to wait. */
export class HostBusyError extends Error {
  constructor(
    readonly host: string,
    readonly retryAfterMs: number,
  ) {
    super(`${host} rate window full; retry in ${retryAfterMs} ms`);
  }
}

/**
 * Per-host sliding-window limiter + global concurrency cap (Reporting: RDAP stays under
 * Cloudflare's 10 req / 10 s with 8 per 11 s and 8 in flight).
 */
export class HostRateLimiter {
  private inFlight = 0;
  private readonly waiting: (() => void)[] = [];
  private readonly windows = new Map<string, number[]>();

  constructor(
    private readonly maxConcurrent = 8,
    private readonly maxPerWindow = 8,
    private readonly windowMs = 11_000,
    private readonly sleep: (ms: number) => Promise<void> = (ms) =>
      new Promise((r) => setTimeout(r, ms)),
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * Runs `fn` within the host's window. The window is reserved BEFORE taking a concurrency slot,
   * so callers waiting on one busy host never block calls to other hosts. With `maxWaitMs`, a
   * caller that would have to wait longer gets a HostBusyError instead (the WHOIS processor turns
   * that into a delayed job, freeing its worker slot).
   */
  async run<T>(
    host: string,
    fn: () => Promise<T>,
    maxWaitMs?: number,
  ): Promise<T> {
    await this.waitForWindow(host, maxWaitMs);
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.inFlight < this.maxConcurrent) {
      this.inFlight++;
      return Promise.resolve();
    }
    return new Promise((resolve) =>
      this.waiting.push(() => {
        this.inFlight++;
        resolve();
      }),
    );
  }

  private release(): void {
    this.inFlight--;
    this.waiting.shift()?.();
  }

  private async waitForWindow(host: string, maxWaitMs?: number): Promise<void> {
    for (;;) {
      const now = this.now();
      const stamps = (this.windows.get(host) ?? []).filter(
        (t) => t > now - this.windowMs,
      );
      if (stamps.length < this.maxPerWindow) {
        stamps.push(now);
        this.windows.set(host, stamps);
        return;
      }
      const waitMs = stamps[0] + this.windowMs - now + 1;
      if (maxWaitMs !== undefined && waitMs > maxWaitMs)
        throw new HostBusyError(host, waitMs);
      await this.sleep(waitMs);
    }
  }
}
