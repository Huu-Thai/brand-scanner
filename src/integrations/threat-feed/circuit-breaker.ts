/**
 * Minimal circuit breaker: after `threshold` consecutive failures the circuit opens for
 * `cooldownMs`; calls fail fast with CircuitOpenError until a trial call succeeds.
 */
export class CircuitOpenError extends Error {
  constructor() {
    super('circuit open');
  }
}

export class CircuitBreaker {
  private failures = 0;
  private openUntil = 0;

  constructor(
    private readonly threshold = 5,
    private readonly cooldownMs = 60_000,
    private readonly now: () => number = Date.now,
  ) {}

  get isOpen(): boolean {
    return this.now() < this.openUntil;
  }

  async exec<T>(fn: () => Promise<T>): Promise<T> {
    if (this.isOpen) throw new CircuitOpenError();
    try {
      const result = await fn();
      this.failures = 0;
      return result;
    } catch (e) {
      if (++this.failures >= this.threshold) {
        this.openUntil = this.now() + this.cooldownMs;
        this.failures = 0;
      }
      throw e;
    }
  }
}
