import { CircuitBreaker, CircuitOpenError } from './circuit-breaker.js';

describe('CircuitBreaker', () => {
  it('opens after N consecutive failures, fails fast, and closes after the cooldown', async () => {
    let now = 0;
    const breaker = new CircuitBreaker(2, 1_000, () => now);
    const fail = () => Promise.reject(new Error('down'));
    await expect(breaker.exec(fail)).rejects.toThrow('down');
    await expect(breaker.exec(fail)).rejects.toThrow('down');
    expect(breaker.isOpen).toBe(true);
    const spy = vi.fn(async () => 'ok');
    await expect(breaker.exec(spy)).rejects.toBeInstanceOf(CircuitOpenError);
    expect(spy).not.toHaveBeenCalled();
    now = 1_001;
    expect(await breaker.exec(spy)).toBe('ok');
  });

  it('a success resets the failure count', async () => {
    const breaker = new CircuitBreaker(2, 1_000);
    await expect(
      breaker.exec(() => Promise.reject(new Error('x'))),
    ).rejects.toThrow();
    await breaker.exec(async () => 1);
    await expect(
      breaker.exec(() => Promise.reject(new Error('x'))),
    ).rejects.toThrow();
    expect(breaker.isOpen).toBe(false);
  });
});
