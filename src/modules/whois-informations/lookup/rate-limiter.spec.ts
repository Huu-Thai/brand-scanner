import { HostRateLimiter } from './rate-limiter.js';

describe('HostRateLimiter', () => {
  it('caps requests per host per window, independently per host', async () => {
    let now = 0;
    const sleeps: number[] = [];
    const limiter = new HostRateLimiter(
      10,
      2,
      1_000,
      async (ms) => {
        sleeps.push(ms);
        now += ms;
      },
      () => now,
    );
    await limiter.run('a', async () => 1);
    await limiter.run('a', async () => 1);
    await limiter.run('b', async () => 1); // other host: no wait
    expect(sleeps).toEqual([]);
    await limiter.run('a', async () => 1); // third in window → waits for the oldest to expire
    expect(sleeps).toEqual([1_001]);
  });

  it('caps concurrency and releases slots on failure', async () => {
    const limiter = new HostRateLimiter(1, 100, 1_000);
    let running = 0;
    let peak = 0;
    const task = async () => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, 5));
      running--;
    };
    await Promise.all([
      limiter.run('h', task),
      limiter.run('h', task),
      limiter
        .run('h', async () => Promise.reject(new Error('x')))
        .catch(() => 0),
    ]);
    expect(peak).toBe(1);
    await expect(limiter.run('h', async () => 'still works')).resolves.toBe(
      'still works',
    );
  });
});

describe('HostRateLimiter (busy hosts)', () => {
  it('raises HostBusyError instead of sleeping beyond maxWaitMs', async () => {
    let now = 0;
    const limiter = new HostRateLimiter(
      10,
      1,
      11_000,
      async () => undefined,
      () => now,
    );
    await limiter.run('rdap.verisign.com', async () => 1, 1_000);
    await expect(
      limiter.run('rdap.verisign.com', async () => 1, 1_000),
    ).rejects.toMatchObject({
      name: 'Error',
      host: 'rdap.verisign.com',
      retryAfterMs: 11_001,
    });
    expect(await limiter.run('rdap.nic.io', async () => 2, 1_000)).toBe(2);
    now = 11_001;
    expect(await limiter.run('rdap.verisign.com', async () => 3, 1_000)).toBe(
      3,
    );
  });

  it('does not hold a concurrency slot while waiting for a busy host', async () => {
    let releaseSleep!: () => void;
    let now = 0;
    const limiter = new HostRateLimiter(
      1,
      1,
      1_000,
      () =>
        new Promise<void>((r) => (releaseSleep = () => ((now += 1_000), r()))),
      () => now,
    );
    await limiter.run('busy', async () => 1);
    const waiting = limiter.run('busy', async () => 'late'); // sleeps for the window
    expect(await limiter.run('other', async () => 'free')).toBe('free'); // single slot still free
    releaseSleep();
    expect(await waiting).toBe('late');
  });
});
