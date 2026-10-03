import { DelayedError } from 'bullmq';
import { HostBusyError } from '../lookup/rate-limiter.js';
import { busyDelayMs, WhoisProcessor } from './whois.processor.js';

describe('WhoisProcessor — busy registry', () => {
  function setup() {
    const lookup = {
      lookup: vi.fn(async () =>
        Promise.reject(new HostBusyError('rdap.verisign.com', 5_000)),
      ),
    };
    const proc = new WhoisProcessor(
      lookup as never,
      { create: vi.fn() } as never,
      { isStale: vi.fn(async () => true) } as never,
      { getForEnrichment: vi.fn(async () => ({ id: 'sd' })) } as never,
      { emit: vi.fn() } as never,
      { get: () => ({ whoisRefreshDays: 7 }) } as never,
    );
    const job = {
      id: 'j1',
      name: 'whois-lookup',
      data: {
        scannedDomainId: 'sd',
        domain: 'paypa1.com',
        scanId: 's1',
      } as Record<string, unknown>,
      updateData: vi.fn(async function (this: { data: unknown }, d: unknown) {
        this.data = d;
      }),
      moveToDelayed: vi.fn(async () => undefined),
    };
    return { proc, job, lookup };
  }

  it('re-parks the job as delayed (no attempt used) and counts the bounce', async () => {
    const { proc, job } = setup();
    const before = Date.now();
    await expect(proc.process(job as never, 'token-1')).rejects.toBeInstanceOf(
      DelayedError,
    );
    expect(job.updateData).toHaveBeenCalledWith(
      expect.objectContaining({ busyBounces: 1 }),
    );
    const [at, token] = job.moveToDelayed.mock.calls[0] as unknown as [
      number,
      string,
    ];
    expect(token).toBe('token-1');
    expect(at).toBeGreaterThanOrEqual(before + 5_000);
    expect(at).toBeLessThanOrEqual(Date.now() + 5_000 + 11_000);
  });

  it('without a lock token, a busy registry is an ordinary retryable failure', async () => {
    const { proc, job } = setup();
    await expect(proc.process(job as never)).rejects.toBeInstanceOf(
      HostBusyError,
    );
    expect(job.moveToDelayed).not.toHaveBeenCalled();
  });

  it('spreads re-parked jobs further with each bounce, capped at 60 s', () => {
    expect(busyDelayMs(1_000, 1, () => 0)).toBe(1_000);
    expect(busyDelayMs(1_000, 1, () => 0.999)).toBe(1_000 + 10_989);
    expect(busyDelayMs(0, 3, () => 0.5)).toBe(22_000);
    expect(busyDelayMs(0, 20, () => 0.5)).toBe(30_000);
  });
});
