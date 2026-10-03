import { Reflector } from '@nestjs/core';
import { ScansController } from '../../modules/scans/scans.controller.js';
import { ApiKeyThrottlerGuard } from './api-key-throttler.guard.js';

class Probe extends ApiKeyThrottlerGuard {
  tracker(req: Record<string, unknown>) {
    return this.getTracker(req);
  }
}

describe('ApiKeyThrottlerGuard', () => {
  const guard = new Probe(
    { throttlers: [] } as never,
    {} as never,
    new Reflector(),
  );

  it('buckets authenticated requests per API key, public ones per IP', async () => {
    expect(
      await guard.tracker({
        principal: { name: 'manage-feed' },
        ip: '10.0.0.1',
      }),
    ).toBe('key:manage-feed');
    expect(await guard.tracker({ ip: '10.0.0.1' })).toBe('ip:10.0.0.1');
  });

  it('marks expensive routes with a configurable per-route limit', () => {
    const limit = Reflect.getMetadata(
      'THROTTLER:LIMITdefault',
      ScansController.prototype.create,
    );
    expect(typeof limit).toBe('function');
    process.env.THROTTLE_EXPENSIVE_LIMIT = '3';
    expect(limit()).toBe(3);
    delete process.env.THROTTLE_EXPENSIVE_LIMIT;
    expect(limit()).toBe(10);
  });
});
