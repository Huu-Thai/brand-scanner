import type { ConfigService } from '@nestjs/config';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../../config/configuration.js';
import { ReputationService } from './reputation.service.js';
import type { ThreatFeedClient } from './threat-feed.client.js';

function setup(enabled = true) {
  const store = new Map<string, string>();
  const redis = {
    get: vi.fn(async (k: string) => store.get(k) ?? null),
    set: vi.fn(async (k: string, v: string) => {
      store.set(k, v);
      return 'OK';
    }),
  } as unknown as Redis;
  const client = {
    enabled,
    findActiveIndicator: vi.fn(),
  } as unknown as ThreatFeedClient & {
    findActiveIndicator: ReturnType<typeof vi.fn>;
  };
  const config = {
    get: () => ({ cacheTtlSeconds: 3600, missTtlSeconds: 600 }),
  } as unknown as ConfigService<AppConfig, true>;
  return {
    service: new ReputationService(client, redis, config),
    client,
    redis,
    store,
  };
}

describe('ReputationService', () => {
  it('reports unknown when the integration is disabled', async () => {
    const { service, client } = setup(false);
    expect(await service.check('a.com')).toEqual({
      status: 'unknown',
      reason: 'threat-feed integration disabled',
    });
    expect(client.findActiveIndicator).not.toHaveBeenCalled();
  });

  it('finds a DOMAIN indicator and caches it for the hit TTL', async () => {
    const { service, client, redis } = setup();
    client.findActiveIndicator.mockResolvedValue({
      value: 'a.com',
      severity: 'high',
    });
    expect(await service.check('A.com', '1.2.3.4')).toMatchObject({
      status: 'found',
      indicatorType: 'DOMAIN',
    });
    expect(redis.set).toHaveBeenCalledWith(
      'cache:reputation:DOMAIN:a.com',
      expect.any(String),
      'EX',
      3600,
    );
    await service.check('a.com');
    expect(client.findActiveIndicator).toHaveBeenCalledOnce(); // second call served from cache
  });

  it('falls back to the IPv4 indicator and caches misses with the shorter TTL', async () => {
    const { service, client, redis } = setup();
    client.findActiveIndicator.mockImplementation(async (type: string) =>
      type === 'IPV4' ? { value: '1.2.3.4', severity: 'medium' } : null,
    );
    expect(await service.check('a.com', '1.2.3.4')).toMatchObject({
      status: 'found',
      indicatorType: 'IPV4',
      value: '1.2.3.4',
    });
    expect(redis.set).toHaveBeenCalledWith(
      'cache:reputation:DOMAIN:a.com',
      '{"status":"not_found"}',
      'EX',
      600,
    );
  });

  it('returns unknown (not cached) when threat-feed fails, then fails fast once the circuit opens', async () => {
    const { service, client, store } = setup();
    client.findActiveIndicator.mockRejectedValue(new Error('ECONNREFUSED'));
    for (let i = 0; i < 5; i++)
      expect((await service.check(`d${i}.com`)).status).toBe('unknown');
    expect(store.size).toBe(0);
    expect(await service.check('next.com')).toEqual({
      status: 'unknown',
      reason: 'threat-feed circuit open',
    });
    expect(client.findActiveIndicator).toHaveBeenCalledTimes(5);
  });

  it('reports not_found only when both domain and IP are clean', async () => {
    const { service, client } = setup();
    client.findActiveIndicator.mockResolvedValue(null);
    expect(await service.check('a.com', '9.9.9.9')).toEqual({
      status: 'not_found',
    });
  });
});
