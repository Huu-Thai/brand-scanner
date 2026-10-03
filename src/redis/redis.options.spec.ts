import type { AppConfig } from '../config/configuration.js';
import { buildRedisOptions } from './redis.options.js';

const redis: AppConfig['redis'] = {
  host: 'redis',
  port: 6379,
  username: 'fuzzer',
  password: 'secret-password',
  tls: false,
  queueDb: 0,
  cacheDb: 1,
};

describe('buildRedisOptions', () => {
  it('always includes credentials and picks the db per purpose', () => {
    expect(buildRedisOptions(redis, 'queue')).toMatchObject({
      host: 'redis',
      username: 'fuzzer',
      password: 'secret-password',
      db: 0,
      maxRetriesPerRequest: null,
      connectionName: 'fuzzer-scanner:queue',
    });
    expect(buildRedisOptions(redis, 'cache').db).toBe(1);
  });

  it('enables TLS when configured', () => {
    expect(buildRedisOptions({ ...redis, tls: true }, 'queue').tls).toEqual({});
    expect(buildRedisOptions(redis, 'queue').tls).toBeUndefined();
  });

  it('refuses to build an unauthenticated connection', () => {
    expect(() =>
      buildRedisOptions({ ...redis, password: '' }, 'queue'),
    ).toThrow(/REDIS_PASSWORD/);
  });

  it('backs off reconnects up to 5 seconds', () => {
    const { retryStrategy } = buildRedisOptions(redis, 'queue');
    expect(retryStrategy(1)).toBe(200);
    expect(retryStrategy(100)).toBe(5_000);
  });
});
