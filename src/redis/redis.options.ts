import type { AppConfig } from '../config/configuration.js';

/**
 * The only place Redis connection options are built. Every client — BullMQ,
 * cache, health check — goes through here, so none can connect without the
 * password (and ACL username / TLS when configured).
 */
/** Structural subset accepted by both ioredis and BullMQ's `ConnectionOptions`. */
export interface RedisConnectionSettings {
  host: string;
  port: number;
  username?: string;
  password: string;
  db: number;
  tls?: Record<string, never>;
  maxRetriesPerRequest: null;
  enableReadyCheck: boolean;
  connectionName: string;
  retryStrategy: (attempt: number) => number;
}

export function buildRedisOptions(
  redis: AppConfig['redis'],
  purpose: 'queue' | 'cache',
): RedisConnectionSettings {
  if (!redis.password) {
    throw new Error(
      'Refusing to create a Redis connection without REDIS_PASSWORD',
    );
  }
  return {
    host: redis.host,
    port: redis.port,
    username: redis.username,
    password: redis.password,
    db: purpose === 'queue' ? redis.queueDb : redis.cacheDb,
    tls: redis.tls ? {} : undefined,
    // Required by BullMQ for blocking commands; harmless for the cache client.
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
    connectionName: `fuzzer-scanner:${purpose}`,
    retryStrategy: (attempt) => Math.min(attempt * 200, 5_000),
  };
}
