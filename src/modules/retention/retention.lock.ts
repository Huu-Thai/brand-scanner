import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import type { Redis } from 'ioredis';
import { REDIS_CLIENT } from '../../redis/redis.module.js';

const RELEASE = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`;

/** Single-holder Redis lock so two workers never run retention (or the sweep) at once. */
@Injectable()
export class RetentionLock {
  constructor(@Inject(REDIS_CLIENT) private readonly redis: Redis) {}

  async withLock<T>(
    name: string,
    ttlMs: number,
    fn: () => Promise<T>,
  ): Promise<T | null> {
    const key = `lock:${name}`;
    const token = randomUUID();
    if ((await this.redis.set(key, token, 'PX', ttlMs, 'NX')) !== 'OK')
      return null;
    try {
      return await fn();
    } finally {
      await this.redis.eval(RELEASE, 1, key, token).catch(() => undefined);
    }
  }
}
