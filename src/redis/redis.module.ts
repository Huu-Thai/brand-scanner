import { Global, Inject, Module, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';
import type { AppConfig } from '../config/configuration.js';
import { buildRedisOptions } from './redis.options.js';

export const REDIS_CLIENT = Symbol('REDIS_CLIENT');

/** Shared authenticated Redis client for cache/health use (BullMQ manages its own connections). */
@Global()
@Module({
  providers: [
    {
      provide: REDIS_CLIENT,
      inject: [ConfigService],
      useFactory: (config: ConfigService<AppConfig, true>) =>
        new Redis({
          ...buildRedisOptions(config.get('redis', { infer: true }), 'cache'),
          lazyConnect: true,
        }),
    },
  ],
  exports: [REDIS_CLIENT],
})
export class RedisModule implements OnApplicationShutdown {
  constructor(@Inject(REDIS_CLIENT) private readonly client: Redis) {}

  async onApplicationShutdown(): Promise<void> {
    if (this.client.status !== 'end')
      await this.client.quit().catch(() => undefined);
  }
}
