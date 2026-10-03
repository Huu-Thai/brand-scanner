import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HealthIndicatorService } from '@nestjs/terminus';
import type { Redis } from 'ioredis';
import type { AppConfig } from '../config/configuration.js';
import { PrismaService } from '../database/prisma.service.js';
import { REDIS_CLIENT } from '../redis/redis.module.js';
import { StorageService } from '../storage/storage.service.js';

const errMessage = (e: unknown) => (e instanceof Error ? e.message : String(e));

async function timed<T>(
  fn: () => Promise<T>,
): Promise<{ result: T; responseTimeMs: number }> {
  const started = Date.now();
  const result = await fn();
  return { result, responseTimeMs: Date.now() - started };
}

/** Dependency checks for /health. Each returns up/down without throwing secrets into the body. */
@Injectable()
export class HealthIndicators {
  constructor(
    private readonly indicator: HealthIndicatorService,
    private readonly prisma: PrismaService,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
    private readonly storage: StorageService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async database() {
    const check = this.indicator.check('database');
    try {
      const { responseTimeMs } = await timed(
        () => this.prisma.$queryRaw`SELECT 1`,
      );
      return check.up({ responseTimeMs });
    } catch (e) {
      return check.down({ message: errMessage(e) });
    }
  }

  async redisPing() {
    const check = this.indicator.check('redis');
    try {
      if (this.redis.status === 'wait') await this.redis.connect();
      const { result, responseTimeMs } = await timed(() => this.redis.ping());
      return result === 'PONG'
        ? check.up({ responseTimeMs, authenticated: true })
        : check.down({ message: result });
    } catch (e) {
      return check.down({ message: errMessage(e) });
    }
  }

  async objectStorage() {
    const check = this.indicator.check('storage');
    try {
      const { responseTimeMs } = await timed(() => this.storage.ping());
      return check.up({ bucket: this.storage.bucket, responseTimeMs });
    } catch (e) {
      return check.down({
        bucket: this.storage.bucket,
        message: errMessage(e),
      });
    }
  }

  async selenium() {
    const check = this.indicator.check('selenium');
    const { url } = this.config.get('selenium', { infer: true });
    try {
      const res = await fetch(new URL('/status', url), {
        signal: AbortSignal.timeout(3_000),
      });
      const body = (await res.json()) as {
        value?: { ready?: boolean; message?: string };
      };
      return body.value?.ready
        ? check.up({ message: body.value.message })
        : check.down({ message: body.value?.message ?? `HTTP ${res.status}` });
    } catch (e) {
      return check.down({ message: errMessage(e) });
    }
  }
}
