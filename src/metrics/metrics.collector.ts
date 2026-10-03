import { getQueueToken } from '@nestjs/bullmq';
import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import type { Queue } from 'bullmq';
import type { Redis } from 'ioredis';
import { PrismaService } from '../database/prisma.service.js';
import { ALL_QUEUES } from '../queue/queue.constants.js';
import { REDIS_CLIENT } from '../redis/redis.module.js';
import {
  lastRetentionRun,
  outboxDeadLetters,
  outboxOldestPending,
  outboxPending,
  queueJobs,
  queueOldestWaiting,
  registry,
  scansByStatus,
} from './metrics.js';

const STATES = [
  'waiting',
  'active',
  'delayed',
  'failed',
  'prioritized',
  'waiting-children',
] as const;

/**
 * Refreshes scrape-time gauges (queue depth / lag, scans, outbox, retention) right before each
 * scrape. Failures only skip the refresh — /metrics must keep answering while a dependency is down.
 */
@Injectable()
export class MetricsCollector implements OnModuleInit {
  private readonly logger = new Logger(MetricsCollector.name);
  private queues: Queue[] = [];

  constructor(
    private readonly moduleRef: ModuleRef,
    private readonly prisma: PrismaService,
    @Inject(REDIS_CLIENT) private readonly redis: Redis,
  ) {}

  onModuleInit(): void {
    this.queues = ALL_QUEUES.flatMap((name) => {
      try {
        return [
          this.moduleRef.get<Queue>(getQueueToken(name), { strict: false }),
        ];
      } catch {
        return [];
      }
    });
  }

  /** Serialises the registry after refreshing scrape-time gauges. */
  async scrape(): Promise<{ contentType: string; body: string }> {
    await Promise.allSettled([
      this.collectQueues(),
      this.collectDatabase(),
      this.collectRetention(),
    ]);
    return {
      contentType: registry.contentType,
      body: await registry.metrics(),
    };
  }

  private async collectQueues(): Promise<void> {
    await Promise.all(
      this.queues.map(async (q) => {
        const counts = await q.getJobCounts(...STATES);
        for (const state of STATES)
          queueJobs.set({ queue: q.name, state }, counts[state] ?? 0);
        const [oldest] = await q.getJobs(
          ['waiting', 'prioritized'],
          0,
          0,
          true,
        );
        queueOldestWaiting.set(
          { queue: q.name },
          oldest ? Math.max(0, (Date.now() - oldest.timestamp) / 1000) : 0,
        );
      }),
    ).catch((e: Error) =>
      this.logger.debug(`queue metrics skipped: ${e.message}`),
    );
  }

  private async collectDatabase(): Promise<void> {
    try {
      const [scans, pending, oldest, dead] = await Promise.all([
        this.prisma.scan.groupBy({ by: ['status'], _count: { _all: true } }),
        this.prisma.outboxEvent.groupBy({
          by: ['origin'],
          where: { failedAt: null },
          _count: { _all: true },
        }),
        this.prisma.outboxEvent.findFirst({
          where: { failedAt: null },
          orderBy: { createdAt: 'asc' },
          select: { createdAt: true },
        }),
        this.prisma.outboxEvent.count({ where: { failedAt: { not: null } } }),
      ]);
      scansByStatus.reset();
      for (const s of scans)
        scansByStatus.set({ status: s.status }, s._count._all);
      outboxPending.reset();
      for (const o of pending)
        outboxPending.set({ origin: o.origin }, o._count._all);
      outboxOldestPending.set(
        oldest ? (Date.now() - oldest.createdAt.getTime()) / 1000 : 0,
      );
      outboxDeadLetters.set(dead);
    } catch (e) {
      this.logger.debug(`database metrics skipped: ${(e as Error).message}`);
    }
  }

  private async collectRetention(): Promise<void> {
    const raw = await this.redis.get('retention:last-run').catch(() => null);
    if (!raw) return;
    const finishedAt = Date.parse(
      (JSON.parse(raw) as { finishedAt?: string }).finishedAt ?? '',
    );
    if (Number.isFinite(finishedAt)) lastRetentionRun.set(finishedAt / 1000);
  }
}
