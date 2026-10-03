import { EventEmitter } from 'node:events';
import { WorkerHost } from '@nestjs/bullmq';
import { UnauthorizedException } from '@nestjs/common';
import { EventMetricsListener } from './event-metrics.listener.js';
import { HttpMetricsMiddleware } from './http-metrics.middleware.js';
import { JobMetricsBinder } from './job-metrics.binder.js';
import { MetricsCollector } from './metrics.collector.js';
import { authorized, MetricsController } from './metrics.controller.js';
import { registry } from './metrics.js';
import { WorkerMetricsServer } from './worker-metrics.server.js';

const value = async (name: string, labels: Record<string, string> = {}) => {
  const metric = (await registry.getMetricsAsJSON()).find(
    (m) => m.name === name,
  );
  const v = metric?.values.find((x) =>
    Object.entries(labels).every(([k, l]) => x.labels[k] === l),
  );
  return v?.value;
};

function collector(opts: { failDb?: boolean } = {}) {
  const queue = {
    name: 'whois',
    getJobCounts: vi.fn(async () => ({
      waiting: 4,
      active: 1,
      delayed: 0,
      failed: 2,
      prioritized: 0,
      'waiting-children': 0,
    })),
    getJobs: vi.fn(async () => [{ timestamp: Date.now() - 90_000 }]),
  };
  const prisma = {
    scan: {
      groupBy: vi.fn(async () => [
        { status: 'COMPLETED', _count: { _all: 7 } },
      ]),
    },
    outboxEvent: {
      groupBy: vi.fn(async () => {
        if (opts.failDb) throw new Error('db down');
        return [{ origin: 'api', _count: { _all: 3 } }];
      }),
      findFirst: vi.fn(async () => ({
        createdAt: new Date(Date.now() - 60_000),
      })),
      count: vi.fn(async () => 1),
    },
  };
  const redis = {
    get: vi.fn(async () =>
      JSON.stringify({ finishedAt: '2026-10-02T03:31:00.000Z' }),
    ),
  };
  const moduleRef = {
    get: vi.fn((token: unknown) => {
      if (String(token).includes('whois')) return queue;
      throw new Error('not registered');
    }),
  };
  const c = new MetricsCollector(
    moduleRef as never,
    prisma as never,
    redis as never,
  );
  c.onModuleInit();
  return c;
}

describe('metrics', () => {
  it('refreshes queue, scan, outbox and retention gauges on scrape', async () => {
    const { body, contentType } = await collector().scrape();
    expect(contentType).toMatch(/text\/plain/);
    expect(body).toContain(
      'fuzzer_queue_jobs{queue="whois",state="waiting"} 4',
    );
    expect(
      await value('fuzzer_queue_oldest_waiting_seconds', { queue: 'whois' }),
    ).toBeGreaterThanOrEqual(89);
    expect(await value('fuzzer_scans', { status: 'COMPLETED' })).toBe(7);
    expect(await value('fuzzer_outbox_pending', { origin: 'api' })).toBe(3);
    expect(await value('fuzzer_outbox_dead_letters')).toBe(1);
    expect(await value('fuzzer_retention_last_success_timestamp_seconds')).toBe(
      Date.parse('2026-10-02T03:31:00Z') / 1000,
    );
  });

  it('still answers when the database is down', async () => {
    const { body } = await collector({ failDb: true }).scrape();
    expect(body).toContain('fuzzer_');
  });

  it('records request latency by route template, never raw paths', async () => {
    const res = new EventEmitter() as EventEmitter & { statusCode: number };
    res.statusCode = 200;
    const next = vi.fn();
    new HttpMetricsMiddleware().use(
      {
        method: 'GET',
        baseUrl: '',
        route: { path: '/api/v1/scanned-domains/:id' },
      } as never,
      res as never,
      next,
    );
    res.emit('finish');
    expect(next).toHaveBeenCalled();
    const text = await registry.getSingleMetricAsString(
      'fuzzer_http_request_duration_seconds',
    );
    expect(text).toContain(
      'fuzzer_http_request_duration_seconds_count{method="GET",route="/api/v1/scanned-domains/:id",status="200"} 1',
    );
  });

  it('counts finished jobs for every worker in the process', async () => {
    class Proc extends WorkerHost {
      process = vi.fn();
    }
    const host = new Proc();
    const worker = new EventEmitter() as EventEmitter & { name: string };
    worker.name = 'analytics';
    Object.defineProperty(host, 'worker', { get: () => worker });
    new JobMetricsBinder({
      getProviders: () => [{ instance: host }, { instance: {} }],
    } as never).onApplicationBootstrap();
    worker.emit('completed', { processedOn: 1_000, finishedOn: 1_500 });
    worker.emit('failed', undefined);
    expect(
      await value('fuzzer_jobs_total', {
        queue: 'analytics',
        status: 'completed',
      }),
    ).toBe(1);
    expect(
      await value('fuzzer_jobs_total', {
        queue: 'analytics',
        status: 'failed',
      }),
    ).toBe(1);
  });

  it('derives domain counters from events', async () => {
    const l = new EventMetricsListener();
    l.captured();
    l.captureFailed();
    l.whoisCreated();
    l.whoisFailed();
    l.purged({ table: 'scans', rows: 5, objects: 2 } as never);
    expect(
      await value('fuzzer_screenshots_total', { result: 'captured' }),
    ).toBe(1);
    expect(
      await value('fuzzer_whois_lookups_total', { result: 'failed' }),
    ).toBe(1);
    expect(
      await value('fuzzer_retention_rows_purged_total', { table: 'scans' }),
    ).toBe(5);
    expect(await value('fuzzer_retention_objects_deleted_total')).toBe(2);
  });

  it('protects /metrics with a bearer token when configured', async () => {
    expect(authorized(undefined, undefined)).toBe(true);
    expect(
      authorized('s3cret-token-0123456', 'Bearer s3cret-token-0123456'),
    ).toBe(true);
    expect(authorized('s3cret-token-0123456', 'Bearer nope')).toBe(false);
    const res = { setHeader: vi.fn(), send: vi.fn() };
    const scrape = vi.fn(async () => ({
      contentType: 'text/plain',
      body: 'x 1',
    }));
    const ctrl = new MetricsController(
      { scrape } as never,
      { get: () => ({ token: 's3cret-token-0123456' }) } as never,
    );
    await expect(ctrl.scrape(undefined, res as never)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    await ctrl.scrape('Bearer s3cret-token-0123456', res as never);
    expect(res.send).toHaveBeenCalledWith('x 1');
  });

  it('keeps the worker running when the metrics port is taken', async () => {
    const { createServer } = await import('node:http');
    const blocker = createServer();
    await new Promise<void>((r) => blocker.listen(0, r));
    const port = (blocker.address() as { port: number }).port;
    const worker = new WorkerMetricsServer(
      { scrape: vi.fn() } as never,
      {
        get: (k: string) => (k === 'processRole' ? 'worker' : { port }),
      } as never,
    );
    await expect(worker.onApplicationBootstrap()).resolves.toBeUndefined();
    await worker.onApplicationShutdown();
    await new Promise((r) => blocker.close(r));
  });

  it('serves worker metrics on its own port only in the worker role', async () => {
    const scrape = vi.fn(async () => ({
      contentType: 'text/plain',
      body: 'fuzzer_up 1',
    }));
    const api = new WorkerMetricsServer(
      { scrape } as never,
      {
        get: (k: string) => (k === 'processRole' ? 'api' : { port: 9 }),
      } as never,
    );
    await api.onApplicationBootstrap();
    await api.onApplicationShutdown();

    const port = 40_000 + Math.floor(Math.random() * 10_000);
    const worker = new WorkerMetricsServer(
      { scrape } as never,
      {
        get: (k: string) => (k === 'processRole' ? 'worker' : { port }),
      } as never,
    );
    await worker.onApplicationBootstrap();
    const ok = await fetch(`http://127.0.0.1:${port}/metrics`);
    expect(await ok.text()).toBe('fuzzer_up 1');
    expect((await fetch(`http://127.0.0.1:${port}/other`)).status).toBe(404);
    await worker.onApplicationShutdown();
  });
});
