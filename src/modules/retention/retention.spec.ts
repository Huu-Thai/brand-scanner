import { fakeBus } from '../../testing/fake-bus.js';
import { RETENTION_EVENTS } from './events/retention.events.js';
import { RetentionProcessor } from './processors/retention.processor.js';
import { RetentionController } from './retention.controller.js';
import { RetentionLock } from './retention.lock.js';
import { enqueueManual, RetentionScheduler } from './retention.scheduler.js';
import { LAST_RUN_KEY, RetentionService } from './retention.service.js';

const sql = (call: unknown[]) =>
  (call[0] as TemplateStringsArray).join('?').replace(/\s+/g, ' ').trim();
const NOW = new Date('2026-10-02T03:30:00Z');

/**
 * prisma.$queryRaw answers by query shape; tx.$executeRaw records every DELETE.
 * `screenshots` / `deletedDomains` feed the candidate selects once, then return nothing.
 */
function setup(
  opts: {
    screenshots?: { id: string; storage_key: string | null }[];
    deletedDomains?: { id: string }[];
    domainObjects?: { parent: string; key: string }[];
    s3Failed?: string[];
    s3Throws?: boolean;
    executeCounts?: Record<string, number>;
    settings?: Partial<{
      days: number;
      keepLatest: boolean;
      batchSize: number;
    }>;
  } = {},
) {
  const order: string[] = [];
  const executed: string[] = [];
  let shots = opts.screenshots ?? [];
  let domains = opts.deletedDomains ?? [];
  const prisma = {
    $queryRaw: vi.fn(async (...call: unknown[]) => {
      const q = sql(call);
      if (q.includes('FROM screenshots s WHERE s.created_at')) {
        const out = shots;
        shots = [];
        return out;
      }
      if (q.includes('FROM ? WHERE deleted_at')) {
        const out = domains;
        domains = [];
        return out;
      }
      if (q.includes('AS parent')) return opts.domainObjects ?? [];
      return [];
    }),
    screenshot: { findMany: vi.fn(async () => []) },
  };
  const tx = {
    $executeRaw: vi.fn(async (...call: unknown[]) => {
      const q = sql(call);
      executed.push(q);
      order.push(`db:${q.slice(0, 40)}`);
      const hit = Object.entries(opts.executeCounts ?? {}).find(([k]) =>
        q.includes(k),
      );
      if (hit) return hit[1];
      // `… = ANY(${ids})` deletes: report one row per id passed.
      const ids = call.slice(1).find((v) => Array.isArray(v)) as
        unknown[] | undefined;
      return ids?.length ?? 0;
    }),
  };
  const bus = fakeBus(tx);
  const storage = {
    deleteObjects: vi.fn(async (keys: string[]) => {
      order.push(`s3:${keys.join(',')}`);
      if (opts.s3Throws) throw new Error('s3 down');
      const failed = keys.filter((k) => opts.s3Failed?.includes(k));
      return { deleted: keys.filter((k) => !failed.includes(k)), failed };
    }),
    listObjects: vi.fn(),
  };
  const redis = {
    set: vi.fn(async () => 'OK'),
    get: vi.fn(async () => null),
    eval: vi.fn(async () => 1),
  };
  const lock = new RetentionLock(redis as never);
  const config = {
    get: () => ({
      days: 31,
      keepLatest: true,
      batchSize: 5_000,
      cron: '30 3 * * *',
      sweepCron: '0 4 * * 0',
      orphanMinAgeMs: 3_600_000,
      ...opts.settings,
    }),
  };
  const svc = new RetentionService(
    prisma as never,
    bus.bus,
    storage as never,
    lock,
    config as never,
    redis as never,
  );
  return { svc, prisma, tx, bus, storage, redis, order, executed };
}

describe('RetentionService', () => {
  it('purges every table in order with a 31-day cutoff and stores the report', async () => {
    const { svc, executed, redis, bus } = setup({
      executeCounts: {
        'DELETE FROM ? WHERE id IN ( SELECT h.id': 3,
        'DELETE FROM scans': 2,
      },
    });
    const report = await svc.run('schedule', NOW);
    expect(report).toMatchObject({
      requestedBy: 'schedule',
      cutoff: '2026-09-01T03:30:00.000Z', // Oct 2 − 31 days
      keepLatest: true,
      rows: {
        analytics: 3,
        whois_informations: 3,
        scans: 2,
        outbox_events: 0,
        alert_deliveries: 0,
      },
    });
    expect(executed.map((q) => q.split(' ').slice(0, 3).join(' '))).toEqual([
      'DELETE FROM ?', // analytics
      'DELETE FROM ?', // whois
      'DELETE FROM scans',
      'DELETE FROM outbox_events',
      'DELETE FROM alert_deliveries',
    ]);
    expect(executed[2]).toMatch(/'COMPLETED'::"ScanStatus"/);
    expect(bus.beforeNames()).toContain(RETENTION_EVENTS.BEFORE_PURGE);
    expect(
      bus.after.filter((e) => e.name === RETENTION_EVENTS.PURGED),
    ).toHaveLength(3);
    expect(redis.set).toHaveBeenCalledWith(
      LAST_RUN_KEY,
      expect.stringContaining('"scans":2'),
    );
  });

  it('keeps going in batches until a short batch', async () => {
    let calls = 0;
    const { svc, tx } = setup({ settings: { batchSize: 100 } });
    tx.$executeRaw.mockImplementation(async (...call: unknown[]) =>
      sql(call).includes('DELETE FROM scans') ? (++calls < 3 ? 100 : 7) : 0,
    );
    const report = await svc.run('x', NOW);
    expect(report?.rows.scans).toBe(207);
    expect(calls).toBe(3);
  });

  it('deletes screenshot objects BEFORE their rows, and keeps rows whose object failed', async () => {
    const { svc, order, executed, tx } = setup({
      screenshots: [
        { id: '1', storage_key: 'screenshots/a.png' },
        { id: '2', storage_key: 'screenshots/b.png' },
        { id: '3', storage_key: null },
      ],
      s3Failed: ['screenshots/b.png'],
    });
    const report = await svc.run('x', NOW);
    expect(
      order.indexOf('s3:screenshots/a.png,screenshots/b.png'),
    ).toBeLessThan(
      order.findIndex((o) => o.startsWith('db:DELETE FROM screenshots')),
    );
    expect(
      executed.find((q) => q.startsWith('DELETE FROM screenshots')),
    ).toBeDefined();
    const shotDelete = tx.$executeRaw.mock.calls.find((c) =>
      sql(c).startsWith('DELETE FROM screenshots'),
    )!;
    expect(shotDelete[1]).toEqual(['1', '3']);
    expect(report).toMatchObject({
      rows: { screenshots: 2 },
      objectsDeleted: 1,
      objectsFailed: 1,
    });
  });

  it('keeps every row when object storage is unreachable', async () => {
    const { svc, executed } = setup({
      screenshots: [{ id: '1', storage_key: 'screenshots/a.png' }],
      s3Throws: true,
    });
    const report = await svc.run('x', NOW);
    expect(executed.some((q) => q.startsWith('DELETE FROM screenshots'))).toBe(
      false,
    );
    expect(report?.objectsFailed).toBe(1);
  });

  it('honours RETENTION_KEEP_LATEST=false (strict cut-off)', async () => {
    const { svc, prisma, tx } = setup({ settings: { keepLatest: false } });
    await svc.run('x', NOW);
    const history = tx.$executeRaw.mock.calls.find((c) =>
      sql(c).includes('SELECT h.id'),
    )!;
    expect(history).toContain(true); // `${!keepLatest}` short-circuits the keep-latest EXISTS
    const shots = prisma.$queryRaw.mock.calls.find((c) =>
      sql(c).includes('FROM screenshots s'),
    )!;
    expect(shots).toContain(true);
  });

  it('hard-purges soft-deleted parents after removing their objects, skipping blocked ones', async () => {
    const { svc, tx, storage } = setup({
      deletedDomains: [{ id: 'd1' }, { id: 'd2' }],
      domainObjects: [
        { parent: 'd1', key: 'screenshots/o/d1/x.png' },
        { parent: 'd2', key: 'screenshots/o/d2/y.png' },
      ],
      s3Failed: ['screenshots/o/d2/y.png'],
    });
    const report = await svc.run('x', NOW);
    expect(storage.deleteObjects).toHaveBeenCalledWith([
      'screenshots/o/d1/x.png',
      'screenshots/o/d2/y.png',
    ]);
    const purge = tx.$executeRaw.mock.calls.find((c) =>
      sql(c).includes('AND deleted_at IS NOT NULL'),
    )!;
    expect(purge[2]).toEqual(['d1']);
    expect(report?.rows.scanned_domains).toBe(1);
  });

  it('skips the run when another holds the lock', async () => {
    const { svc, redis, tx } = setup();
    redis.set.mockResolvedValueOnce(null as never);
    expect(await svc.run('x', NOW)).toBeNull();
    expect(tx.$executeRaw).not.toHaveBeenCalled();
  });

  it('releases the lock even when a run fails', async () => {
    const { svc, tx, redis } = setup();
    tx.$executeRaw.mockRejectedValueOnce(new Error('db down'));
    await expect(svc.run('x', NOW)).rejects.toThrow('db down');
    expect(redis.eval).toHaveBeenCalledWith(
      expect.stringContaining('del'),
      1,
      'lock:retention',
      expect.any(String),
    );
  });

  it('sweeps only old, unreferenced objects', async () => {
    const { svc, storage, prisma } = setup();
    const old = new Date(Date.now() - 2 * 3_600_000);
    storage.listObjects.mockImplementation(async function* () {
      yield [
        { key: 'screenshots/known.png', lastModified: old, size: 1 },
        { key: 'screenshots/orphan.png', lastModified: old, size: 1 },
        { key: 'screenshots/uploading.png', lastModified: new Date(), size: 1 },
      ];
    });
    prisma.screenshot.findMany.mockResolvedValueOnce([
      { storageKey: 'screenshots/known.png' },
    ] as never);
    const report = await svc.sweepOrphans('admin');
    expect(storage.deleteObjects).toHaveBeenCalledWith([
      'screenshots/orphan.png',
    ]);
    expect(report).toMatchObject({
      scanned: 3,
      orphans: 1,
      deleted: 1,
      failed: 0,
    });
  });

  it('reads the last reports', async () => {
    const { svc, redis } = setup();
    redis.get.mockResolvedValueOnce(
      JSON.stringify({ requestedBy: 'schedule' }) as never,
    );
    expect(await svc.lastRun()).toEqual({ requestedBy: 'schedule' });
    expect(await svc.lastSweep()).toBeNull();
  });
});

describe('retention jobs and API', () => {
  it('processor routes job names and reports skipped runs', async () => {
    const retention = {
      run: vi.fn(async () => ({ rows: {} })),
      sweepOrphans: vi.fn(async () => null),
    };
    const p = new RetentionProcessor(retention as never);
    expect(
      await p.process({
        id: '1',
        name: 'retention-run',
        data: { requestedBy: 'schedule' },
      } as never),
    ).toEqual({ rows: {} });
    expect(
      await p.process({
        id: '2',
        name: 'orphan-sweep',
        data: { requestedBy: 'a' },
      } as never),
    ).toEqual({ skipped: 'already running' });
  });

  it('scheduler upserts both job schedulers in UTC', async () => {
    const queue = { upsertJobScheduler: vi.fn(async () => ({})) };
    const config = {
      get: () => ({ cron: '30 3 * * *', sweepCron: '0 4 * * 0' }),
    };
    await new RetentionScheduler(
      queue as never,
      config as never,
    ).onApplicationBootstrap();
    expect(queue.upsertJobScheduler).toHaveBeenCalledWith(
      'retention-daily',
      { pattern: '30 3 * * *', tz: 'UTC' },
      expect.objectContaining({ name: 'retention-run' }),
    );
    expect(queue.upsertJobScheduler).toHaveBeenCalledWith(
      'retention-orphan-sweep',
      { pattern: '0 4 * * 0', tz: 'UTC' },
      expect.objectContaining({ name: 'orphan-sweep' }),
    );
  });

  it('controller reports status and queues manual runs', async () => {
    const queue = {
      add: vi.fn(async (name: string, _d: unknown, o: { jobId: string }) => ({
        id: o.jobId,
        name,
      })),
      getJobScheduler: vi.fn(async (key: string) =>
        key === 'retention-daily'
          ? { next: Date.parse('2026-10-03T03:30:00Z') }
          : undefined,
      ),
    };
    const retention = {
      lastRun: vi.fn(async () => ({ rows: { scans: 1 } })),
      lastSweep: vi.fn(async () => null),
    };
    const config = {
      get: () => ({
        days: 31,
        keepLatest: true,
        cron: 'c',
        sweepCron: 's',
        batchSize: 5000,
      }),
    };
    const ctrl = new RetentionController(
      retention as never,
      config as never,
      queue as never,
    );
    expect(await ctrl.status()).toMatchObject({
      lastRun: { rows: { scans: 1 } },
      nextRun: '2026-10-03T03:30:00.000Z',
      nextSweep: null,
      settings: { days: 31 },
    });
    const res = await ctrl.run(
      { task: 'orphan-sweep' },
      { name: 'ops', scope: 'admin', actor: 'ops' },
    );
    expect(res).toMatchObject({
      queued: true,
      jobId: expect.stringMatching(/^orphan-sweep-manual-/),
    });
    expect(queue.add).toHaveBeenCalledWith(
      'orphan-sweep',
      { requestedBy: 'ops' },
      expect.objectContaining({ attempts: 1 }),
    );
    await enqueueManual(queue as never, 'retention-run', 'x');
  });
});
