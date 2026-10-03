import { ConflictException, NotFoundException } from '@nestjs/common';
import { Prisma } from '../../database/generated/prisma/client.js';
import type { PrismaService } from '../../database/prisma.service.js';
import { fakeBus } from '../../testing/fake-bus.js';
import type { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';
import { SCAN_EVENTS } from './events/scan.events.js';
import { ScansService } from './scans.service.js';

const scanRow = (over: Record<string, unknown> = {}) => ({
  id: 'scan-1',
  originalDomainId: 'od-1',
  status: 'QUEUED',
  triggeredBy: 'API',
  options: {},
  permutationsTotal: 0,
  resolvedCount: 0,
  registeredCount: 0,
  newCount: 0,
  failedCount: 0,
  errorMessage: null,
  idempotencyKey: null,
  startedAt: null,
  finishedAt: null,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over,
});

function setup() {
  const tx = {
    scan: {
      findFirst: vi.fn(async () => null),
      create: vi.fn(async ({ data }) => scanRow(data)),
      findUnique: vi.fn(async () => ({ status: 'QUEUED' })),
      updateMany: vi.fn(async (_args?: any) => ({ count: 1 })),
      findUniqueOrThrow: vi.fn(async () => scanRow({ status: 'FUZZING' })),
      update: vi.fn(async () => ({
        id: 'scan-1',
        resolvedCount: 500,
        permutationsTotal: 1000,
      })),
    },
  };
  const prisma = {
    scan: {
      findUnique: vi.fn(async () => null),
      findFirst: vi.fn(async () => null),
      findMany: vi.fn(async () => []),
      count: vi.fn(async () => 0),
    },
  };
  const originals = {
    getScannable: vi.fn(async () => ({
      id: 'od-1',
      domain: 'example.com',
      scanOptions: { includeWhois: true },
    })),
  } as unknown as OriginalDomainsQuery;
  const bus = fakeBus(tx);
  return {
    service: new ScansService(
      prisma as unknown as PrismaService,
      bus.bus,
      originals,
    ),
    tx,
    prisma,
    ...bus,
  };
}

describe('ScansService.create', () => {
  it('creates a scan with options merged over the domain defaults', async () => {
    const t = setup();
    const res = await t.service.create({
      originalDomainId: 'od-1',
      triggeredBy: 'API',
      options: { fuzzers: ['omission'] },
    });
    expect(res.created).toBe(true);
    expect(t.tx.scan.create.mock.calls[0][0].data.options).toEqual({
      includeWhois: true,
      fuzzers: ['omission'],
    });
    expect(t.beforeNames()).toEqual([SCAN_EVENTS.BEFORE_CREATE]);
    expect(t.afterNames()).toEqual([SCAN_EVENTS.CREATED]);
  });

  it('returns the in-flight scan instead of starting another', async () => {
    const t = setup();
    t.tx.scan.findFirst.mockResolvedValue(
      scanRow({ id: 'active', status: 'RESOLVING' }) as never,
    );
    const res = await t.service.create({
      originalDomainId: 'od-1',
      triggeredBy: 'API',
    });
    expect(res).toMatchObject({ created: false, scan: { id: 'active' } });
    expect(t.after).toEqual([]);
  });

  it('replays an idempotency key, and rejects reuse for another domain', async () => {
    const t = setup();
    t.prisma.scan.findUnique.mockResolvedValue(
      scanRow({ id: 'earlier' }) as never,
    );
    expect(
      await t.service.create({
        originalDomainId: 'od-1',
        triggeredBy: 'API',
        idempotencyKey: 'k-12345678',
      }),
    ).toMatchObject({
      created: false,
      scan: { id: 'earlier' },
    });
    await expect(
      t.service.create({
        originalDomainId: 'other',
        triggeredBy: 'API',
        idempotencyKey: 'k-12345678',
      }),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('returns the winner when the partial unique index rejects a concurrent insert', async () => {
    const t = setup();
    t.tx.scan.create.mockRejectedValue(
      new Prisma.PrismaClientKnownRequestError('dup', {
        code: 'P2002',
        clientVersion: '7',
        meta: {
          driverAdapterError: {
            cause: { constraint: { index: 'uq_scans_active_original_domain' } },
          },
        },
      }),
    );
    t.prisma.scan.findFirst.mockResolvedValue(
      scanRow({ id: 'winner' }) as never,
    );
    expect(
      await t.service.create({ originalDomainId: 'od-1', triggeredBy: 'API' }),
    ).toMatchObject({
      created: false,
      scan: { id: 'winner' },
    });
  });

  it('rethrows unrelated errors', async () => {
    const t = setup();
    t.tx.scan.create.mockRejectedValue(new Error('db down'));
    await expect(
      t.service.create({ originalDomainId: 'od-1', triggeredBy: 'API' }),
    ).rejects.toThrow('db down');
  });
});

describe('ScansService transitions', () => {
  it('compare-and-sets the status and emits status-changed', async () => {
    const t = setup();
    const scan = await t.service.startFuzzing('scan-1');
    expect(scan?.status).toBe('FUZZING');
    expect(t.tx.scan.updateMany).toHaveBeenCalledWith({
      where: { id: 'scan-1', status: { in: ['QUEUED'] } },
      data: expect.objectContaining({
        status: 'FUZZING',
        startedAt: expect.any(Date),
      }),
    });
    expect(t.afterNames()).toEqual([SCAN_EVENTS.STATUS_CHANGED]);
  });

  it('returns null when another actor already moved the scan', async () => {
    const t = setup();
    t.tx.scan.updateMany.mockResolvedValue({ count: 0 });
    expect(await t.service.startResolving('scan-1', 10)).toBeNull();
    expect(t.after).toEqual([]);
  });

  it('emits a finished event flagged as a full scan on completion', async () => {
    const t = setup();
    t.tx.scan.findUniqueOrThrow.mockResolvedValue(
      scanRow({ status: 'COMPLETED', registeredCount: 3 }) as never,
    );
    await t.service.complete('scan-1', {
      registeredCount: 3,
      newCount: 1,
      failedCount: 0,
    });
    expect(t.afterNames()).toEqual([
      SCAN_EVENTS.STATUS_CHANGED,
      SCAN_EVENTS.COMPLETED,
    ]);
    expect(t.after[1]).toMatchObject({
      fullScan: true,
      counts: { registeredCount: 3 },
    });
  });

  it('marks subset scans as not full', async () => {
    const t = setup();
    t.tx.scan.findUniqueOrThrow.mockResolvedValue(
      scanRow({
        status: 'FAILED',
        options: { fuzzers: ['omission'] },
      }) as never,
    );
    await t.service.fail('scan-1', 'x'.repeat(5000));
    expect(
      t.tx.scan.updateMany.mock.calls[0][0].data.errorMessage,
    ).toHaveLength(2000);
    expect(t.after[1]).toMatchObject({
      name: SCAN_EVENTS.FAILED,
      fullScan: false,
    });
  });

  it('cancel 409s when the scan already finished, 404 when unknown', async () => {
    const t = setup();
    t.prisma.scan.findUnique.mockResolvedValue(
      scanRow({ status: 'COMPLETED' }) as never,
    );
    t.tx.scan.updateMany.mockResolvedValue({ count: 0 });
    await expect(t.service.cancel('scan-1')).rejects.toBeInstanceOf(
      ConflictException,
    );
    t.prisma.scan.findUnique.mockResolvedValue(null);
    await expect(t.service.cancel('nope')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('records progress atomically', async () => {
    const t = setup();
    await t.service.recordProgress('scan-1', 500);
    expect(t.tx.scan.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { resolvedCount: { increment: 500 } } }),
    );
    expect(t.after[0]).toMatchObject({
      name: SCAN_EVENTS.PROGRESS,
      resolvedCount: 500,
      permutationsTotal: 1000,
    });
  });
});
