import {
  BadRequestException,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import type { PrismaService } from '../../database/prisma.service.js';
import { fakeBus } from '../../testing/fake-bus.js';
import { ORIGINAL_DOMAIN_EVENTS } from './events/original-domain.events.js';
import { OriginalDomainsService } from './original-domains.service.js';

const now = new Date('2026-10-02T00:00:00Z');
const row = (over: Record<string, unknown> = {}) => ({
  id: 'od-1',
  domain: 'example.com',
  unicodeDomain: 'example.com',
  label: null,
  isActive: true,
  scanSchedule: null,
  scanOptions: {},
  lastScannedAt: null,
  deletedAt: null,
  createdAt: now,
  updatedAt: now,
  ...over,
});

function setup() {
  const tx = {
    originalDomain: {
      findUnique: vi.fn(),
      findFirst: vi.fn(async () => ({ id: 'od-1' })),
      create: vi.fn(async ({ data }) => row(data)),
      update: vi.fn(async ({ data }) => row(data)),
    },
  };
  const prisma = {
    originalDomain: {
      findMany: vi.fn(async (_args: any) => [row()]),
      count: vi.fn(async () => 1),
      findFirst: vi.fn(),
    },
    scannedDomain: {
      groupBy: vi.fn(
        async (_args?: unknown) =>
          [] as { threatLevel: string; _count: { _all: number } }[],
      ),
    },
    scan: { findFirst: vi.fn(async () => null) },
  };
  const bus = fakeBus(tx);
  return {
    service: new OriginalDomainsService(
      prisma as unknown as PrismaService,
      bus.bus,
    ),
    tx,
    prisma,
    ...bus,
  };
}

describe('OriginalDomainsService', () => {
  describe('create', () => {
    it('normalises the domain and emits before-create → created', async () => {
      const t = setup();
      t.tx.originalDomain.findUnique.mockResolvedValue(null);
      const dto = await t.service.create({
        domain: 'München.INFO.',
        scanSchedule: '0 2 * * *',
      });
      expect(t.tx.originalDomain.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          domain: 'xn--mnchen-3ya.info',
          unicodeDomain: 'münchen.info',
          scanSchedule: '0 2 * * *',
        }),
      });
      expect(dto.domain).toBe('xn--mnchen-3ya.info');
      expect(t.beforeNames()).toEqual([ORIGINAL_DOMAIN_EVENTS.BEFORE_CREATE]);
      expect(t.afterNames()).toEqual([ORIGINAL_DOMAIN_EVENTS.CREATED]);
      expect(t.after[0]).toMatchObject({ restored: false });
    });

    it('restores a soft-deleted domain in place', async () => {
      const t = setup();
      t.tx.originalDomain.findUnique.mockResolvedValue(row({ deletedAt: now }));
      await t.service.create({ domain: 'example.com' });
      expect(t.tx.originalDomain.update).toHaveBeenCalledWith({
        where: { id: 'od-1' },
        data: expect.objectContaining({ deletedAt: null }),
      });
      expect(t.after[0]).toMatchObject({ restored: true });
    });

    it('rejects duplicates (409) and invalid domains (400) without after events', async () => {
      const t = setup();
      t.tx.originalDomain.findUnique.mockResolvedValue(row());
      await expect(
        t.service.create({ domain: 'example.com' }),
      ).rejects.toBeInstanceOf(ConflictException);
      await expect(
        t.service.create({ domain: 'http://x.com' }),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(t.after).toEqual([]);
    });
  });

  it('lists with search across domain, unicode and label', async () => {
    const t = setup();
    const page = await t.service.findAll(
      Object.assign(
        new (
          await import('./dto/original-domain.dto.js')
        ).ListOriginalDomainsQueryDto(),
        {
          search: 'Ex',
          isActive: true,
        },
      ),
    );
    expect(page).toMatchObject({ total: 1, page: 1, limit: 25 });
    const where = t.prisma.originalDomain.findMany.mock.calls[0][0].where;
    expect(where).toMatchObject({ deletedAt: null, isActive: true });
    expect(where.OR).toHaveLength(3);
  });

  it('returns stats grouped by threat level', async () => {
    const t = setup();
    t.prisma.originalDomain.findFirst.mockResolvedValue(row());
    t.prisma.scannedDomain.groupBy.mockResolvedValue([
      { threatLevel: 'UNSCORED', _count: { _all: 3 } },
      { threatLevel: 'HIGH_RISK', _count: { _all: 1 } },
    ]);
    const detail = await t.service.findOne('od-1');
    expect(detail.stats).toEqual({
      trackedDomains: 4,
      byThreatLevel: { UNSCORED: 3, HIGH_RISK: 1 },
      latestScan: null,
    });
  });

  it('404s on a missing domain', async () => {
    const t = setup();
    t.prisma.originalDomain.findFirst.mockResolvedValue(null);
    await expect(t.service.findOne('nope')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('updates only provided fields and reports which changed', async () => {
    const t = setup();
    await t.service.update('od-1', { scanSchedule: '0 3 * * *' });
    expect(t.after[0]).toMatchObject({
      name: ORIGINAL_DOMAIN_EVENTS.UPDATED,
      changedFields: ['scanSchedule'],
    });
  });

  it('soft-deletes and emits deleted; 404 when already gone', async () => {
    const t = setup();
    await t.service.remove('od-1');
    expect(t.tx.originalDomain.update).toHaveBeenCalledWith({
      where: { id: 'od-1' },
      data: { deletedAt: expect.any(Date), isActive: false },
    });
    expect(t.afterNames()).toEqual([ORIGINAL_DOMAIN_EVENTS.DELETED]);

    const t2 = setup();
    t2.tx.originalDomain.findFirst.mockResolvedValue(null as never);
    await expect(t2.service.remove('gone')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('records lastScannedAt through the bus', async () => {
    const t = setup();
    await t.service.markScanned('od-1', now);
    expect(t.tx.originalDomain.update).toHaveBeenCalledWith({
      where: { id: 'od-1' },
      data: { lastScannedAt: now },
    });
    expect(t.after[0]).toMatchObject({ changedFields: ['lastScannedAt'] });
  });
});
