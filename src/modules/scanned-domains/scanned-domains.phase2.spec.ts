import type { PrismaService } from '../../database/prisma.service.js';
import { fakeBus } from '../../testing/fake-bus.js';
import { AnalyticsComputedEvent } from '../analytics/events/analytics.events.js';
import { AnalyticsQuery } from '../analytics/analytics.query.js';
import { SCANNED_DOMAIN_EVENTS } from './events/scanned-domain.events.js';
import { ScanPipelineListener } from './listeners/scan-pipeline.listener.js';
import { ScannedDomainsQuery } from './scanned-domains.query.js';
import { ScannedDomainsService } from './scanned-domains.service.js';

describe('ScannedDomainsService (Phase 2)', () => {
  it('updateRisk mirrors the newest score and reports the previous level', async () => {
    const tx = {
      scannedDomain: {
        findUnique: vi.fn(async () => ({ threatLevel: 'UNSCORED' })),
        update: vi.fn(async () => ({})),
      },
    };
    const bus = fakeBus(tx);
    expect(
      await new ScannedDomainsService(bus.bus, {} as never).updateRisk(
        'sd',
        75,
        'MEDIUM_RISK',
      ),
    ).toBe(true);
    expect(tx.scannedDomain.update).toHaveBeenCalledWith({
      where: { id: 'sd' },
      data: { riskScore: 75, threatLevel: 'MEDIUM_RISK' },
    });
    expect(bus.after[0]).toMatchObject({
      name: SCANNED_DOMAIN_EVENTS.RISK_UPDATED,
      previousThreatLevel: 'UNSCORED',
    });
  });

  it('updateRisk is a no-op for a deleted row', async () => {
    const bus = fakeBus({
      scannedDomain: { findUnique: vi.fn(async () => null), update: vi.fn() },
    });
    expect(
      await new ScannedDomainsService(bus.bus, {} as never).updateRisk(
        'gone',
        1,
        'LOW_RISK',
      ),
    ).toBe(false);
    expect(bus.after).toEqual([]);
  });

  it('emits a first-enrichment update for never-scored look-alikes even without DNS changes', async () => {
    const tx = {
      scannedDomain: {
        findMany: vi.fn(async () => [
          {
            domain: 'x.com',
            dnsA: ['1.1.1.1'],
            dnsAaaa: [],
            dnsMx: [],
            dnsNs: [],
            threatLevel: 'UNSCORED',
          },
        ]),
      },
      $queryRaw: vi.fn(async () => [
        { id: 'sd', domain: 'x.com', inserted: false, deleted: false },
      ]),
    };
    const bus = fakeBus(tx);
    await new ScannedDomainsService(bus.bus, {} as never).upsertBatch({
      scanId: 's',
      originalDomainId: 'od',
      fuzzerByDomain: {},
      resolutions: [
        {
          domain: 'x.com',
          nxdomain: false,
          registered: true,
          a: ['1.1.1.1'],
          aaaa: [],
          mx: [],
          ns: [],
          ttl: 1,
          errors: [],
        },
      ],
    });
    expect(bus.after[0]).toMatchObject({
      name: SCANNED_DOMAIN_EVENTS.UPDATED,
      changedFields: [],
      firstEnrichment: true,
    });
  });
});

describe('ScanPipelineListener.onScored', () => {
  it('updates risk and swallows failures', async () => {
    const service = {
      updateRisk: vi.fn(async () => true),
    } as unknown as ScannedDomainsService & {
      updateRisk: ReturnType<typeof vi.fn>;
    };
    const l = new ScanPipelineListener(service);
    const e = new AnalyticsComputedEvent(
      'a',
      'sd',
      's',
      90,
      'HIGH_RISK',
      'LOW_RISK',
    );
    await l.onScored(e);
    expect(service.updateRisk).toHaveBeenCalledWith('sd', 90, 'HIGH_RISK');
    service.updateRisk.mockRejectedValueOnce(new Error('db'));
    await expect(l.onScored(e)).resolves.toBeUndefined();
  });
});

describe('summary and trends', () => {
  const prisma = {
    scannedDomain: {
      groupBy: vi.fn(async ({ by }: { by: string[] }) =>
        by[0] === 'threatLevel'
          ? [{ threatLevel: 'HIGH_RISK', _count: { _all: 3 } }]
          : by[0] === 'status'
            ? [{ status: 'NEW', _count: { _all: 3 } }]
            : [{ fuzzer: 'omission', _count: { _all: 3 } }],
      ),
      count: vi.fn(async () => 3),
    },
    $queryRaw: vi.fn(),
    analytics: { findMany: vi.fn() },
  } as unknown as PrismaService & { $queryRaw: ReturnType<typeof vi.fn> };

  it('groups look-alikes by level, status and technique', async () => {
    expect(await new ScannedDomainsQuery(prisma).summary('od')).toEqual({
      total: 3,
      byThreatLevel: { HIGH_RISK: 3 },
      byStatus: { NEW: 3 },
      byFuzzer: { omission: 3 },
    });
  });

  it('fills every day in the window, zeroing days without data', async () => {
    const today = new Date(
      new Date().toISOString().slice(0, 10) + 'T00:00:00Z',
    );
    prisma.$queryRaw
      .mockResolvedValueOnce([{ day: today, count: 5n }])
      .mockResolvedValueOnce([{ day: today, count: 2n }]);
    const points = await new AnalyticsQuery(
      prisma,
      new ScannedDomainsQuery(prisma),
    ).trends(3);
    expect(points).toHaveLength(3);
    expect(points[2]).toEqual({
      date: today.toISOString().slice(0, 10),
      newLookalikes: 5,
      highRisk: 2,
    });
    expect(points[0]).toMatchObject({ newLookalikes: 0, highRisk: 0 });
  });
});
