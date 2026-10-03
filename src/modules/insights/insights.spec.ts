import { NotFoundException } from '@nestjs/common';
import { InsightsController } from './insights.controller.js';
import { InsightsService, NEIGHBOUR_LIMIT } from './insights.service.js';

const t = (iso: string) => new Date(iso);
const center = {
  id: 'c',
  domain: 'paypa1.com',
  status: 'ACTIVE',
  riskScore: 90,
  threatLevel: 'HIGH_RISK',
  dnsA: ['3.3.3.3'],
  dnsNs: ['ns1.park.example'],
  dnsMx: [],
  firstSeenAt: t('2026-10-01T10:00:00Z'),
  lastSeenAt: t('2026-10-02T10:00:00Z'),
  fuzzer: 'homoglyph',
  originalDomain: { id: 'b', domain: 'paypal.com' },
};
const other = (id: string, domain: string) => ({
  id,
  domain,
  riskScore: 50,
  threatLevel: 'MEDIUM_RISK',
  status: 'NEW',
});

function setup(found = true) {
  const prisma = {
    scannedDomain: {
      findFirst: vi.fn(async () => (found ? center : null)),
      findMany: vi.fn(
        async ({ where }: { where: Record<string, { has: string }> }) =>
          where.dnsA
            ? [other('o1', 'paypai.com'), other('o2', 'paypall.com')]
            : [other('o1', 'paypai.com')],
      ),
      count: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
        where.dnsA ? 2 : 340,
      ),
    },
    whoisInformation: {
      findFirst: vi.fn(async () => ({ registrar: 'GoDaddy.com, LLC' })),
      findMany: vi.fn(async () => [
        {
          fetchedAt: t('2026-10-01T11:00:00Z'),
          source: 'RDAP',
          registrar: 'GoDaddy.com, LLC',
          parseSucceeded: true,
        },
      ]),
    },
    screenshot: {
      findMany: vi.fn(async () => [
        {
          createdAt: t('2026-10-01T12:00:00Z'),
          status: 'CAPTURED',
          pageTitle: 'Log in',
          httpStatus: 200,
          errorMessage: null,
        },
      ]),
    },
    analytics: {
      findMany: vi.fn(async () => [
        {
          computedAt: t('2026-10-01T13:00:00Z'),
          totalScore: 90,
          threatLevel: 'HIGH_RISK',
        },
        {
          computedAt: t('2026-10-01T12:30:00Z'),
          totalScore: 90,
          threatLevel: 'HIGH_RISK',
        },
        {
          computedAt: t('2026-10-01T10:30:00Z'),
          totalScore: 50,
          threatLevel: 'MEDIUM_RISK',
        },
      ]),
    },
    review: {
      findMany: vi.fn(async () => [
        {
          createdAt: t('2026-10-01T14:00:00Z'),
          verdict: 'MALICIOUS',
          reviewer: 'ana',
          previousStatus: 'NEW',
          newStatus: 'CONFIRMED_THREAT',
          notes: 'kit',
        },
      ]),
    },
    alertDelivery: {
      findMany: vi.fn(async () => [
        {
          createdAt: t('2026-10-01T14:00:05Z'),
          eventType: 'CONFIRMED_THREAT',
          status: 'SENT',
          channel: { name: 'SOC' },
        },
      ]),
    },
  };
  return { svc: new InsightsService(prisma as never), prisma };
}

describe('InsightsService.related', () => {
  it('builds the infrastructure graph with shared look-alikes and counts', async () => {
    const { svc, prisma } = setup();
    const g = await svc.related('c');
    const ids = g.nodes.map((n) => n.id).sort();
    expect(ids).toEqual(
      [
        'brand:b',
        'ip:3.3.3.3',
        'lookalike:c',
        'lookalike:o1',
        'lookalike:o2',
        'nameserver:ns1.park.example',
        'registrar:godaddy.com, llc',
      ].sort(),
    );
    expect(g.nodes.find((n) => n.id === 'lookalike:c')).toMatchObject({
      focus: true,
      riskScore: 90,
    });
    expect(g.nodes.find((n) => n.id === 'ip:3.3.3.3')).toMatchObject({
      sharedBy: 3,
    });
    expect(g.nodes.find((n) => n.kind === 'nameserver')).toMatchObject({
      sharedBy: 341,
    }); // parking NS: count, not 341 nodes
    expect(g.edges).toContainEqual({
      source: 'lookalike:c',
      target: 'brand:b',
      kind: 'imitates',
    });
    expect(g.edges).toContainEqual({
      source: 'lookalike:o1',
      target: 'nameserver:ns1.park.example',
      kind: 'uses-nameserver',
    });
    expect(
      new Set(g.edges.map((e) => `${e.source}|${e.target}|${e.kind}`)).size,
    ).toBe(g.edges.length);
    expect(
      (prisma.scannedDomain.findMany.mock.calls[0] as unknown[])[0],
    ).toMatchObject({
      take: NEIGHBOUR_LIMIT,
      where: { deletedAt: null, id: { not: 'c' } },
    });
  });

  it('404s unknown look-alikes', async () => {
    await expect(setup(false).svc.related('x')).rejects.toBeInstanceOf(
      NotFoundException,
    );
    await expect(setup(false).svc.timeline('x')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('InsightsService.timeline', () => {
  it('merges every source newest-first, keeping only risk-band changes', async () => {
    const tl = await setup().svc.timeline('c');
    expect(new Set(tl.map((e) => e.kind))).toEqual(
      new Set([
        'alert',
        'review',
        'score',
        'screenshot',
        'whois',
        'last-seen',
        'discovered',
      ]),
    );
    expect(tl[0]).toMatchObject({ kind: 'last-seen' });
    expect(tl.filter((e) => e.kind === 'score').map((e) => e.title)).toEqual([
      'Risk changed to high risk',
      'Scored medium risk',
    ]);
    expect(tl.find((e) => e.kind === 'review')).toMatchObject({
      tone: 'danger',
      detail: 'NEW → CONFIRMED_THREAT · kit',
    });
    expect(tl.at(-1)).toMatchObject({
      kind: 'discovered',
      detail: 'Technique: homoglyph',
    });
    expect([...tl].map((e) => e.at)).toEqual(
      [...tl]
        .map((e) => e.at)
        .sort()
        .reverse(),
    );
  });

  it('controller delegates', async () => {
    const svc = {
      related: vi.fn(async () => ({ nodes: [], edges: [] })),
      timeline: vi.fn(async () => []),
    };
    const c = new InsightsController(svc as never);
    await c.related('a');
    await c.timeline('a');
    expect(svc.related).toHaveBeenCalledWith('a');
    expect(svc.timeline).toHaveBeenCalledWith('a');
  });
});
