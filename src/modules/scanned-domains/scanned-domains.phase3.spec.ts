import { UnprocessableEntityException } from '@nestjs/common';
import { DomainStatus } from '../../database/generated/prisma/enums.js';
import type { DnsResolution } from '../dns-resolver/dns.types.js';
import { fakeBus } from '../../testing/fake-bus.js';
import {
  SCANNED_DOMAIN_EVENTS,
  ScannedDomainBeforeStatusChangeEvent,
} from './events/scanned-domain.events.js';
import { StatusRulesListener } from './listeners/status-rules.listener.js';
import { DomainRescanProcessor } from './processors/domain-rescan.processor.js';
import { ScannedDomainsService } from './scanned-domains.service.js';
import { transitionError } from './status-rules.js';

const S = DomainStatus;

describe('status rules', () => {
  it.each([
    [S.NEW, S.ACTIVE, 'system', true],
    [S.ACTIVE, S.INACTIVE, 'system', true],
    [S.CONFIRMED_THREAT, S.INACTIVE, 'system', false], // scans never undo an analyst call
    [S.FALSE_POSITIVE, S.ACTIVE, 'system', false],
    [S.NEW, S.CONFIRMED_THREAT, 'manual', true],
    [S.NEW, S.PARKED, 'manual', false], // system-only target
    [S.ACTIVE, S.TAKEN_DOWN, 'manual', false],
    [S.CONFIRMED_THREAT, S.TAKEN_DOWN, 'manual', true],
    [S.FALSE_POSITIVE, S.ACTIVE, 'manual', true], // reopen
    [S.PARKED, S.ACTIVE, 'manual', false],
    [S.ALLOWLISTED, S.CONFIRMED_THREAT, 'review', true],
    [S.TAKEN_DOWN, S.TAKEN_DOWN, 'system', true], // no-op
  ] as const)('%s → %s by %s allowed=%s', (from, to, source, ok) => {
    expect(transitionError(from, to, source) === null).toBe(ok);
  });
});

describe('StatusRulesListener', () => {
  const listener = (
    rows: { id: string; domain: string; status: DomainStatus }[],
  ) =>
    new StatusRulesListener({
      scannedDomain: { findMany: vi.fn(async () => rows) },
    } as never);

  it('vetoes the whole change when any row would make an illegal transition', async () => {
    const l = listener([
      { id: 'a', domain: 'ok.com', status: S.CONFIRMED_THREAT },
      { id: 'b', domain: 'bad.com', status: S.ACTIVE },
    ]);
    const event = new ScannedDomainBeforeStatusChangeEvent(
      ['a', 'b'],
      S.TAKEN_DOWN,
      'manual',
      'ana',
    );
    await expect(l.validate(event)).rejects.toBeInstanceOf(
      UnprocessableEntityException,
    );
    await expect(l.validate(event)).rejects.toMatchObject({
      response: {
        message: ['bad.com: Only a CONFIRMED_THREAT can be marked TAKEN_DOWN'],
      },
    });
  });

  it('allows legal transitions', async () => {
    await expect(
      listener([{ id: 'a', domain: 'x.com', status: S.NEW }]).validate(
        new ScannedDomainBeforeStatusChangeEvent(
          ['a'],
          S.UNDER_REVIEW,
          'manual',
          'ana',
        ),
      ),
    ).resolves.toBeUndefined();
  });
});

describe('ScannedDomainsService (Phase 3)', () => {
  it('changeStatus uses compare-and-set and emits one event per changed row', async () => {
    const tx = {
      scannedDomain: {
        findMany: vi.fn(async () => [
          { id: 'a', originalDomainId: 'o', domain: 'a.com', status: S.NEW },
          {
            id: 'b',
            originalDomainId: 'o',
            domain: 'b.com',
            status: S.CONFIRMED_THREAT,
          },
          { id: 'c', originalDomainId: 'o', domain: 'c.com', status: S.ACTIVE },
        ]),
        // 'c' was moved concurrently: CAS matches nothing.
        updateMany: vi.fn(async ({ where }: { where: { id: string } }) => ({
          count: where.id === 'c' ? 0 : 1,
        })),
      },
    };
    const bus = fakeBus(tx);
    const result = await new ScannedDomainsService(
      bus.bus,
      {} as never,
    ).changeStatus(['a', 'b', 'c', 'missing'], S.CONFIRMED_THREAT, {
      source: 'manual',
      actor: 'ana@x',
    });
    expect(result).toEqual({ changed: 1, unchanged: 3 });
    expect(tx.scannedDomain.updateMany).toHaveBeenCalledWith({
      where: { id: 'a', status: S.NEW },
      data: { status: S.CONFIRMED_THREAT },
    });
    expect(bus.beforeNames()).toEqual([
      SCANNED_DOMAIN_EVENTS.BEFORE_STATUS_CHANGE,
    ]);
    expect(bus.after).toEqual([
      expect.objectContaining({
        name: SCANNED_DOMAIN_EVENTS.STATUS_CHANGED,
        scannedDomainId: 'a',
        from: S.NEW,
        to: S.CONFIRMED_THREAT,
        source: 'manual',
        actor: 'ana@x',
      }),
    ]);
  });

  it('updateTags normalises, de-duplicates and only writes rows that change', async () => {
    const tx = {
      scannedDomain: {
        findMany: vi.fn(async () => [
          { id: 'a', tags: ['old', 'keep'] },
          { id: 'b', tags: ['vip'] },
        ]),
        update: vi.fn(async () => ({})),
      },
    };
    const bus = fakeBus(tx);
    const n = await new ScannedDomainsService(bus.bus, {} as never).updateTags(
      ['a', 'b'],
      { add: [' VIP ', 'vip'], remove: ['OLD'] },
      'ana',
    );
    expect(n).toBe(1);
    expect(tx.scannedDomain.update).toHaveBeenCalledWith({
      where: { id: 'a' },
      data: { tags: ['keep', 'vip'] },
    });
    expect(bus.after[0]).toMatchObject({
      name: SCANNED_DOMAIN_EVENTS.TAGS_UPDATED,
      scannedDomainIds: ['a'],
    });
  });

  it('softDelete marks deletedAt and emits deleted; unknown ids return false', async () => {
    const update = vi.fn(async (_args: unknown) => ({}));
    const bus = fakeBus({
      scannedDomain: {
        findFirst: vi.fn(async ({ where }: { where: { id: string } }) =>
          where.id === 'a' ? { domain: 'a.com' } : null,
        ),
        update,
      },
    });
    const svc = new ScannedDomainsService(bus.bus, {} as never);
    expect(await svc.softDelete('a', 'ana')).toBe(true);
    expect(update.mock.calls[0][0]).toMatchObject({
      where: { id: 'a' },
      data: { deletedAt: expect.any(Date) },
    });
    expect(await svc.softDelete('nope', 'ana')).toBe(false);
    expect(bus.afterNames()).toEqual([SCANNED_DOMAIN_EVENTS.DELETED]);
  });

  describe('refreshDns', () => {
    const resolution = (registered: boolean): DnsResolution =>
      ({
        domain: 'a.com',
        nxdomain: !registered,
        registered,
        a: registered ? ['1.2.3.4'] : [],
        aaaa: [],
        mx: [],
        ns: registered ? ['ns1.x'] : [],
        ttl: 300,
        errors: {},
      }) as unknown as DnsResolution;

    function setup(status: DomainStatus) {
      const row = {
        id: 'a',
        originalDomainId: 'o',
        lastScanId: 'scan',
        domain: 'a.com',
        status,
        dnsA: [],
        dnsAaaa: [],
        dnsMx: [],
        dnsNs: ['ns1.x'],
      };
      const tx = {
        scannedDomain: {
          findFirst: vi.fn(async () => row),
          findMany: vi.fn(async () => [row]),
          update: vi.fn(
            async (_args: { data: Record<string, unknown> }) => ({}),
          ),
          updateMany: vi.fn(async () => ({ count: 1 })),
        },
      };
      const bus = fakeBus(tx);
      const prisma = { scannedDomain: { findFirst: vi.fn(async () => row) } };
      return {
        svc: new ScannedDomainsService(bus.bus, prisma as never),
        bus,
        tx,
      };
    }

    it('forces re-enrichment and reactivates an INACTIVE look-alike that resolves again', async () => {
      const { svc, bus, tx } = setup(S.INACTIVE);
      expect(await svc.refreshDns('a', resolution(true), 'ana')).toBe(
        'refreshed',
      );
      expect(tx.scannedDomain.update.mock.calls[0][0]).toMatchObject({
        data: { dnsA: ['1.2.3.4'], status: S.ACTIVE },
      });
      expect(bus.after[0]).toMatchObject({
        name: SCANNED_DOMAIN_EVENTS.UPDATED,
        force: true,
        changedFields: ['dnsA'],
      });
      expect(bus.after[1]).toMatchObject({
        name: SCANNED_DOMAIN_EVENTS.STATUS_CHANGED,
        from: S.INACTIVE,
        to: S.ACTIVE,
      });
    });

    it('keeps an analyst status when the look-alike resolves', async () => {
      const { svc, bus, tx } = setup(S.CONFIRMED_THREAT);
      await svc.refreshDns('a', resolution(true), 'ana');
      expect(tx.scannedDomain.update.mock.calls[0][0].data).not.toHaveProperty(
        'status',
      );
      expect(bus.afterNames()).toEqual([SCANNED_DOMAIN_EVENTS.UPDATED]);
    });

    it('marks a vanished system-managed look-alike INACTIVE, but never an analyst decision', async () => {
      const active = setup(S.ACTIVE);
      expect(await active.svc.refreshDns('a', resolution(false), 'ana')).toBe(
        'inactive',
      );
      expect(active.bus.after[0]).toMatchObject({
        to: S.INACTIVE,
        source: 'system',
      });

      const confirmed = setup(S.CONFIRMED_THREAT);
      expect(
        await confirmed.svc.refreshDns('a', resolution(false), 'ana'),
      ).toBe('inactive');
      expect(confirmed.bus.after).toEqual([]);
    });

    it('never invents a scan id when the last scan was purged by retention (regression)', async () => {
      const { svc, bus, tx } = setup(S.ACTIVE);
      const row = await tx.scannedDomain.findFirst();
      row.lastScanId = null as never;
      await svc.refreshDns('a', resolution(true), 'ana');
      expect(bus.after[0]).toMatchObject({
        name: SCANNED_DOMAIN_EVENTS.UPDATED,
        scanId: undefined,
      });
    });

    it("reports 'gone' for deleted look-alikes", async () => {
      const bus = fakeBus({});
      const prisma = { scannedDomain: { findFirst: vi.fn(async () => null) } };
      expect(
        await new ScannedDomainsService(bus.bus, prisma as never).refreshDns(
          'x',
          resolution(true),
          'a',
        ),
      ).toBe('gone');
    });
  });
});

describe('DomainRescanProcessor', () => {
  it('resolves the domain and hands the result to the service', async () => {
    const resolution = { domain: 'a.com', registered: true };
    const dns = { resolve: vi.fn(async () => resolution) };
    const service = { refreshDns: vi.fn(async () => 'refreshed') };
    const processor = new DomainRescanProcessor(dns as never, service as never);
    const job = {
      id: '1',
      name: 'rescan',
      data: { scannedDomainId: 'sd', domain: 'a.com', actor: 'ana' },
    };
    expect(await processor.process(job as never)).toEqual({
      outcome: 'refreshed',
      registered: true,
    });
    expect(service.refreshDns).toHaveBeenCalledWith('sd', resolution, 'ana');
  });
});
