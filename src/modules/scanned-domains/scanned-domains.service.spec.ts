import { fakeBus } from '../../testing/fake-bus.js';
import type { DnsResolution } from '../dns-resolver/dns.types.js';
import { SCANNED_DOMAIN_EVENTS } from './events/scanned-domain.events.js';
import { ScannedDomainsService } from './scanned-domains.service.js';

const res = (
  domain: string,
  over: Partial<DnsResolution> = {},
): DnsResolution => ({
  domain,
  nxdomain: false,
  registered: true,
  a: ['1.2.3.4'],
  aaaa: [],
  mx: [],
  ns: ['ns1.x'],
  ttl: 300,
  errors: [],
  ...over,
});

function setup(
  returned: {
    id: string;
    domain: string;
    inserted: boolean;
    deleted: boolean;
  }[],
) {
  const tx = {
    scannedDomain: {
      findMany: vi.fn(async () => [
        {
          domain: 'same.com',
          dnsA: ['1.2.3.4'],
          dnsAaaa: [],
          dnsMx: [],
          dnsNs: ['ns1.x'],
        },
        {
          domain: 'moved.com',
          dnsA: ['9.9.9.9'],
          dnsAaaa: [],
          dnsMx: [],
          dnsNs: ['ns1.x'],
        },
      ]),
    },
    $queryRaw: vi.fn(async () => returned),
  };
  const bus = fakeBus(tx);
  return {
    service: new ScannedDomainsService(bus.bus, {} as never),
    tx,
    ...bus,
  };
}

describe('ScannedDomainsService.upsertBatch', () => {
  it('upserts registered domains only and emits discovered / updated precisely', async () => {
    const t = setup([
      { id: '1', domain: 'new.com', inserted: true, deleted: false },
      { id: '2', domain: 'same.com', inserted: false, deleted: false },
      { id: '3', domain: 'moved.com', inserted: false, deleted: false },
    ]);
    const out = await t.service.upsertBatch({
      scanId: 'scan-1',
      originalDomainId: 'od-1',
      fuzzerByDomain: { 'new.com': 'omission' },
      resolutions: [
        res('new.com'),
        res('same.com'),
        res('moved.com'),
        res('dead.com', { registered: false }),
      ],
    });
    expect(out).toEqual({ inserted: 1, updated: 2 });
    expect(t.before[0]).toMatchObject({
      domains: ['new.com', 'same.com', 'moved.com'],
    });
    expect(t.afterNames()).toEqual([
      SCANNED_DOMAIN_EVENTS.DISCOVERED,
      SCANNED_DOMAIN_EVENTS.UPDATED,
      SCANNED_DOMAIN_EVENTS.BATCH_UPSERTED,
    ]);
    expect(t.after[0]).toMatchObject({
      scannedDomainId: '1',
      resolvesToIp: true,
    });
    expect(t.after[1]).toMatchObject({
      domain: 'moved.com',
      changedFields: ['dnsA'],
    });
  });

  it('does not emit updates for soft-deleted rows', async () => {
    const t = setup([
      { id: '3', domain: 'moved.com', inserted: false, deleted: true },
    ]);
    await t.service.upsertBatch({
      scanId: 's',
      originalDomainId: 'od',
      fuzzerByDomain: {},
      resolutions: [res('moved.com')],
    });
    expect(t.afterNames()).toEqual([SCANNED_DOMAIN_EVENTS.BATCH_UPSERTED]);
  });

  it('skips the database entirely when nothing is registered', async () => {
    const t = setup([]);
    expect(
      await t.service.upsertBatch({
        scanId: 's',
        originalDomainId: 'od',
        fuzzerByDomain: {},
        resolutions: [res('x.com', { registered: false })],
      }),
    ).toEqual({ inserted: 0, updated: 0 });
    expect(t.bus.write).not.toHaveBeenCalled();
  });
});

describe('ScannedDomainsService.markUnseenInactive', () => {
  it('emits marked-inactive with the affected ids', async () => {
    const t = setup([{ id: 'a' }, { id: 'b' }] as never);
    expect(await t.service.markUnseenInactive('od-1', 'scan-1')).toEqual([
      'a',
      'b',
    ]);
    expect(t.after[0]).toMatchObject({
      name: SCANNED_DOMAIN_EVENTS.MARKED_INACTIVE,
      scannedDomainIds: ['a', 'b'],
    });
  });

  it('emits nothing when every domain was seen', async () => {
    const t = setup([]);
    await t.service.markUnseenInactive('od-1', 'scan-1');
    expect(t.after).toEqual([]);
  });
});
