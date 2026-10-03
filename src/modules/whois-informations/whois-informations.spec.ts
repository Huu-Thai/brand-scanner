import type { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { Job } from 'bullmq';
import type { AppConfig } from '../../config/configuration.js';
import { fakeBus } from '../../testing/fake-bus.js';
import type { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import {
  ScannedDomainDiscoveredEvent,
  ScannedDomainUpdatedEvent,
} from '../scanned-domains/events/scanned-domain.events.js';
import { WHOIS_EVENTS } from './events/whois-information.events.js';
import { WhoisTriggerListener } from './listeners/whois-trigger.listener.js';
import type { WhoisLookupService } from './lookup/whois-lookup.service.js';
import { WhoisProcessor } from './processors/whois.processor.js';
import type { WhoisEnqueuer } from './whois.enqueuer.js';
import {
  toWhoisDto,
  WhoisInformationsController,
} from './whois-informations.controller.js';
import type { WhoisInformationsQuery } from './whois-informations.query.js';
import { WhoisInformationsService } from './whois-informations.service.js';

const config = {
  get: () => ({ whoisRefreshDays: 7 }),
} as unknown as ConfigService<AppConfig, true>;
const flags = { whois: true, screenshots: true };
const lookupResult = {
  source: 'RDAP' as const,
  queriedDomain: 'x.com',
  rawText: '{}',
  parseSucceeded: true,
  record: {
    registrar: 'R'.repeat(600),
    emails: ['a@x.com'],
    nameServers: [],
    statuses: [],
    createdDate: new Date('2020-01-01'),
  },
};

describe('WhoisInformationsService', () => {
  it('stores a truncated snapshot and emits created after commit', async () => {
    const tx = {
      whoisInformation: {
        create: vi.fn(async ({ data }) => ({ id: 'w-1', ...data })),
      },
    };
    const bus = fakeBus(tx);
    await new WhoisInformationsService(bus.bus).create(
      'sd-1',
      lookupResult,
      'scan-1',
    );
    expect(
      tx.whoisInformation.create.mock.calls[0][0].data.registrar,
    ).toHaveLength(500);
    expect(bus.afterNames()).toEqual([WHOIS_EVENTS.CREATED]);
    expect(bus.after[0]).toMatchObject({
      scannedDomainId: 'sd-1',
      scanId: 'scan-1',
      parseSucceeded: true,
    });
  });
});

describe('WhoisTriggerListener', () => {
  function setup(stale: boolean) {
    const enqueuer = {
      enqueue: vi.fn(async () => 'job'),
    } as unknown as WhoisEnqueuer & { enqueue: ReturnType<typeof vi.fn> };
    const query = {
      isStale: vi.fn(async () => stale),
    } as unknown as WhoisInformationsQuery;
    return {
      enqueuer,
      listener: new WhoisTriggerListener(enqueuer, query, config),
    };
  }

  it('looks up every new look-alike unless WHOIS is disabled for the scan', async () => {
    const t = setup(false);
    await t.listener.onDiscovered(
      new ScannedDomainDiscoveredEvent(
        'sd',
        'od',
        'scan',
        'x.com',
        true,
        flags,
      ),
    );
    await t.listener.onDiscovered(
      new ScannedDomainDiscoveredEvent('sd', 'od', 'scan', 'x.com', true, {
        ...flags,
        whois: false,
      }),
    );
    expect(t.enqueuer.enqueue).toHaveBeenCalledTimes(1);
  });

  it('re-fetches on DNS change only when the snapshot is stale', async () => {
    const fresh = setup(false);
    await fresh.listener.onUpdated(
      new ScannedDomainUpdatedEvent(
        'sd',
        'od',
        'scan',
        'x.com',
        ['dnsA'],
        true,
        flags,
      ),
    );
    expect(fresh.enqueuer.enqueue).not.toHaveBeenCalled();
    const stale = setup(true);
    await stale.listener.onUpdated(
      new ScannedDomainUpdatedEvent(
        'sd',
        'od',
        'scan',
        'x.com',
        ['dnsA'],
        true,
        flags,
      ),
    );
    expect(stale.enqueuer.enqueue).toHaveBeenCalledWith({
      scannedDomainId: 'sd',
      domain: 'x.com',
      scanId: 'scan',
    });
  });

  it('never throws when the queue is down', async () => {
    const t = setup(true);
    t.enqueuer.enqueue.mockRejectedValue(new Error('redis'));
    await expect(
      t.listener.onDiscovered(
        new ScannedDomainDiscoveredEvent('sd', 'od', 's', 'x.com', true, flags),
      ),
    ).resolves.toBeUndefined();
  });
});

describe('WhoisProcessor', () => {
  function setup(opts: { exists?: boolean; stale?: boolean } = {}) {
    const lookup = {
      lookup: vi.fn(async () => lookupResult),
    } as unknown as WhoisLookupService;
    const service = {
      create: vi.fn(async () => ({ id: 'w-1' })),
    } as unknown as WhoisInformationsService;
    const query = {
      isStale: vi.fn(async () => opts.stale ?? true),
    } as unknown as WhoisInformationsQuery;
    const sd = {
      getForEnrichment: vi.fn(async () =>
        opts.exists === false ? null : { id: 'sd' },
      ),
    } as unknown as ScannedDomainsQuery;
    const events = new EventEmitter2();
    return {
      lookup,
      service,
      events,
      p: new WhoisProcessor(lookup, service, query, sd, events, config),
    };
  }
  const job = (data: object, over: object = {}) =>
    ({
      id: 'j',
      queueName: 'whois',
      data: { scannedDomainId: 'sd', domain: 'x.com', scanId: 's', ...data },
      attemptsMade: 1,
      opts: { attempts: 5 },
      ...over,
    }) as unknown as Job;

  it('looks up and stores; skips fresh snapshots unless forced; skips deleted domains', async () => {
    const t = setup();
    expect(await t.p.process(job({}))).toMatchObject({
      whoisInformationId: 'w-1',
      source: 'RDAP',
    });
    expect(await setup({ stale: false }).p.process(job({}))).toEqual({
      skipped: 'fresh snapshot exists',
    });
    expect(
      await setup({ stale: false }).p.process(job({ force: true })),
    ).toMatchObject({ whoisInformationId: 'w-1' });
    expect(await setup({ exists: false }).p.process(job({}))).toEqual({
      skipped: 'scanned domain gone',
    });
  });

  it('emits whois-information.failed only after the final attempt', () => {
    const t = setup();
    const seen = vi.fn();
    t.events.on(WHOIS_EVENTS.FAILED, seen);
    t.p.onFailed(job({}, { attemptsMade: 2 }), new Error('x'));
    t.p.onFailed(job({}, { attemptsMade: 5 }), new Error('rate limited'));
    expect(seen).toHaveBeenCalledOnce();
    expect(seen.mock.calls[0][0]).toMatchObject({
      scannedDomainId: 'sd',
      reason: 'rate limited',
    });
  });
});

describe('WhoisInformationsController', () => {
  const row = {
    id: 'w',
    scannedDomainId: 'sd',
    source: 'RDAP',
    createdDate: new Date('2026-09-01T00:00:00Z'),
    fetchedAt: new Date('2026-10-01T00:00:00Z'),
    rawText: '{}',
    emails: null,
  } as never;

  it('computes domain age and only includes raw text on the detail view', () => {
    expect(toWhoisDto(row)).toMatchObject({ domainAgeDays: 30, emails: [] });
    expect(toWhoisDto(row)).not.toHaveProperty('rawText');
    expect(toWhoisDto(row, true).rawText).toBe('{}');
  });

  it('queues a forced refresh and 404s unknown domains', async () => {
    const enqueuer = {
      enqueue: vi.fn(async () => 'job-1'),
    } as unknown as WhoisEnqueuer;
    const sd = {
      getForEnrichment: vi.fn(async (id: string) =>
        id === 'sd' ? { domain: 'x.com' } : null,
      ),
    } as unknown as ScannedDomainsQuery;
    const query = {
      history: vi.fn(async () => [row]),
      get: vi.fn(async () => row),
    } as unknown as WhoisInformationsQuery;
    const c = new WhoisInformationsController(query, sd, enqueuer);
    expect(await c.refresh('sd')).toEqual({ queued: true, jobId: 'job-1' });
    expect(enqueuer.enqueue).toHaveBeenCalledWith({
      scannedDomainId: 'sd',
      domain: 'x.com',
      force: true,
    });
    expect(await c.history('sd')).toHaveLength(1);
    await expect(c.history('nope')).rejects.toThrow(/not found/);
  });
});
