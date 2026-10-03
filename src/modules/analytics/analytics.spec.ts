import type { Job } from 'bullmq';
import { fakeBus } from '../../testing/fake-bus.js';
import type { RuleEngineService } from '../rules/rule-engine.service.js';
import type { DomainScoreResult } from '../rules/rule.types.js';
import type { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import {
  ScannedDomainDiscoveredEvent,
  ScannedDomainUpdatedEvent,
} from '../scanned-domains/events/scanned-domain.events.js';
import {
  WhoisInformationCreatedEvent,
  WhoisInformationFailedEvent,
} from '../whois-informations/events/whois-information.events.js';
import type { WhoisInformationsQuery } from '../whois-informations/whois-informations.query.js';
import type { AnalyticsEnqueuer } from './analytics.enqueuer.js';
import { AnalyticsService, extractSignals } from './analytics.service.js';
import { ANALYTICS_EVENTS } from './events/analytics.events.js';
import { AnalyticsTriggerListener } from './listeners/analytics-trigger.listener.js';
import { AnalyticsProcessor } from './processors/analytics.processor.js';

const result = (
  level: 'LOW_RISK' | 'HIGH_RISK',
  score: number,
): DomainScoreResult => ({
  totalScore: score,
  threatLevel: level,
  thresholds: { thresholdLowRisk: 40, thresholdMediumRisk: 80 },
  ruleResults: [
    {
      key: 'levenshtein_distance',
      matched: true,
      condition: '4',
      value: 2,
      points: 10,
    },
    {
      key: 'domain_age',
      matched: false,
      condition: 'default',
      value: 400,
      points: 0,
    },
    {
      key: 'ssl_issues',
      matched: false,
      condition: 'default',
      value: 'valid',
      points: 0,
    },
    {
      key: 'dmarc_missing',
      matched: true,
      condition: 'missing',
      value: 'missing',
      points: 15,
    },
    {
      key: 'mx_records_found',
      matched: true,
      condition: 'exist',
      value: 'mx1.x',
      points: 15,
    },
    {
      key: 'spamhaus_blacklist',
      matched: false,
      condition: null,
      value: null,
      points: 0,
    },
    {
      key: 'reputation_check',
      matched: true,
      condition: 'found',
      value: 'manage-feed DOMAIN x',
      points: 40,
    },
  ],
});

describe('extractSignals', () => {
  it('denormalises the breakdown; unknown signals stay null', () => {
    expect(extractSignals(result('HIGH_RISK', 80).ruleResults)).toEqual({
      levenshteinDistance: 2,
      domainAgeDays: 400,
      sslStatus: 'valid',
      dmarcPolicy: 'missing',
      hasMx: true,
      spamhausListed: null,
      reputationHit: true,
    });
    expect(
      extractSignals([
        {
          key: 'reputation_check',
          matched: false,
          condition: 'default',
          value: 'unknown: disabled',
          points: 0,
        },
      ]).reputationHit,
    ).toBeNull();
  });
});

describe('AnalyticsService.record', () => {
  function setup() {
    const tx = {
      analytics: {
        create: vi.fn(async ({ data }) => ({ id: 'a-1', ...data })),
      },
    };
    const bus = fakeBus(tx);
    return { service: new AnalyticsService(bus.bus), tx, ...bus };
  }
  const base = {
    scannedDomainId: 'sd',
    originalDomainId: 'od',
    domain: 'x.com',
    scanId: 's',
  };

  it('emits computed, plus a high-risk alert only on the transition into HIGH_RISK', async () => {
    const t = setup();
    await t.service.record({
      ...base,
      previousThreatLevel: 'MEDIUM_RISK',
      result: result('HIGH_RISK', 95),
    });
    expect(t.afterNames()).toEqual([
      ANALYTICS_EVENTS.COMPUTED,
      ANALYTICS_EVENTS.ALERT_HIGH_RISK,
    ]);
    expect(t.after[1]).toMatchObject({
      matchedRules: [
        'levenshtein_distance',
        'dmarc_missing',
        'mx_records_found',
        'reputation_check',
      ],
    });

    const again = setup();
    await again.service.record({
      ...base,
      previousThreatLevel: 'HIGH_RISK',
      result: result('HIGH_RISK', 95),
    });
    expect(again.afterNames()).toEqual([ANALYTICS_EVENTS.COMPUTED]);
  });
});

describe('AnalyticsTriggerListener', () => {
  const flags = (whois: boolean) => ({ whois, screenshots: true });
  it('waits for WHOIS on discovery unless disabled; rescoring on DNS change and WHOIS outcomes', async () => {
    const enqueuer = {
      enqueue: vi.fn(async () => 'j'),
    } as unknown as AnalyticsEnqueuer & { enqueue: ReturnType<typeof vi.fn> };
    const l = new AnalyticsTriggerListener(enqueuer, {
      capturedLookalikes: vi.fn(async () => []),
    } as never);
    await l.onDiscovered(
      new ScannedDomainDiscoveredEvent(
        'sd',
        'od',
        's',
        'x.com',
        true,
        flags(true),
      ),
    );
    expect(enqueuer.enqueue).not.toHaveBeenCalled();
    await l.onDiscovered(
      new ScannedDomainDiscoveredEvent(
        'sd',
        'od',
        's',
        'x.com',
        true,
        flags(false),
      ),
    );
    await l.onDnsChanged(
      new ScannedDomainUpdatedEvent(
        'sd',
        'od',
        's',
        'x.com',
        ['dnsA'],
        true,
        flags(true),
      ),
    );
    await l.onWhois(new WhoisInformationCreatedEvent('w', 'sd', 's', true));
    await l.onWhoisFailed(new WhoisInformationFailedEvent('sd', 's', 'x'));
    expect(enqueuer.enqueue.mock.calls.map((c) => c[1])).toEqual([
      'discovered',
      'dns-changed',
      'whois',
      'whois-failed',
    ]);
  });
});

describe('AnalyticsProcessor', () => {
  it('scores with DNS + parsed WHOIS and records with the previous level', async () => {
    const sd = {
      id: 'sd',
      domain: 'apypal.com',
      originalDomainId: 'od',
      threatLevel: 'UNSCORED',
      dnsA: ['1.2.3.4'],
      dnsAaaa: null,
      dnsMx: [],
      dnsNs: ['ns1'],
      dnsTtl: 300,
      originalDomain: { domain: 'paypal.com' },
    };
    const scanned = {
      getForEnrichment: vi.fn(async () => sd),
    } as unknown as ScannedDomainsQuery;
    const whois = {
      latest: vi.fn(async () => ({
        parseSucceeded: true,
        createdDate: new Date('2020-01-01'),
      })),
    } as unknown as WhoisInformationsQuery;
    const engine = {
      score: vi.fn(async () => result('LOW_RISK', 10)),
    } as unknown as RuleEngineService & { score: ReturnType<typeof vi.fn> };
    const analytics = {
      record: vi.fn(async () => ({ id: 'a-1' })),
    } as unknown as AnalyticsService & { record: ReturnType<typeof vi.fn> };
    const shots = {
      latestCaptured: vi.fn(async () => null),
      reference: vi.fn(async () => null),
    };
    const p = new AnalyticsProcessor(
      scanned,
      whois,
      engine,
      analytics,
      shots as never,
    );
    const job = {
      id: 'j',
      queueName: 'analytics',
      data: { scannedDomainId: 'sd', scanId: 's', trigger: 'whois' },
    } as unknown as Job;
    expect(await p.process(job)).toEqual({
      analyticsId: 'a-1',
      totalScore: 10,
      threatLevel: 'LOW_RISK',
    });
    expect(engine.score).toHaveBeenCalledWith({
      originalDomain: 'paypal.com',
      fuzzerDomain: 'apypal.com',
      dns: { a: ['1.2.3.4'], aaaa: [], mx: [], ns: ['ns1'], ttl: 300 },
      whois: { createdDate: new Date('2020-01-01') },
    });
    expect(analytics.record.mock.calls[0][0]).toMatchObject({
      previousThreatLevel: 'UNSCORED',
      scanId: 's',
    });
  });
});
