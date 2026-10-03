/**
 * Phase 2 "done" criterion: every discovered look-alike gets WHOIS, a screenshot and a score,
 * and reputation hits come from manage-feed indicators. Runs API + all workers against real
 * PostgreSQL, password-protected Redis (BullMQ) and MinIO. External network edges are stubbed
 * for determinism: DNS, WHOIS/RDAP, the browser, threat-feed and the network-probing rules.
 */
import type { INestApplication } from '@nestjs/common';
import sharp from 'sharp';
import request from 'supertest';
import type { DnsResolution } from '../src/modules/dns-resolver/dns.types.js';
import { KEYS, startStack, type TestStack } from './support/stack.js';

const registered = new Set(['exmple.com', 'exampel.com', 'examle.com']);

const stubDns = {
  resolveMany: async (domains: readonly string[]): Promise<DnsResolution[]> =>
    domains.map((domain) => ({
      domain,
      nxdomain: !registered.has(domain),
      registered: registered.has(domain),
      a: registered.has(domain) ? ['203.0.113.7'] : [],
      aaaa: [],
      mx: domain === 'exampel.com' ? ['mx.exampel.com'] : [],
      ns: registered.has(domain) ? ['ns1.parking.example'] : [],
      ttl: registered.has(domain) ? 120 : null,
      errors: [],
    })),
};

const stubWhois = {
  lookup: async (domain: string) => ({
    source: 'RDAP' as const,
    queriedDomain: domain,
    rawText: '{"stub":true}',
    parseSucceeded: true,
    record: {
      registrar: 'Stub Registrar',
      emails: ['abuse@stub.example'],
      abuseEmail: 'abuse@stub.example',
      nameServers: ['ns1.parking.example'],
      statuses: ['active'],
      // exampel.com was "registered" 3 days ago → domain_age fires
      createdDate: new Date(
        Date.now() - (domain === 'exampel.com' ? 3 : 900) * 86_400_000,
      ),
    },
  }),
};

let pngBytes: Buffer;
/** The brand's own site: a strong left→right gradient, i.e. visually unlike the look-alikes. */
let brandPng: Buffer;
const stubCapture = {
  capture: async (domain: string) => ({
    png: domain === 'example.com' ? brandPng : pngBytes,
    requestedUrl: `https://${domain}/`,
    finalUrl: `https://${domain}/landing`,
    pageTitle: `Parked: ${domain}`,
    httpStatus: 200,
  }),
};

/** manage-feed has exampel.com as an active DOMAIN indicator. */
const stubReputation = {
  check: async (domain: string) =>
    domain === 'exampel.com'
      ? {
          status: 'found',
          indicatorType: 'DOMAIN',
          value: domain,
          severity: 'high',
        }
      : { status: 'not_found' },
};

describe('enrichment pipeline (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;
  const api = () => request(app.getHttpServer());
  const auth = { 'x-api-key': KEYS.admin };

  beforeAll(async () => {
    pngBytes = await sharp({
      create: { width: 40, height: 20, channels: 3, background: '#336699' },
    })
      .png()
      .toBuffer();
    const gradient = Buffer.alloc(90 * 80 * 3);
    for (let y = 0; y < 80; y++)
      for (let x = 0; x < 90; x++)
        gradient.fill(
          255 - Math.floor((x / 89) * 255),
          (y * 90 + x) * 3,
          (y * 90 + x) * 3 + 3,
        );
    brandPng = await sharp(gradient, {
      raw: { width: 90, height: 80, channels: 3 },
    })
      .png()
      .toBuffer();
    stack = await startStack();
    const m = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
      import('../src/modules/scans/scans-worker.module.js'),
      import('../src/modules/enrichment-worker.module.js'),
      import('../src/modules/dns-resolver/dns-resolver.service.js'),
      import('../src/modules/whois-informations/lookup/whois-lookup.service.js'),
      import('../src/modules/screenshots/capture/selenium-capture.service.js'),
      import('../src/integrations/threat-feed/reputation.service.js'),
      import('../src/modules/rules/rules/network.rules.js'),
    ]);
    const [
      { Test },
      { AppModule },
      { configureApp },
      { ScansWorkerModule },
      { EnrichmentWorkerModule },
    ] = m;
    const net = m[9];
    const builder = Test.createTestingModule({
      imports: [
        AppModule,
        ScansWorkerModule.forQueues([]),
        EnrichmentWorkerModule.forQueues([]),
      ],
    })
      .overrideProvider(m[5].DnsResolverService)
      .useValue(stubDns)
      .overrideProvider(m[6].WhoisLookupService)
      .useValue(stubWhois)
      .overrideProvider(m[7].SeleniumCaptureService)
      .useValue(stubCapture)
      .overrideProvider(m[8].ReputationService)
      .useValue(stubReputation);
    // Network-probing rules → deterministic offline answers (their logic is unit-tested).
    for (const [Rule, condition, value] of [
      [net.DmarcMissingRule, 'missing', 'missing'],
      [net.SslIssuesRule, 'default', 'valid'],
      [net.SpamhausBlacklistRule, 'default', 'not listed'],
    ] as const) {
      // Real rule class (so BaseRule.evaluate and tiers apply) with the network call replaced.
      const instance = new (
        Rule as unknown as new (dep: unknown) => { resolveCondition: unknown }
      )({ get: () => ({}) });
      instance.resolveCondition = () => ({ condition, value });
      builder.overrideProvider(Rule).useValue(instance);
    }
    const moduleRef = await builder.compile();
    app = moduleRef.createNestApplication({ bufferLogs: true });
    configureApp(app);
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
    await stack?.stop();
  });

  async function waitFor<T>(
    fn: () => Promise<T | undefined>,
    timeoutMs = 60_000,
  ): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const v = await fn();
      if (v !== undefined) return v;
      if (Date.now() > deadline)
        throw new Error('timed out waiting for enrichment');
      await new Promise((r) => setTimeout(r, 300));
    }
  }

  it('enriches every discovered look-alike: WHOIS, stored screenshot, score with reputation from manage-feed', async () => {
    const od = await api()
      .post('/api/v1/original-domains')
      .set(auth)
      .send({ domain: 'example.com' })
      .expect(201);
    const scan = await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({
        originalDomainId: od.body.id,
        options: { fuzzers: ['omission', 'transposition'] },
      })
      .expect(202);

    const domains = await waitFor(async () => {
      const { body } = await api()
        .get(
          `/api/v1/scanned-domains?scanId=${scan.body.id}&sort=domain&order=asc`,
        )
        .set(auth);
      return body.total === 3 &&
        body.data.every(
          (d: { threatLevel: string }) => d.threatLevel !== 'UNSCORED',
        )
        ? (body.data as {
            id: string;
            domain: string;
            riskScore: number;
            threatLevel: string;
          }[])
        : undefined;
    });
    expect(domains.map((d) => d.domain)).toEqual([
      'examle.com',
      'exampel.com',
      'exmple.com',
    ]);

    for (const d of domains) {
      const whois = await api()
        .get(`/api/v1/scanned-domains/${d.id}/whois`)
        .set(auth)
        .expect(200);
      expect(whois.body[0]).toMatchObject({
        source: 'RDAP',
        registrar: 'Stub Registrar',
        parseSucceeded: true,
      });

      const shots = await waitFor(async () => {
        const { body } = await api()
          .get(`/api/v1/scanned-domains/${d.id}/screenshots`)
          .set(auth);
        return body.length ? body : undefined;
      });
      expect(shots[0]).toMatchObject({
        status: 'CAPTURED',
        httpStatus: 200,
        width: 40,
        height: 20,
        pageTitle: `Parked: ${d.domain}`,
      });

      // The image endpoint redirects to a presigned MinIO URL that serves the exact bytes.
      const img = await api().get(shots[0].imageUrl).set(auth).expect(302);
      const bytes = Buffer.from(
        await (await fetch(img.headers.location)).arrayBuffer(),
      );
      expect(bytes.equals(pngBytes)).toBe(true);
    }

    const hit = domains.find((d) => d.domain === 'exampel.com')!;
    const analytics = await api()
      .get(`/api/v1/scanned-domains/${hit.id}/analytics`)
      .set(auth)
      .expect(200);
    const latest = analytics.body[0];
    // levenshtein 10 + dmarc 15 + domain_age 20 + reputation 40 + mx 15 + dns 10 + low_ttl 15 = 125
    expect(latest).toMatchObject({
      totalScore: 125,
      threatLevel: 'HIGH_RISK',
      reputationHit: true,
      hasMx: true,
      domainAgeDays: 3,
    });
    // The brand site was captured as the reference; the look-alike looks nothing like it.
    expect(
      latest.ruleResults.find(
        (r: { key: string }) => r.key === 'visual_similarity',
      ),
    ).toMatchObject({
      matched: false,
      points: 0,
      value: expect.stringMatching(/% similar to the brand site$/),
    });
    expect(
      latest.ruleResults.find(
        (r: { key: string }) => r.key === 'reputation_check',
      ),
    ).toMatchObject({
      matched: true,
      value: 'manage-feed DOMAIN exampel.com',
      points: 40,
    });
    expect(hit).toMatchObject({ riskScore: 125, threatLevel: 'HIGH_RISK' });

    const clean = domains.find((d) => d.domain === 'exmple.com')!;
    expect(clean.threatLevel).toBe('MEDIUM_RISK'); // 10 + 15 + 10 + 15 = 50

    const summary = await api()
      .get(`/api/v1/analytics/summary?originalDomainId=${od.body.id}`)
      .set(auth)
      .expect(200);
    expect(summary.body).toMatchObject({
      total: 3,
      byThreatLevel: { HIGH_RISK: 1, MEDIUM_RISK: 2 },
    });
    const trends = await api()
      .get(`/api/v1/analytics/trends?originalDomainId=${od.body.id}&days=7`)
      .set(auth)
      .expect(200);
    expect(trends.body).toHaveLength(7);
    expect(trends.body[6]).toMatchObject({ newLookalikes: 3, highRisk: 1 });
  });

  it('rule edits apply immediately (cache invalidated) and rescoring uses them', async () => {
    await api()
      .patch('/api/v1/scoring/rules/reputation_check')
      .set({ 'x-api-key': KEYS.reader })
      .send({ enabled: false })
      .expect(403); // admin scope required
    await api()
      .patch('/api/v1/scoring/rules/reputation_check')
      .set(auth)
      .send({ enabled: false })
      .expect(200);

    const { body } = await api()
      .get('/api/v1/scanned-domains?search=exampel')
      .set(auth);
    const id = body.data[0].id;
    await api()
      .post(`/api/v1/scanned-domains/${id}/analytics/rescore`)
      .set(auth)
      .expect(202);
    const rescored = await waitFor(async () => {
      const r = await api()
        .get(`/api/v1/scanned-domains/${id}/analytics`)
        .set(auth);
      return r.body[0]?.totalScore === 85 ? r.body[0] : undefined;
    });
    expect(rescored.threatLevel).toBe('HIGH_RISK'); // 125 − 40 = 85 ≥ 80
    await api()
      .put('/api/v1/scoring/thresholds')
      .set(auth)
      .send({ thresholdLowRisk: 90, thresholdMediumRisk: 40 })
      .expect(400);
  });

  it('manual WHOIS refresh and recapture are queued', async () => {
    const { body } = await api()
      .get('/api/v1/scanned-domains?search=exmple')
      .set(auth);
    const id = body.data[0].id;
    await api()
      .post(`/api/v1/scanned-domains/${id}/whois/refresh`)
      .set(auth)
      .expect(202);
    await api()
      .post(`/api/v1/scanned-domains/${id}/screenshots`)
      .set(auth)
      .expect(202);
    await waitFor(async () => {
      const [w, s] = await Promise.all([
        api().get(`/api/v1/scanned-domains/${id}/whois`).set(auth),
        api().get(`/api/v1/scanned-domains/${id}/screenshots`).set(auth),
      ]);
      return w.body.length === 2 && s.body.length === 2 ? true : undefined;
    });
  });
});
