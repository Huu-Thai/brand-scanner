/**
 * Phase 3 "done" criterion: an analyst's MALICIOUS review publishes the look-alike as an
 * indicator in manage-feed (threat-feed), and the rest of the analyst workflow — triage,
 * bulk changes, tags, export, rescan, delete — works end to end. Runs API + workers on real
 * PostgreSQL / Redis / MinIO; threat-feed is an in-process HTTP stub with the real API shape.
 */
import { createServer, type Server } from 'node:http';
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { DnsResolution } from '../src/modules/dns-resolver/dns.types.js';
import { KEYS, startStack, type TestStack } from './support/stack.js';

const registered = new Set(['exmple.com', 'exampel.com', 'examle.com']);
const resolution = (domain: string): DnsResolution => ({
  domain,
  nxdomain: !registered.has(domain),
  registered: registered.has(domain),
  a: registered.has(domain) ? ['203.0.113.7'] : [],
  aaaa: [],
  mx: [],
  ns: registered.has(domain) ? ['ns1.parking.example'] : [],
  ttl: registered.has(domain) ? 3600 : null,
  errors: [],
});
const stubDns = {
  resolveMany: async (domains: readonly string[]) => domains.map(resolution),
  resolve: async (domain: string) => resolution(domain),
};

interface Feed {
  id: string;
  value: string;
  type: string;
  severity?: string;
  confidence?: number;
  tags: string[];
  isActive: boolean;
  sourceId: string;
}

/** The slice of the threat-feed API that fuzzer-scanner uses. */
function threatFeedStub() {
  const feeds: Feed[] = [];
  const sources: { id: string; name: string }[] = [];
  const calls: string[] = [];
  let seq = 0;
  const server: Server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      const url = new URL(req.url!, 'http://stub');
      const body = raw ? JSON.parse(raw) : undefined;
      const send = (status: number, payload: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      calls.push(`${req.method} ${url.pathname}`);
      if (url.pathname === '/api/v1/auth/login')
        return send(200, { accessToken: 'h.e30.s' });
      if (req.headers.authorization !== 'Bearer h.e30.s') return send(401, {});
      if (url.pathname === '/api/v1/sources')
        return req.method === 'POST'
          ? send(
              201,
              sources[
                sources.push({ id: `src-${++seq}`, name: body.name }) - 1
              ],
            )
          : send(200, sources);
      if (url.pathname === '/api/v1/feeds' && req.method === 'GET') {
        const search = url.searchParams.get('search')?.toLowerCase() ?? '';
        const active = url.searchParams.get('isActive');
        const data = feeds.filter(
          (f) =>
            f.value.includes(search) &&
            (active === null || String(f.isActive) === active),
        );
        return send(200, { data, total: data.length });
      }
      if (url.pathname === '/api/v1/feeds' && req.method === 'POST') {
        if (feeds.some((f) => f.value === body.value && f.type === body.type))
          return send(409, {});
        const feed = { id: `feed-${++seq}`, tags: [], isActive: true, ...body };
        feeds.push(feed);
        return send(201, feed);
      }
      const m = /^\/api\/v1\/feeds\/([^/]+)$/.exec(url.pathname);
      const feed = m && feeds.find((f) => f.id === m[1]);
      if (feed && req.method === 'PATCH')
        return send(200, Object.assign(feed, body));
      send(404, {});
    });
  });
  return {
    feeds,
    sources,
    calls,
    server,
    listen: () =>
      new Promise<string>((resolve) =>
        server.listen(0, '127.0.0.1', () =>
          resolve(
            `http://127.0.0.1:${(server.address() as { port: number }).port}/api/v1`,
          ),
        ),
      ),
  };
}

describe('analyst workflow (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;
  const tf = threatFeedStub();
  const api = () => request(app.getHttpServer());
  // The admin key is a trusted proxy (like manage-feed's gateway key) so it may name the analyst.
  const analyst = {
    'x-api-key': KEYS.admin,
    'x-acting-user': 'Ana@Example.com',
  };
  const reader = { 'x-api-key': KEYS.reader };
  let ids: Record<string, string>;
  let brandId: string;

  async function waitFor<T>(
    fn: () => Promise<T | undefined>,
    what: string,
    timeoutMs = 30_000,
  ): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const v = await fn();
      if (v !== undefined) return v;
      if (Date.now() > deadline)
        throw new Error(`timed out waiting for ${what}`);
      await new Promise((r) => setTimeout(r, 250));
    }
  }

  beforeAll(async () => {
    stack = await startStack();
    Object.assign(process.env, {
      TRUSTED_PROXY_KEYS: 'e2e-admin',
      THREAT_FEED_ENABLED: 'true',
      THREAT_FEED_PUSH_ENABLED: 'true',
      THREAT_FEED_URL: await tf.listen(),
      THREAT_FEED_EMAIL: 'svc-fuzzer@example.com',
      THREAT_FEED_PASSWORD: 'e2e-threat-feed-password',
      REPUTATION_CACHE_TTL_S: '0',
      REPUTATION_MISS_TTL_S: '0',
    });
    const m = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
      import('../src/modules/scans/scans-worker.module.js'),
      import('../src/modules/enrichment-worker.module.js'),
      import('../src/modules/dns-resolver/dns-resolver.service.js'),
      import('../src/modules/whois-informations/lookup/whois-lookup.service.js'),
      import('../src/modules/screenshots/capture/selenium-capture.service.js'),
      import('../src/modules/rules/rules/network.rules.js'),
    ]);
    const [
      { Test },
      { AppModule },
      { configureApp },
      { ScansWorkerModule },
      { EnrichmentWorkerModule },
    ] = m;
    const net = m[8];
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
      .useValue({
        lookup: async () => {
          throw new Error('WHOIS is offline in this test');
        },
      })
      .overrideProvider(m[7].SeleniumCaptureService)
      .useValue({
        capture: async () => {
          throw new Error('browser is offline in this test');
        },
      });
    for (const [Rule, condition, value] of [
      [net.DmarcMissingRule, 'missing', 'missing'],
      [net.SslIssuesRule, 'default', 'valid'],
      [net.SpamhausBlacklistRule, 'default', 'not listed'],
    ] as const) {
      const instance = new (
        Rule as unknown as new (dep: unknown) => { resolveCondition: unknown }
      )({
        get: () => ({}),
      });
      instance.resolveCondition = () => ({ condition, value });
      builder.overrideProvider(Rule).useValue(instance);
    }
    app = (await builder.compile()).createNestApplication({ bufferLogs: true });
    configureApp(app);
    await app.init();

    const od = await api()
      .post('/api/v1/original-domains')
      .set(analyst)
      .send({ domain: 'example.com' })
      .expect(201);
    brandId = od.body.id;
    const scan = await api()
      .post('/api/v1/scans')
      .set(analyst)
      .send({
        originalDomainId: brandId,
        options: {
          fuzzers: ['omission', 'transposition'],
          includeWhois: false,
          includeScreenshots: false,
        },
      })
      .expect(202);
    ids = await waitFor(async () => {
      const { body } = await api()
        .get(`/api/v1/scanned-domains?scanId=${scan.body.id}`)
        .set(reader);
      return body.total === 3
        ? Object.fromEntries(
            body.data.map((d: { domain: string; id: string }) => [
              d.domain,
              d.id,
            ]),
          )
        : undefined;
    }, 'scan results');
  });

  afterAll(async () => {
    await app?.close();
    await new Promise((r) => tf.server.close(r));
    await stack?.stop();
  });

  it('a MALICIOUS review confirms the look-alike and publishes it to manage-feed', async () => {
    const review = await api()
      .post(`/api/v1/scanned-domains/${ids['exampel.com']}/reviews`)
      .set(analyst)
      .send({ verdict: 'MALICIOUS', notes: '  Credential phishing kit  ' })
      .expect(201);
    expect(review.body).toMatchObject({
      domain: 'exampel.com',
      verdict: 'MALICIOUS',
      notes: 'Credential phishing kit',
      reviewer: 'ana@example.com',
      previousStatus: 'NEW',
      newStatus: 'CONFIRMED_THREAT',
    });

    const sd = await waitFor(async () => {
      const { body } = await api()
        .get(`/api/v1/scanned-domains/${ids['exampel.com']}`)
        .set(reader);
      return body.status === 'CONFIRMED_THREAT' ? body : undefined;
    }, 'status change');
    expect(sd.originalDomain).toBe('example.com');

    const feed = await waitFor(
      async () => tf.feeds.find((f) => f.value === 'exampel.com'),
      'indicator push',
    );
    expect(feed).toMatchObject({
      type: 'DOMAIN',
      isActive: true,
      severity: expect.stringMatching(/^(high|critical)$/),
      confidence: 95,
      sourceId: tf.sources[0].id,
      tags: expect.arrayContaining([
        'typosquat',
        'source:fuzzer-scanner',
        'brand:example.com',
      ]),
    });
    expect(tf.sources).toEqual([
      { id: tf.sources[0].id, name: 'Fuzzer Scanner' },
    ]);

    const history = await api()
      .get(`/api/v1/scanned-domains/${ids['exampel.com']}/reviews`)
      .set(reader)
      .expect(200);
    expect(history.body).toHaveLength(1);
  });

  it('a later FALSE_POSITIVE review retires the indicator (kept, inactive)', async () => {
    await api()
      .post(`/api/v1/scanned-domains/${ids['exampel.com']}/reviews`)
      .set(analyst)
      .send({ verdict: 'FALSE_POSITIVE' })
      .expect(201);
    await waitFor(
      async () =>
        tf.feeds.find((f) => f.value === 'exampel.com')?.isActive === false
          ? true
          : undefined,
      'deactivation',
    );
    expect(tf.feeds.filter((f) => f.value === 'exampel.com')).toHaveLength(1);

    const queue = await api()
      .get(`/api/v1/reviews?verdict=FALSE_POSITIVE&reviewer=ana@example.com`)
      .set(reader)
      .expect(200);
    expect(queue.body).toMatchObject({
      total: 1,
      data: [{ domain: 'exampel.com', previousStatus: 'CONFIRMED_THREAT' }],
    });
  });

  it('enforces status rules and atomic bulk changes', async () => {
    // TAKEN_DOWN requires CONFIRMED_THREAT: the whole bulk is rejected, nothing changes.
    const rejected = await api()
      .patch('/api/v1/scanned-domains/bulk')
      .set(analyst)
      .send({
        ids: [ids['exmple.com'], ids['examle.com']],
        status: 'TAKEN_DOWN',
      })
      .expect(422);
    expect(rejected.body.message.join(' ')).toMatch(
      /Only a CONFIRMED_THREAT can be marked TAKEN_DOWN/,
    );

    const bulk = await api()
      .patch('/api/v1/scanned-domains/bulk')
      .set(analyst)
      .send({
        ids: [ids['exmple.com'], ids['examle.com']],
        status: 'UNDER_REVIEW',
        addTags: ['Campaign-42', 'vip'],
      })
      .expect(200);
    expect(bulk.body).toEqual({ statusChanged: 2, tagsUpdated: 2 });

    const one = await api()
      .patch(`/api/v1/scanned-domains/${ids['examle.com']}`)
      .set(analyst)
      .send({ removeTags: ['vip'] })
      .expect(200);
    expect(one.body).toMatchObject({
      status: 'UNDER_REVIEW',
      tags: ['campaign-42'],
    });

    // Scan-owned statuses cannot be set by hand; readers cannot write.
    await api()
      .patch(`/api/v1/scanned-domains/${ids['examle.com']}`)
      .set(analyst)
      .send({ status: 'PARKED' })
      .expect(400);
    await api()
      .patch(`/api/v1/scanned-domains/${ids['examle.com']}`)
      .set(reader)
      .send({ status: 'ACTIVE' })
      .expect(403);
    await api()
      .post(`/api/v1/scanned-domains/${ids['examle.com']}/reviews`)
      .set(reader)
      .send({ verdict: 'BENIGN' })
      .expect(403);

    // Only UNDER_REVIEW items were touched — none of this reaches threat-feed.
    expect(tf.feeds.map((f) => f.value)).toEqual(['exampel.com']);
  });

  it('exports the filtered list as CSV and STIX', async () => {
    const csv = await api()
      .get(
        `/api/v1/scanned-domains/export?format=csv&originalDomainId=${brandId}&status=UNDER_REVIEW`,
      )
      .set(reader)
      .expect(200);
    expect(csv.headers['content-type']).toMatch(/text\/csv/);
    expect(csv.headers['content-disposition']).toMatch(
      /attachment; filename="lookalikes-.*\.csv"/,
    );
    const lines = csv.text.trimEnd().split('\r\n');
    expect(lines[0]).toMatch(/^domain,unicode_domain,original_domain,/);
    expect(
      lines
        .slice(1)
        .map((l) => l.split(',')[0])
        .sort(),
    ).toEqual(['examle.com', 'exmple.com']);

    const stix = await api()
      .get(
        `/api/v1/scanned-domains/export?format=stix&originalDomainId=${brandId}`,
      )
      .set(reader)
      .buffer(true)
      .parse((res, cb) => {
        let data = '';
        res.on('data', (c: Buffer) => (data += c));
        res.on('end', () => cb(null, data));
      })
      .expect(200);
    const bundle = JSON.parse(stix.body as string);
    expect(bundle.type).toBe('bundle');
    expect(
      bundle.objects.filter((o: { type: string }) => o.type === 'indicator'),
    ).toHaveLength(3);
  });

  it('rescans a look-alike on demand and soft-deletes it', async () => {
    const id = ids['exmple.com'];
    const before = (
      await api().get(`/api/v1/scanned-domains/${id}`).set(reader)
    ).body.lastSeenAt;
    const queued = await api()
      .post(`/api/v1/scanned-domains/${id}/rescan`)
      .set(analyst)
      .expect(202);
    expect(queued.body).toMatchObject({
      queued: true,
      jobId: expect.stringMatching(/^rescan-/),
    });
    await waitFor(async () => {
      const { body } = await api()
        .get(`/api/v1/scanned-domains/${id}`)
        .set(reader);
      return body.lastSeenAt !== before ? true : undefined;
    }, 'rescan');

    await api()
      .delete(`/api/v1/scanned-domains/${id}`)
      .set(analyst)
      .expect(204);
    await api().get(`/api/v1/scanned-domains/${id}`).set(reader).expect(404);
    await api()
      .delete(`/api/v1/scanned-domains/${id}`)
      .set(analyst)
      .expect(404);
    await api()
      .post(`/api/v1/scanned-domains/${id}/rescan`)
      .set(analyst)
      .expect(404);
    await api()
      .post(`/api/v1/scanned-domains/${id}/reviews`)
      .set(analyst)
      .send({ verdict: 'BENIGN' })
      .expect(404);
  });

  it('attributes requests without x-acting-user to the API key', async () => {
    const r = await api()
      .post(`/api/v1/scanned-domains/${ids['examle.com']}/reviews`)
      .set({ 'x-api-key': KEYS.admin })
      .send({ verdict: 'NEEDS_INFO' })
      .expect(201);
    expect(r.body.reviewer).toBe('e2e-admin');
  });
});
