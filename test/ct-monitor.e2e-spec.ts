/**
 * Phase 5 — Certificate Transparency monitoring end to end: a local certstream-compatible server
 * emits certificates; matching look-alikes are tracked (technique ct:<kind>), enriched by the
 * normal pipeline, and kept alive by later full scans. Real PostgreSQL / Redis / MinIO.
 */
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { WebSocketServer, type WebSocket } from 'ws';
import type { DnsResolution } from '../src/modules/dns-resolver/dns.types.js';
import { KEYS, startStack, type TestStack } from './support/stack.js';

// Registered in our stub DNS: the CT finds, plus two fuzzer permutations.
const registered = new Set([
  'paypal-secure-login.com',
  'paypa1.com',
  'paypall.com',
]);
const resolution = (domain: string): DnsResolution => ({
  domain,
  nxdomain: !registered.has(domain),
  registered: registered.has(domain),
  a: registered.has(domain) ? ['203.0.113.9'] : [],
  aaaa: [],
  mx: [],
  ns: registered.has(domain) ? ['ns1.bulletproof.example'] : [],
  ttl: registered.has(domain) ? 300 : null,
  errors: [],
});

const cert = (...names: string[]) =>
  JSON.stringify({
    message_type: 'certificate_update',
    data: { leaf_cert: { all_domains: names } },
  });

describe('CT monitoring (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;
  let wss: WebSocketServer;
  let client: WebSocket | undefined;
  const api = () => request(app.getHttpServer());
  const admin = { 'x-api-key': KEYS.admin };
  let brandId: string;

  async function waitFor<T>(
    fn: () => Promise<T | undefined>,
    what: string,
    ms = 30_000,
  ): Promise<T> {
    const deadline = Date.now() + ms;
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
    wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise((r) => wss.once('listening', r));
    wss.on('connection', (socket) => (client = socket));
    Object.assign(process.env, {
      CT_MONITOR_ENABLED: 'true',
      CT_STREAM_URL: `ws://127.0.0.1:${(wss.address() as { port: number }).port}/`,
    });
    const m = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
      import('../src/modules/scans/scans-worker.module.js'),
      import('../src/modules/enrichment-worker.module.js'),
      import('../src/modules/ct-monitor/ct-monitor.module.js'),
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
      { CtMonitorWorkerModule },
    ] = m;
    const net = m[9];
    const builder = Test.createTestingModule({
      imports: [
        AppModule,
        ScansWorkerModule.forQueues([]),
        EnrichmentWorkerModule.forQueues([]),
        CtMonitorWorkerModule.forQueues([]),
      ],
    })
      .overrideProvider(m[6].DnsResolverService)
      .useValue({
        resolveMany: async (d: readonly string[]) => d.map(resolution),
        resolve: async (d: string) => resolution(d),
      })
      .overrideProvider(m[7].WhoisLookupService)
      .useValue({
        lookup: async (domain: string) => ({
          source: 'RDAP' as const,
          queriedDomain: domain,
          rawText: '{"stub":true}',
          parseSucceeded: true,
          record: {
            registrar: 'Stub Registrar',
            emails: [],
            nameServers: ['ns1.bulletproof.example'],
            statuses: ['active'],
            createdDate: new Date(Date.now() - 2 * 86_400_000), // registered 2 days ago
          },
        }),
      })
      .overrideProvider(m[8].SeleniumCaptureService)
      .useValue({ capture: async () => Promise.reject(new Error('offline')) });
    for (const Rule of [
      net.DmarcMissingRule,
      net.SslIssuesRule,
      net.SpamhausBlacklistRule,
    ]) {
      const instance = new (
        Rule as unknown as new (dep: unknown) => { resolveCondition: unknown }
      )({ get: () => ({}) });
      instance.resolveCondition = () => ({
        condition: 'default',
        value: 'stub',
      });
      builder.overrideProvider(Rule).useValue(instance);
    }
    app = (await builder.compile()).createNestApplication({ bufferLogs: true });
    configureApp(app);
    await app.init();
    brandId = (
      await api()
        .post('/api/v1/original-domains')
        .set(admin)
        .send({ domain: 'paypal.com' })
        .expect(201)
    ).body.id;
  });

  afterAll(async () => {
    await app?.close();
    await new Promise((r) => wss.close(r));
    await stack?.stop();
  });

  const lookalike = async (domain: string) => {
    const { body } = await api()
      .get(
        `/api/v1/scanned-domains?originalDomainId=${brandId}&search=${domain}`,
      )
      .set(admin);
    return (
      body.data as {
        domain: string;
        id: string;
        fuzzer: string;
        status: string;
        threatLevel: string;
      }[]
    ).find((d) => d.domain === domain);
  };

  it('connects as the single CT consumer', async () => {
    await waitFor(async () => (client ? true : undefined), 'stream connection');
    // Brands are cached for a minute, but the first message loads them.
    const status = await waitFor(async () => {
      client!.send(JSON.stringify({ message_type: 'heartbeat' }));
      const { body } = await api().get('/api/v1/ct-monitor/status').set(admin);
      return body.leaderElected ? body : undefined;
    }, 'leader');
    expect(status).toMatchObject({ enabled: true, leaderElected: true });
  });

  it('tracks a certificate look-alike and enriches it through the normal pipeline', async () => {
    client!.send(cert('example.org', 'www.example.org')); // unrelated
    client!.send(
      cert('paypal-secure-login.com', 'www.paypal-secure-login.com'),
    ); // combo
    client!.send(cert('paypal-unregistered-yet.com')); // matches, but not in DNS
    const d = await waitFor(
      () => lookalike('paypal-secure-login.com'),
      'CT look-alike',
    );
    expect(d).toMatchObject({ fuzzer: 'ct:combo', status: 'NEW' });
    // Scoring runs for it like for any discovered look-alike.
    await waitFor(
      async () =>
        (await lookalike('paypal-secure-login.com'))?.threatLevel !== 'UNSCORED'
          ? true
          : undefined,
      'scored',
    );
    expect(await lookalike('paypal-unregistered-yet.com')).toBeUndefined();
    expect(await lookalike('example.org')).toBeUndefined();

    const status = await waitFor(async () => {
      const { body } = await api().get('/api/v1/ct-monitor/status').set(admin);
      return body.matches >= 2 ? body : undefined;
    }, 'stats flushed');
    expect(status).toMatchObject({
      connected: true,
      certificates: expect.any(Number),
    });
  });

  it('a duplicate certificate (renewal) is not queued again', async () => {
    client!.send(cert('paypal-secure-login.com'));
    await new Promise((r) => setTimeout(r, 1_500));
    const { body } = await api()
      .get(`/api/v1/scanned-domains?originalDomainId=${brandId}`)
      .set(admin);
    expect(
      body.data.filter(
        (x: { domain: string }) => x.domain === 'paypal-secure-login.com',
      ),
    ).toHaveLength(1);
  });

  it('full scans keep CT finds alive instead of marking them INACTIVE', async () => {
    const scan = await api()
      .post('/api/v1/scans')
      .set(admin)
      .send({
        originalDomainId: brandId,
        options: { includeWhois: false, includeScreenshots: false },
      })
      .expect(202);
    const done = await waitFor(
      async () => {
        const { body } = await api()
          .get(`/api/v1/scans/${scan.body.id}`)
          .set(admin);
        return body.status === 'COMPLETED' ? body : undefined;
      },
      'full scan',
      60_000,
    );
    // The CT domain was re-resolved in the scan (permutations + 1) and found registered again.
    expect(done.registeredCount).toBe(3);
    const ct = await lookalike('paypal-secure-login.com');
    expect(ct).toMatchObject({ fuzzer: 'ct:combo', status: 'ACTIVE' });
    expect(await lookalike('paypa1.com')).toMatchObject({
      fuzzer: expect.not.stringMatching(/^ct:/),
    });
  });
});
