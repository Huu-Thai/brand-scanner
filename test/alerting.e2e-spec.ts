/**
 * Phase 5 — alerting end to end: channels with encrypted targets, subscriptions, immediate
 * (signed webhook) and digest delivery, idempotency, and the delivery log. Real PostgreSQL /
 * Redis / MinIO; DNS, WHOIS, browser and network rules stubbed; a local HTTP server is the webhook.
 */
import { createHmac } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { getQueueToken } from '@nestjs/bullmq';
import type { INestApplication } from '@nestjs/common';
import type { Queue } from 'bullmq';
import request from 'supertest';
import type { DnsResolution } from '../src/modules/dns-resolver/dns.types.js';
import { KEYS, startStack, type TestStack } from './support/stack.js';

const registered = new Set(['exmple.com', 'exampel.com']);
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

interface Hit {
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function receiver() {
  const hits: Hit[] = [];
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      hits.push({ path: req.url ?? '', headers: req.headers, body });
      res.writeHead(req.url === '/gone' ? 410 : 204).end();
    });
  });
  return {
    hits,
    server,
    listen: () =>
      new Promise<string>((r) =>
        server.listen(0, '127.0.0.1', () =>
          r(`http://127.0.0.1:${(server.address() as { port: number }).port}`),
        ),
      ),
  };
}

describe('alerting (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;
  let base: string;
  const hook = receiver();
  const api = () => request(app.getHttpServer());
  const admin = { 'x-api-key': KEYS.admin, 'x-acting-user': 'ana@example.com' };
  const ids: Record<string, string> = {};
  let secret: string;

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
    base = await hook.listen();
    Object.assign(process.env, {
      TRUSTED_PROXY_KEYS: 'e2e-admin',
      ALERT_ENCRYPTION_KEY: 'c'.repeat(64),
      ALERT_ALLOW_PRIVATE_TARGETS: 'true', // the receiver listens on 127.0.0.1
      ALERT_ALLOW_INSECURE_TARGETS: 'true',
      ALERT_CONSOLE_URL: 'https://console.test',
    });
    const m = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
      import('../src/modules/scans/scans-worker.module.js'),
      import('../src/modules/enrichment-worker.module.js'),
      import('../src/modules/alerts/alerts.module.js'),
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
      { AlertsWorkerModule },
    ] = m;
    const net = m[9];
    const builder = Test.createTestingModule({
      imports: [
        AppModule,
        ScansWorkerModule.forQueues([]),
        EnrichmentWorkerModule.forQueues([]),
        AlertsWorkerModule.forQueues([]),
      ],
    })
      .overrideProvider(m[6].DnsResolverService)
      .useValue({
        resolveMany: async (d: readonly string[]) => d.map(resolution),
        resolve: async (d: string) => resolution(d),
      })
      .overrideProvider(m[7].WhoisLookupService)
      .useValue({ lookup: async () => Promise.reject(new Error('offline')) })
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
  });

  afterAll(async () => {
    await app?.close();
    await new Promise((r) => hook.server.close(r));
    await stack?.stop();
  });

  it('creates channels with encrypted targets; the signing secret is shown once', async () => {
    const created = await api()
      .post('/api/v1/alert-channels')
      .set(admin)
      .send({
        name: 'SOC webhook',
        type: 'WEBHOOK',
        target: `${base}/hook?token=abcd1234`,
      })
      .expect(201);
    expect(created.body).toMatchObject({
      type: 'WEBHOOK',
      signed: true,
      createdBy: 'ana@example.com',
      targetHint: expect.stringMatching(/…1234$/),
    });
    secret = created.body.signingSecret;
    expect(secret).toMatch(/^whsec_/);
    ids.hook = created.body.id;

    const listed = await api()
      .get('/api/v1/alert-channels')
      .set(admin)
      .expect(200);
    expect(JSON.stringify(listed.body)).not.toContain('abcd1234');
    expect(JSON.stringify(listed.body)).not.toContain(secret);

    ids.digest = (
      await api()
        .post('/api/v1/alert-channels')
        .set(admin)
        .send({
          name: 'Daily digest',
          type: 'WEBHOOK',
          target: `${base}/digest`,
        })
        .expect(201)
    ).body.id;
    await api()
      .post('/api/v1/alert-channels')
      .set(admin)
      .send({ name: 'bad', type: 'SLACK', target: `${base}/x` })
      .expect(400);
    await api()
      .post('/api/v1/alert-channels')
      .set({ 'x-api-key': KEYS.reader })
      .send({ name: 'r', type: 'WEBHOOK', target: `${base}/x` })
      .expect(403);

    const test = await api()
      .post(`/api/v1/alert-channels/${ids.hook}/test`)
      .set(admin)
      .expect(200);
    expect(test.body).toEqual({ ok: true });
    expect(hook.hits.at(-1)?.path).toBe('/hook?token=abcd1234');
  });

  it('routes events through subscriptions: immediate signed webhook + daily digest', async () => {
    const brand = await api()
      .post('/api/v1/original-domains')
      .set(admin)
      .send({ domain: 'example.com' })
      .expect(201);
    ids.brand = brand.body.id;
    await api()
      .post('/api/v1/alert-subscriptions')
      .set(admin)
      .send({
        channelId: ids.hook,
        originalDomainId: ids.brand,
        eventTypes: ['CONFIRMED_THREAT', 'HIGH_RISK'],
      })
      .expect(201);
    await api()
      .post('/api/v1/alert-subscriptions')
      .set(admin)
      .send({
        channelId: ids.digest,
        eventTypes: ['NEW_LOOKALIKE'],
        mode: 'DIGEST',
      })
      .expect(201);
    await api()
      .post('/api/v1/alert-subscriptions')
      .set(admin)
      .send({ channelId: ids.hook, eventTypes: [] })
      .expect(400);

    const scan = await api()
      .post('/api/v1/scans')
      .set(admin)
      .send({
        originalDomainId: ids.brand,
        options: {
          fuzzers: ['omission', 'transposition'],
          includeWhois: false,
          includeScreenshots: false,
        },
      })
      .expect(202);
    const lookalikes = await waitFor(async () => {
      const { body } = await api()
        .get(`/api/v1/scanned-domains?scanId=${scan.body.id}`)
        .set(admin);
      return body.total === 2
        ? (body.data as { id: string; domain: string }[])
        : undefined;
    }, 'scan');
    ids.lookalike = lookalikes.find((d) => d.domain === 'exampel.com')!.id;

    // NEW_LOOKALIKE → digest: recorded as PENDING, nothing sent yet.
    await waitFor(async () => {
      const { body } = await api()
        .get(`/api/v1/alert-deliveries?channelId=${ids.digest}`)
        .set(admin);
      return body.total === 2 &&
        body.data.every((d: { status: string }) => d.status === 'PENDING')
        ? true
        : undefined;
    }, 'digest deliveries');
    expect(hook.hits.filter((h) => h.path === '/digest')).toHaveLength(0);

    // CONFIRMED_THREAT → immediate, signed.
    await api()
      .post(`/api/v1/scanned-domains/${ids.lookalike}/reviews`)
      .set(admin)
      .send({ verdict: 'MALICIOUS' })
      .expect(201);
    const hit = await waitFor(
      async () =>
        hook.hits.find(
          (h) =>
            h.path.startsWith('/hook') && h.body.includes('CONFIRMED_THREAT'),
        ),
      'immediate webhook',
    );
    const body = JSON.parse(hit.body);
    expect(body).toMatchObject({
      type: 'fuzzer.alert',
      alert: {
        eventType: 'CONFIRMED_THREAT',
        domain: 'exampel.com',
        brand: 'example.com',
        details: ['Confirmed by ana@example.com'],
        consoleUrl: `https://console.test/lookalikes/${ids.lookalike}`,
      },
    });
    const expected = createHmac('sha256', secret)
      .update(`${hit.headers['x-fuzzer-timestamp']}.${hit.body}`)
      .digest('hex');
    expect(hit.headers['x-fuzzer-signature']).toBe(`sha256=${expected}`);
    await waitFor(async () => {
      const { body: log } = await api()
        .get(`/api/v1/alert-deliveries?channelId=${ids.hook}&status=SENT`)
        .set(admin);
      return log.total === 1 ? true : undefined;
    }, 'delivery marked sent');

    // The daily digest job sends both NEW_LOOKALIKE alerts in ONE message.
    const queue = app.get<Queue>(getQueueToken('alerts'));
    await queue.add('send-digest', {});
    const digest = await waitFor(
      async () => hook.hits.find((h) => h.path === '/digest'),
      'digest webhook',
    );
    const d = JSON.parse(digest.body);
    expect(d.type).toBe('fuzzer.alert.digest');
    expect(d.alerts.map((a: { domain: string }) => a.domain).sort()).toEqual([
      'exampel.com',
      'exmple.com',
    ]);
    await waitFor(async () => {
      const { body: log } = await api()
        .get(`/api/v1/alert-deliveries?channelId=${ids.digest}&status=SENT`)
        .set(admin);
      return log.total === 2 ? true : undefined;
    }, 'digest marked sent');
  });

  it('is idempotent: re-confirming the same look-alike the same day raises nothing new', async () => {
    const before = hook.hits.length;
    await api()
      .patch(`/api/v1/scanned-domains/${ids.lookalike}`)
      .set(admin)
      .send({ status: 'UNDER_REVIEW' })
      .expect(200);
    await api()
      .patch(`/api/v1/scanned-domains/${ids.lookalike}`)
      .set(admin)
      .send({ status: 'CONFIRMED_THREAT' })
      .expect(200);
    await new Promise((r) => setTimeout(r, 2_000));
    expect(hook.hits.length).toBe(before);
    const { body } = await api()
      .get(`/api/v1/alert-deliveries?channelId=${ids.hook}`)
      .set(admin);
    expect(body.total).toBe(1);
  });

  it('marks deliveries to a broken endpoint FAILED without endless retries', async () => {
    const gone = await api()
      .post('/api/v1/alert-channels')
      .set(admin)
      .send({ name: 'Gone', type: 'WEBHOOK', target: `${base}/gone` })
      .expect(201);
    await api()
      .post('/api/v1/alert-subscriptions')
      .set(admin)
      .send({
        channelId: gone.body.id,
        eventTypes: ['WENT_LIVE', 'CONFIRMED_THREAT'],
      })
      .expect(201);
    const other = (
      await api().get('/api/v1/scanned-domains?search=exmple').set(admin)
    ).body.data[0].id;
    await api()
      .post(`/api/v1/scanned-domains/${other}/reviews`)
      .set(admin)
      .send({ verdict: 'MALICIOUS' })
      .expect(201);
    const failed = await waitFor(async () => {
      const { body } = await api()
        .get(`/api/v1/alert-deliveries?channelId=${gone.body.id}&status=FAILED`)
        .set(admin);
      return body.total === 1 ? body.data[0] : undefined;
    }, 'failed delivery');
    expect(failed).toMatchObject({
      attempts: 1,
      lastError: expect.stringMatching(/HTTP 410/),
    });
  });

  it('deleting a channel removes its subscriptions and history', async () => {
    await api()
      .delete(`/api/v1/alert-channels/${ids.digest}`)
      .set(admin)
      .expect(204);
    const subs = await api()
      .get('/api/v1/alert-subscriptions')
      .set(admin)
      .expect(200);
    expect(
      subs.body.find((s: { channelId: string }) => s.channelId === ids.digest),
    ).toBeUndefined();
    const log = await api()
      .get(`/api/v1/alert-deliveries?channelId=${ids.digest}`)
      .set(admin)
      .expect(200);
    expect(log.body.total).toBe(0);
  });
});
