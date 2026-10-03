/**
 * Phase 1 "done" criterion: POST /scans discovers registered permutations end to end.
 * API + worker processors run in one app against real PostgreSQL and password-protected
 * Redis (BullMQ flows, schedulers, transactions, events). Only DNS is stubbed — real public
 * DNS would make the test slow and non-deterministic.
 */
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { DnsResolution } from '../src/modules/dns-resolver/dns.types.js';
import { KEYS, startStack, type TestStack } from './support/stack.js';

/** Look-alikes that "exist" in the stub DNS. Mutable so a later scan can see one disappear. */
const registered = new Set([
  'exmple.com',
  'xeample.com',
  'exampl.com',
  'examle.com',
]);

const stubDns = {
  resolveMany: async (domains: readonly string[]): Promise<DnsResolution[]> =>
    domains.map((domain) => {
      const exists = registered.has(domain);
      return {
        domain,
        nxdomain: !exists,
        registered: exists,
        a: exists ? ['192.0.2.10'] : [],
        aaaa: [],
        mx: exists && domain.startsWith('ex') ? ['mx.' + domain] : [],
        ns: exists ? ['ns1.' + domain] : [],
        ttl: exists ? 300 : null,
        errors: [],
      };
    }),
};

describe('scan pipeline (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;
  let originalDomainId: string;
  const api = () => request(app.getHttpServer());
  const auth = { 'x-api-key': KEYS.admin };

  async function waitForScan(id: string, timeoutMs = 60_000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const { body } = await api()
        .get(`/api/v1/scans/${id}`)
        .set(auth)
        .expect(200);
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(body.status))
        return body;
      if (Date.now() > deadline)
        throw new Error(`scan ${id} still ${body.status}`);
      await new Promise((r) => setTimeout(r, 250));
    }
  }

  beforeAll(async () => {
    stack = await startStack();
    process.env.SCAN_BATCH_SIZE = '50'; // several DNS batches per scan → exercises the flow fan-out
    const [
      { Test },
      { AppModule },
      { configureApp },
      { ScansWorkerModule },
      { DnsResolverService },
    ] = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
      import('../src/modules/scans/scans-worker.module.js'),
      import('../src/modules/dns-resolver/dns-resolver.service.js'),
    ]);
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule, ScansWorkerModule.forQueues([])],
    })
      .overrideProvider(DnsResolverService)
      .useValue(stubDns)
      .compile();
    app = moduleRef.createNestApplication({ bufferLogs: true });
    configureApp(app);
    await app.init();

    const { body } = await api()
      .post('/api/v1/original-domains')
      .set(auth)
      .send({ domain: 'Example.com', label: 'e2e brand' })
      .expect(201);
    originalDomainId = body.id;
  });

  afterAll(async () => {
    await app?.close();
    await stack?.stop();
  });

  it('discovers registered permutations for a subset scan', async () => {
    const res = await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({
        domain: 'example.com',
        options: { fuzzers: ['omission', 'transposition', 'replacement'] },
      })
      .expect(202);
    expect(res.headers.location).toBe(`/api/v1/scans/${res.body.id}`);

    const scan = await waitForScan(res.body.id);
    expect(scan).toMatchObject({
      status: 'COMPLETED',
      registeredCount: 4,
      newCount: 4,
      failedCount: 0,
      progressPercent: 100,
    });
    expect(scan.permutationsTotal).toBeGreaterThan(100); // replacement alone yields > 200 → several batches of 50
    expect(scan.resolvedCount).toBe(scan.permutationsTotal);

    const list = await api()
      .get(`/api/v1/scanned-domains?scanId=${scan.id}&sort=domain&order=asc`)
      .set(auth)
      .expect(200);
    expect(list.body.data.map((d: { domain: string }) => d.domain)).toEqual(
      [...registered].sort(),
    );
    expect(list.body.data[0]).toMatchObject({
      status: 'NEW',
      threatLevel: 'UNSCORED',
      dnsA: ['192.0.2.10'],
      dnsTtl: 300,
    });

    const od = await api()
      .get(`/api/v1/original-domains/${originalDomainId}`)
      .set(auth)
      .expect(200);
    expect(od.body.lastScannedAt).not.toBeNull();
    expect(od.body.stats).toMatchObject({
      trackedDomains: 4,
      latestScan: { id: scan.id, status: 'COMPLETED' },
    });
  });

  it('runs at most one scan per domain even under concurrent triggers', async () => {
    const responses = await Promise.all(
      Array.from({ length: 6 }, () =>
        api()
          .post(`/api/v1/original-domains/${originalDomainId}/scans`)
          .set(auth)
          .send({ options: { fuzzers: ['omission'] } }),
      ),
    );
    const statuses = responses.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 200, 200, 200, 200, 202]);
    expect(new Set(responses.map((r) => r.body.id)).size).toBe(1);
    await waitForScan(responses[0].body.id);
  });

  it('replays an Idempotency-Key and rejects malformed keys', async () => {
    const first = await api()
      .post('/api/v1/scans')
      .set({ ...auth, 'Idempotency-Key': 'e2e-idem-0001' })
      .send({ originalDomainId, options: { fuzzers: ['omission'] } })
      .expect(202);
    await waitForScan(first.body.id);
    const replay = await api()
      .post('/api/v1/scans')
      .set({ ...auth, 'Idempotency-Key': 'e2e-idem-0001' })
      .send({ originalDomainId })
      .expect(200);
    expect(replay.body.id).toBe(first.body.id);
    await api()
      .post('/api/v1/scans')
      .set({ ...auth, 'Idempotency-Key': 'bad key' })
      .send({ originalDomainId })
      .expect(400);
  });

  it('a full scan marks look-alikes that stopped resolving as INACTIVE, and revives returning ones', async () => {
    const first = await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({ originalDomainId })
      .expect(202);
    const done = await waitForScan(first.body.id, 120_000);
    expect(done).toMatchObject({
      status: 'COMPLETED',
      registeredCount: 4,
      newCount: 0,
    });
    expect(done.permutationsTotal).toBeGreaterThan(5_000);

    registered.delete('xeample.com'); // dropped since the last scan
    const second = await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({ originalDomainId })
      .expect(202);
    await waitForScan(second.body.id, 120_000);

    const inactive = await api()
      .get(
        `/api/v1/scanned-domains?originalDomainId=${originalDomainId}&status=INACTIVE`,
      )
      .set(auth);
    expect(inactive.body.data.map((d: { domain: string }) => d.domain)).toEqual(
      ['xeample.com'],
    );
    const active = await api()
      .get(
        `/api/v1/scanned-domains?originalDomainId=${originalDomainId}&status=ACTIVE`,
      )
      .set(auth);
    expect(active.body.total).toBe(3); // seen again → NEW became ACTIVE

    registered.add('xeample.com');
    const third = await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({ originalDomainId, options: { fuzzers: ['transposition'] } })
      .expect(202);
    await waitForScan(third.body.id);
    const revived = await api()
      .get(
        `/api/v1/scanned-domains?originalDomainId=${originalDomainId}&search=xeample`,
      )
      .set(auth);
    expect(revived.body.data[0].status).toBe('ACTIVE');
  }, 300_000);

  it('cancels an in-flight scan and refuses to cancel a finished one', async () => {
    const started = await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({ originalDomainId })
      .expect(202);
    const cancelled = await api()
      .post(`/api/v1/scans/${started.body.id}/cancel`)
      .set(auth)
      .expect(200);
    expect(cancelled.body.status).toBe('CANCELLED');
    const final = await waitForScan(started.body.id);
    expect(final.status).toBe('CANCELLED'); // late batches/finalize must not overwrite it
    await api()
      .post(`/api/v1/scans/${started.body.id}/cancel`)
      .set(auth)
      .expect(409);
  });

  it('validates input and auth on the new endpoints', async () => {
    await api().post('/api/v1/scans').set(auth).send({}).expect(400);
    await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({ domain: 'unknown-brand.com' })
      .expect(404);
    await api()
      .post('/api/v1/scans')
      .set(auth)
      .send({ originalDomainId, options: { fuzzers: ['nope'] } })
      .expect(400);
    await api()
      .post('/api/v1/scans')
      .set({ 'x-api-key': KEYS.reader })
      .send({ originalDomainId })
      .expect(403);
    await api()
      .get('/api/v1/scans?status=COMPLETED')
      .set({ 'x-api-key': KEYS.reader })
      .expect(200);
    await api()
      .post('/api/v1/original-domains')
      .set(auth)
      .send({ domain: 'x.com', scanSchedule: 'every day' })
      .expect(400);
  });

  it('deleting the original domain hides it and stops further scans', async () => {
    await api()
      .delete(`/api/v1/original-domains/${originalDomainId}`)
      .set(auth)
      .expect(204);
    await api()
      .get(`/api/v1/original-domains/${originalDomainId}`)
      .set(auth)
      .expect(404);
    await api()
      .post(`/api/v1/original-domains/${originalDomainId}/scans`)
      .set(auth)
      .send({})
      .expect(404);
  });
});
