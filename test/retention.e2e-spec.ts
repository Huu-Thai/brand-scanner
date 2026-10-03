/**
 * Phase 4 "done" criterion: retention verified on seeded data. Seeds rows and MinIO objects on
 * both sides of the 31-day cutoff, runs retention through the admin API + worker, and checks
 * exactly what was removed and kept (keep-latest, S3-before-row, soft-delete purge, idempotent
 * re-run), then the orphan sweep and the outbox relay's crash recovery.
 */
import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { PrismaService } from '../src/database/prisma.service.js';
import type { StorageService } from '../src/storage/storage.service.js';
import { KEYS, startStack, type TestStack } from './support/stack.js';

const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY);

describe('retention & outbox (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;
  let db: PrismaService;
  let storage: StorageService;
  let s3: S3Client;
  const api = () => request(app.getHttpServer());
  const admin = { 'x-api-key': KEYS.admin };
  const ids: Record<string, string> = {};
  const shots: Record<string, string> = {};

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

  const exists = (key: string) =>
    s3
      .send(new HeadObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key }))
      .then(() => true)
      .catch(() => false);

  beforeAll(async () => {
    stack = await startStack();
    Object.assign(process.env, {
      RETENTION_ORPHAN_MIN_AGE_MS: '0',
      OUTBOX_RELAY_INTERVAL_MS: '500',
      OUTBOX_GRACE_MS: '1000',
    });
    const [
      { Test },
      { AppModule },
      { configureApp },
      { RetentionWorkerModule },
      prismaMod,
      storageMod,
    ] = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
      import('../src/modules/retention/retention.module.js'),
      import('../src/database/prisma.service.js'),
      import('../src/storage/storage.service.js'),
    ]);
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule, RetentionWorkerModule.forQueues([])],
    }).compile();
    app = moduleRef.createNestApplication({ bufferLogs: true });
    configureApp(app);
    await app.init();
    db = app.get(prismaMod.PrismaService);
    storage = app.get(storageMod.StorageService);
    s3 = new S3Client({
      endpoint: process.env.S3_ENDPOINT,
      region: 'us-east-1',
      forcePathStyle: true,
      credentials: {
        accessKeyId: process.env.S3_ACCESS_KEY_ID!,
        secretAccessKey: process.env.S3_SECRET_ACCESS_KEY!,
      },
    });
    await seed();
  });

  afterAll(async () => {
    s3?.destroy();
    await app?.close();
    await stack?.stop();
  });

  async function shot(
    key: string,
    scannedDomainId: string,
    createdAt: Date,
    status: 'CAPTURED' | 'FAILED',
  ) {
    const storageKey = status === 'CAPTURED' ? `screenshots/${key}.png` : null;
    if (storageKey)
      await storage.putObject(storageKey, Buffer.from(key), 'image/png');
    const row = await db.screenshot.create({
      data: {
        scannedDomainId,
        requestedUrl: `https://${key}/`,
        status,
        storageKey,
        createdAt,
        updatedAt: createdAt,
      },
    });
    shots[key] = row.id;
  }

  async function seed() {
    const brand = await db.originalDomain.create({
      data: {
        domain: 'brand.com',
        unicodeDomain: 'brand.com',
        updatedAt: new Date(),
      },
    });
    const gone = await db.originalDomain.create({
      data: {
        domain: 'gone.com',
        unicodeDomain: 'gone.com',
        updatedAt: new Date(),
        deletedAt: ago(40),
      },
    });
    ids.brand = brand.id;
    ids.goneBrand = gone.id;
    const scan = (days: number, status: 'COMPLETED' | 'FAILED' | 'QUEUED') =>
      db.scan.create({
        data: {
          originalDomainId: brand.id,
          status,
          createdAt: ago(days),
          updatedAt: ago(days),
        },
      });
    ids.scanOldA = (await scan(45, 'COMPLETED')).id;
    ids.scanOldB = (await scan(40, 'FAILED')).id;
    ids.scanNew = (await scan(1, 'COMPLETED')).id;

    const lookalike = (
      originalDomainId: string,
      domain: string,
      deletedAt: Date | null = null,
      lastScanId: string | null = null,
    ) =>
      db.scannedDomain.create({
        data: {
          originalDomainId,
          domain,
          unicodeDomain: domain,
          fuzzer: 'omission',
          updatedAt: new Date(),
          deletedAt,
          lastScanId,
        },
      });
    ids.d1 = (await lookalike(brand.id, 'brnd.com', null, ids.scanOldA)).id; // has fresh history
    ids.d2 = (await lookalike(brand.id, 'bran.com')).id; // only old history
    ids.d3 = (await lookalike(brand.id, 'brabd.com', ago(40))).id; // soft-deleted long ago
    ids.d4 = (await lookalike(brand.id, 'bramd.com', ago(5))).id; // soft-deleted recently
    ids.g1 = (await lookalike(gone.id, 'gome.com')).id;

    const score = (scannedDomainId: string, days: number) =>
      db.analytics.create({
        data: {
          scannedDomainId,
          totalScore: days,
          threatLevel: 'LOW_RISK',
          ruleResults: [],
          computedAt: ago(days),
        },
      });
    ids.a1Old = (await score(ids.d1, 50)).id;
    ids.a1Older = (await score(ids.d1, 40)).id;
    ids.a1New = (await score(ids.d1, 1)).id;
    ids.a2Old = (await score(ids.d2, 40)).id;

    const whois = (scannedDomainId: string, days: number) =>
      db.whoisInformation.create({
        data: { scannedDomainId, source: 'RDAP', fetchedAt: ago(days) },
      });
    ids.w1Old = (await whois(ids.d1, 40)).id;
    ids.w1New = (await whois(ids.d1, 2)).id;
    ids.w2Old = (await whois(ids.d2, 40)).id;

    await shot('d1-old', ids.d1, ago(40), 'CAPTURED');
    await shot('d1-new', ids.d1, ago(1), 'CAPTURED');
    await shot('d2-old', ids.d2, ago(40), 'CAPTURED'); // latest capture of d2 → kept
    await shot('d2-failed', ids.d2, ago(45), 'FAILED');
    await shot('d3', ids.d3, ago(41), 'CAPTURED');
    await shot('d4', ids.d4, ago(10), 'CAPTURED');
    await shot('g1', ids.g1, ago(42), 'CAPTURED');
    await db.review.create({
      data: {
        scannedDomainId: ids.d3,
        verdict: 'BENIGN',
        reviewer: 'ana',
        previousStatus: 'NEW',
        newStatus: 'ACTIVE',
      },
    });

    const dead = (days: number) =>
      db.outboxEvent.create({
        data: {
          eventName: 'x.y',
          payload: {},
          origin: 'nobody',
          failedAt: ago(days),
          createdAt: ago(days),
        },
      });
    ids.deadOld = (await dead(40)).id;
    ids.deadNew = (await dead(3)).id;
  }

  async function runRetention(
    task: 'retention' | 'orphan-sweep' = 'retention',
  ) {
    const before = (
      await api().get('/api/v1/admin/retention').set(admin).expect(200)
    ).body;
    const field = task === 'retention' ? 'lastRun' : 'lastSweep';
    await api()
      .post('/api/v1/admin/retention/run')
      .set(admin)
      .send({ task })
      .expect(202);
    return waitFor(async () => {
      const { body } = await api().get('/api/v1/admin/retention').set(admin);
      return body[field] && body[field].finishedAt !== before[field]?.finishedAt
        ? body
        : undefined;
    }, task);
  }

  it('is admin-only', async () => {
    await api()
      .get('/api/v1/admin/retention')
      .set({ 'x-api-key': KEYS.reader })
      .expect(403);
    await api()
      .post('/api/v1/admin/retention/run')
      .set({ 'x-api-key': KEYS.reader })
      .send({})
      .expect(403);
  });

  it('purges history older than 31 days, keeping the latest row per look-alike', async () => {
    const status = await runRetention();
    expect(status.settings).toMatchObject({ days: 31, keepLatest: true });
    expect(status.nextRun).toEqual(expect.any(String));
    expect(status.lastRun).toMatchObject({
      requestedBy: 'e2e-admin',
      rows: {
        analytics: 2,
        whois_informations: 1,
        screenshots: 2,
        scans: 2,
        scanned_domains: 1,
        original_domains: 1,
        outbox_events: 1,
      },
      objectsFailed: 0,
    });

    const has = async (
      model:
        | 'analytics'
        | 'whoisInformation'
        | 'screenshot'
        | 'scan'
        | 'scannedDomain'
        | 'originalDomain'
        | 'outboxEvent',
      id: string,
    ) =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      !!(await (db[model] as any).findUnique({ where: { id } }));

    // analytics / whois: old rows gone, the newest per domain kept even when old.
    expect([
      await has('analytics', ids.a1Old),
      await has('analytics', ids.a1Older),
    ]).toEqual([false, false]);
    expect([
      await has('analytics', ids.a1New),
      await has('analytics', ids.a2Old),
    ]).toEqual([true, true]);
    expect([
      await has('whoisInformation', ids.w1Old),
      await has('whoisInformation', ids.w1New),
      await has('whoisInformation', ids.w2Old),
    ]).toEqual([false, true, true]);

    // scans: finished + old gone; look-alike's last_scan_id was SET NULL, not cascaded.
    expect([
      await has('scan', ids.scanOldA),
      await has('scan', ids.scanOldB),
      await has('scan', ids.scanNew),
    ]).toEqual([false, false, true]);
    expect(
      (await db.scannedDomain.findUnique({ where: { id: ids.d1 } }))
        ?.lastScanId,
    ).toBeNull();

    // screenshots: rows AND objects removed together; latest capture per domain kept.
    expect(await has('screenshot', shots['d1-old'])).toBe(false);
    expect(await exists('screenshots/d1-old.png')).toBe(false);
    expect(await has('screenshot', shots['d2-failed'])).toBe(false);
    expect([
      await has('screenshot', shots['d1-new']),
      await exists('screenshots/d1-new.png'),
    ]).toEqual([true, true]);
    expect([
      await has('screenshot', shots['d2-old']),
      await exists('screenshots/d2-old.png'),
    ]).toEqual([true, true]);

    // soft-deleted > 31 days: hard-purged with children and objects; recent soft deletes kept.
    expect(await has('scannedDomain', ids.d3)).toBe(false);
    expect(await exists('screenshots/d3.png')).toBe(false);
    expect(await db.review.count({ where: { scannedDomainId: ids.d3 } })).toBe(
      0,
    );
    expect([
      await has('scannedDomain', ids.d4),
      await exists('screenshots/d4.png'),
    ]).toEqual([true, true]);
    expect([
      await has('originalDomain', ids.goneBrand),
      await has('scannedDomain', ids.g1),
      await exists('screenshots/g1.png'),
    ]).toEqual([false, false, false]);
    expect(await has('originalDomain', ids.brand)).toBe(true);

    expect([
      await has('outboxEvent', ids.deadOld),
      await has('outboxEvent', ids.deadNew),
    ]).toEqual([false, true]);
  });

  it('is idempotent: a second run removes nothing more', async () => {
    const { lastRun } = await runRetention();
    expect(Object.values(lastRun.rows).every((n) => n === 0)).toBe(true);
  });

  it('orphan sweep removes unreferenced objects only', async () => {
    await storage.putObject(
      'screenshots/orphan/stray.png',
      Buffer.from('x'),
      'image/png',
    );
    const { lastSweep } = await runRetention('orphan-sweep');
    expect(lastSweep).toMatchObject({ orphans: 1, deleted: 1, failed: 0 });
    expect(await exists('screenshots/orphan/stray.png')).toBe(false);
    expect(await exists('screenshots/d1-new.png')).toBe(true);
  });

  it('outbox: normal writes leave nothing behind; a crashed delivery is redelivered by the relay', async () => {
    // A regular write: outbox row written in the transaction, delivered and cleared right after.
    await api()
      .post(`/api/v1/scanned-domains/${ids.d1}/reviews`)
      .set(admin)
      .send({ verdict: 'SUSPICIOUS' })
      .expect(201);
    await waitFor(
      async () =>
        (await db.scannedDomain.findUnique({ where: { id: ids.d1 } }))
          ?.status === 'UNDER_REVIEW'
          ? true
          : undefined,
      'status',
    );
    await waitFor(
      async () =>
        (await db.outboxEvent.count({ where: { failedAt: null } })) === 0
          ? true
          : undefined,
      'outbox drained',
    );

    // Simulate a process that committed a review but died before delivering review.created.
    const orphan = await db.outboxEvent.create({
      data: {
        eventName: 'review.created',
        origin: 'api',
        availableAt: new Date(),
        payload: {
          name: 'review.created',
          occurredAt: new Date().toISOString(),
          reviewId: '00000000-0000-0000-0000-000000000001',
          scannedDomainId: ids.d2,
          verdict: 'MALICIOUS',
          previousStatus: 'NEW',
          newStatus: 'CONFIRMED_THREAT',
          reviewer: 'crashed-api',
        },
      },
    });
    await waitFor(
      async () =>
        (await db.scannedDomain.findUnique({ where: { id: ids.d2 } }))
          ?.status === 'CONFIRMED_THREAT'
          ? true
          : undefined,
      'relay redelivery',
    );
    await waitFor(
      async () =>
        (await db.outboxEvent.findUnique({ where: { id: orphan.id } }))
          ? undefined
          : true,
      'row cleared',
    );
  });
});
