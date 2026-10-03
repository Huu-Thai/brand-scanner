/**
 * Boots the real application (same HTTP pipeline as main.ts) against real
 * PostgreSQL, password-protected Redis and MinIO. Phase 0 "done" criteria:
 * health is green with authenticated Redis and the bucket reachable.
 */
import type { INestApplication } from '@nestjs/common';
import { Redis } from 'ioredis';
import request from 'supertest';
import {
  KEYS,
  REDIS_PASSWORD,
  startStack,
  type TestStack,
} from './support/stack.js';

describe('Fuzzer Scanner API (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;

  beforeAll(async () => {
    stack = await startStack();
    // Imported after env is set: ConfigModule reads process.env when the module is evaluated.
    const [{ Test }, { AppModule }, { configureApp }] = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
    ]);
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication({ bufferLogs: true });
    configureApp(app);
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
    await stack?.stop();
  });

  describe('GET /api/v1/health', () => {
    it('is public and reports database, authenticated redis, storage and selenium as up', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.info).toMatchObject({
        database: { status: 'up' },
        redis: { status: 'up', authenticated: true },
        storage: { status: 'up', bucket: 'fuzzer-screenshots-e2e' },
        selenium: { status: 'up' },
      });
    });

    it('liveness responds without dependency checks', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/health/live')
        .expect(200, { status: 'ok' });
    });
  });

  describe('Redis authentication', () => {
    it('the Redis server rejects clients without the password', async () => {
      const anon = new Redis({
        host: stack.redis.getHost(),
        port: stack.redis.getMappedPort(6379),
        lazyConnect: true,
        maxRetriesPerRequest: 0,
        enableReadyCheck: false,
      });
      await anon.connect().catch(() => undefined);
      await expect(anon.ping()).rejects.toThrow(/NOAUTH/);
      anon.disconnect();

      const authed = new Redis({
        host: stack.redis.getHost(),
        port: stack.redis.getMappedPort(6379),
        password: REDIS_PASSWORD,
        lazyConnect: true,
      });
      await authed.connect();
      expect(await authed.ping()).toBe('PONG');
      authed.disconnect();
    });
  });

  describe('API key authentication', () => {
    it('401 without a key, with the uniform error body and request id', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/system/info')
        .expect(401);
      expect(res.body).toMatchObject({
        statusCode: 401,
        message: 'Missing API key',
        error: 'Unauthorized',
        path: '/api/v1/system/info',
      });
      expect(res.body.requestId).toBe(res.headers['x-request-id']);
    });

    it('401 with an unknown key', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/system/info')
        .set('x-api-key', 'fsk_not_a_real_key')
        .expect(401);
    });

    it('200 with a valid key; echoes a caller-supplied x-request-id', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/system/info')
        .set('x-api-key', KEYS.reader)
        .set('x-request-id', 'e2e-trace-0001')
        .expect(200);
      expect(res.headers['x-request-id']).toBe('e2e-trace-0001');
      expect(res.body).toMatchObject({
        name: 'fuzzer-scanner',
        caller: 'e2e-reader',
      });
      expect(res.body.queues).toContain('scan-orchestrator');
    });

    it('unknown routes under the prefix return a uniform 404', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/does-not-exist')
        .set('x-api-key', KEYS.admin)
        .expect(404);
      expect(res.body).toMatchObject({ statusCode: 404, error: 'Not Found' });
    });
  });

  describe('OpenAPI', () => {
    it('serves Swagger UI and a spec with the api/v1 prefix and api-key security', async () => {
      await request(app.getHttpServer()).get('/api/docs').expect(200);
      const res = await request(app.getHttpServer())
        .get('/api/docs-json')
        .expect(200);
      expect(Object.keys(res.body.paths)).toEqual(
        expect.arrayContaining(['/api/v1/health', '/api/v1/system/info']),
      );
      expect(res.body.components.securitySchemes['api-key']).toMatchObject({
        type: 'apiKey',
        in: 'header',
        name: 'x-api-key',
      });
    });
  });

  describe('object storage (MinIO)', () => {
    it('uploads, serves a working presigned URL, and deletes', async () => {
      const { StorageService } =
        await import('../src/storage/storage.service.js');
      const storage = app.get(StorageService);
      const body = Buffer.from('\x89PNG e2e round-trip');
      await storage.putObject('e2e/roundtrip.png', body, 'image/png');
      const url = await storage.getSignedUrl('e2e/roundtrip.png', 60);
      const res = await fetch(url);
      expect(res.status).toBe(200);
      expect(Buffer.from(await res.arrayBuffer()).equals(body)).toBe(true);
      expect(await storage.deleteObjects(['e2e/roundtrip.png'])).toEqual({
        deleted: ['e2e/roundtrip.png'],
        failed: [],
      });
      expect((await fetch(url)).status).toBe(404);
    });
  });

  describe('security headers', () => {
    it('sets helmet headers and hides the framework', async () => {
      const res = await request(app.getHttpServer()).get('/api/v1/health/live');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });
});
