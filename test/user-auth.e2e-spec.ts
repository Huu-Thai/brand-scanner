/**
 * Phase 5 — shared auth with threat-feed: a threat-feed user token (HS256, shared secret) is
 * accepted as a Bearer credential; identity and role come from threat-feed GET /auth/me.
 */
import { createHmac } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { KEYS, startStack, type TestStack } from './support/stack.js';

const SECRET = 'e2e-threat-feed-jwt-secret-0123456789';

const token = (
  sub: string,
  opts: { secret?: string; alg?: string; expIn?: number } = {},
) => {
  const h = Buffer.from(
    JSON.stringify({ alg: opts.alg ?? 'HS256', typ: 'JWT' }),
  ).toString('base64url');
  const p = Buffer.from(
    JSON.stringify({
      sub,
      exp: Math.floor(Date.now() / 1000) + (opts.expIn ?? 900),
    }),
  ).toString('base64url');
  return `${h}.${p}.${createHmac('sha256', opts.secret ?? SECRET)
    .update(`${h}.${p}`)
    .digest('base64url')}`;
};

/** threat-feed GET /auth/me for a few users. */
const USERS: Record<
  string,
  | {
      email: string;
      role: string;
      permissions: { key: string; method: string; path: string }[];
    }
  | 'inactive'
> = {
  analyst: {
    email: 'Ana@Example.com',
    role: 'analyst',
    permissions: [
      { key: 'read', method: 'GET', path: '*' },
      { key: 'write', method: 'POST', path: '/feeds' },
    ],
  },
  viewer: {
    email: 'vic@example.com',
    role: 'viewer',
    permissions: [{ key: 'read', method: 'GET', path: '*' }],
  },
  intern: {
    email: 'ian@example.com',
    role: 'sources-only',
    permissions: [{ key: 'read', method: 'GET', path: '/sources' }],
  },
  gone: 'inactive',
};

describe('threat-feed user tokens (e2e)', () => {
  let stack: TestStack;
  let app: INestApplication;
  let tf: Server;
  let meCalls = 0;
  const api = () => request(app.getHttpServer());
  const bearer = (t: string) => ({ authorization: `Bearer ${t}` });

  beforeAll(async () => {
    stack = await startStack();
    tf = createServer((req, res) => {
      meCalls++;
      const t = (req.headers.authorization ?? '').replace('Bearer ', '');
      const sub = JSON.parse(
        Buffer.from(t.split('.')[1] ?? '', 'base64url').toString() || '{}',
      ).sub as string;
      const u = USERS[sub];
      if (req.url !== '/api/v1/auth/me' || !u || u === 'inactive')
        return res.writeHead(401).end('{}');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          id: sub,
          email: u.email,
          role: { id: 'r', key: u.role, name: u.role },
          permissions: u.permissions,
        }),
      );
    });
    await new Promise<void>((r) => tf.listen(0, '127.0.0.1', r));
    Object.assign(process.env, {
      AUTH_JWT_SECRET: SECRET,
      THREAT_FEED_URL: `http://127.0.0.1:${(tf.address() as { port: number }).port}/api/v1`,
    });
    const [{ Test }, { AppModule }, { configureApp }] = await Promise.all([
      import('@nestjs/testing'),
      import('../src/app.module.js'),
      import('../src/bootstrap.js'),
    ]);
    app = (
      await Test.createTestingModule({ imports: [AppModule] }).compile()
    ).createNestApplication({ bufferLogs: true });
    configureApp(app);
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
    await new Promise((r) => tf.close(r));
    await stack?.stop();
  });

  it('an analyst reads and writes as themselves', async () => {
    const t = token('analyst');
    await api().get('/api/v1/original-domains').set(bearer(t)).expect(200);
    const od = await api()
      .post('/api/v1/original-domains')
      .set(bearer(t))
      .send({ domain: 'example.com' })
      .expect(201);
    expect(od.body.domain).toBe('example.com');
    // Identity is cached per token: two requests, one /auth/me call.
    expect(meCalls).toBe(1);
  });

  it('a viewer may read but not write; a role without feed access gets nothing', async () => {
    await api()
      .get('/api/v1/original-domains')
      .set(bearer(token('viewer')))
      .expect(200);
    const denied = await api()
      .post('/api/v1/original-domains')
      .set(bearer(token('viewer')))
      .send({ domain: 'b.com' })
      .expect(403);
    expect(denied.body.message).toMatch(/role \("viewer"\) cannot perform/);
    await api()
      .get('/api/v1/original-domains')
      .set(bearer(token('intern')))
      .expect(403);
  });

  it('rejects forged, expired, alg=none tokens and deactivated users', async () => {
    const before = meCalls;
    await api()
      .get('/api/v1/original-domains')
      .set(bearer(token('analyst', { secret: 'forged-secret-0123456789' })))
      .expect(401);
    await api()
      .get('/api/v1/original-domains')
      .set(bearer(token('analyst', { expIn: -600 })))
      .expect(401);
    await api()
      .get('/api/v1/original-domains')
      .set(bearer(token('analyst', { alg: 'none' })))
      .expect(401);
    expect(meCalls).toBe(before); // rejected locally, threat-feed never asked
    await api()
      .get('/api/v1/original-domains')
      .set(bearer(token('gone')))
      .expect(401);
  });

  it('API keys keep working alongside user tokens', async () => {
    await api()
      .get('/api/v1/original-domains')
      .set({ 'x-api-key': KEYS.reader })
      .expect(200);
    await api().get('/api/v1/original-domains').expect(401);
  });
});
