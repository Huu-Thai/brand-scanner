import { WebSocketServer } from 'ws';
import { CtMonitorController } from './ct-monitor.controller.js';
import {
  CT_LEADER_KEY,
  CtStreamService,
  namesFromMessage,
} from './ct-stream.service.js';
import { CtMatchProcessor } from './processors/ct-match.processor.js';

const certMsg = (...names: string[]) =>
  JSON.stringify({
    message_type: 'certificate_update',
    data: { leaf_cert: { all_domains: names } },
  });

function fakeRedis() {
  const kv = new Map<string, string>();
  const hashes = new Map<string, Record<string, string>>();
  const redis = {
    set: vi.fn(async (key: string, value: string, ...args: unknown[]) => {
      if (args.includes('NX') && kv.has(key)) return null;
      kv.set(key, value);
      return 'OK';
    }),
    eval: vi.fn(
      async (script: string, _n: number, key: string, token: string) => {
        if (kv.get(key) !== token) return 0;
        if (script.includes('del')) kv.delete(key);
        return 1;
      },
    ),
    hset: vi.fn(async (key: string, obj: Record<string, string>) => {
      hashes.set(key, { ...hashes.get(key), ...obj });
      return 1;
    }),
    hgetall: vi.fn(async (key: string) => hashes.get(key) ?? {}),
    exists: vi.fn(async (key: string) => (kv.has(key) ? 1 : 0)),
    multi: vi.fn(() => {
      const chain = {
        hincrby: () => chain,
        hset: (k: string, o: Record<string, string>) => (
          hashes.set(k, { ...hashes.get(k), ...o }),
          chain
        ),
        exec: async () => [],
      };
      return chain;
    }),
  };
  return { redis, kv, hashes };
}

function service(
  opts: {
    url?: string;
    enabled?: boolean;
    redis?: ReturnType<typeof fakeRedis>;
  } = {},
) {
  const r = opts.redis ?? fakeRedis();
  const queue = { add: vi.fn(async () => ({})) };
  const originals = {
    listActive: vi.fn(async () => [{ id: 'b1', domain: 'paypal.com' }]),
  };
  const config = {
    get: () => ({
      enabled: opts.enabled ?? true,
      streamUrl: opts.url ?? 'ws://127.0.0.1:1/',
      minKeywordLength: 5,
      maxEditDistance: 2,
      stallTimeoutMs: 60_000,
    }),
  };
  const svc = new CtStreamService(
    config as never,
    originals as never,
    queue as never,
    r.redis as never,
  );
  return { svc, queue, originals, ...r };
}

describe('CT stream', () => {
  it('reads both certstream formats and ignores heartbeats / junk', () => {
    expect(namesFromMessage(certMsg('a.com', '*.b.com'))).toEqual([
      'a.com',
      '*.b.com',
    ]);
    expect(
      namesFromMessage(
        JSON.stringify({ message_type: 'dns_entries', data: ['x.com'] }),
      ),
    ).toEqual(['x.com']);
    expect(
      namesFromMessage(JSON.stringify({ message_type: 'heartbeat' })),
    ).toBeNull();
    expect(namesFromMessage('not json')).toBeNull();
  });

  it('queues each brand look-alike once per 7 days (Redis de-dupe + job id)', async () => {
    const { svc, queue } = service();
    expect(
      await svc.handle(
        certMsg('paypal-secure-login.com', 'www.paypal-secure-login.com'),
      ),
    ).toBe(1);
    expect(queue.add).toHaveBeenCalledWith(
      'ct-match',
      expect.objectContaining({
        originalDomainId: 'b1',
        domain: 'paypal-secure-login.com',
        kind: 'combo',
      }),
      expect.objectContaining({ jobId: 'ct-b1-paypal-secure-login.com' }),
    );
    expect(await svc.handle(certMsg('paypal-secure-login.com'))).toBe(0); // renewal / duplicate cert
    expect(await svc.handle(certMsg('example.org'))).toBe(0);
    expect(queue.add).toHaveBeenCalledTimes(1);
  });

  it('elects a single leader; another process takes over when the lease is released', async () => {
    const shared = fakeRedis();
    const a = service({ redis: shared });
    const b = service({ redis: shared });
    expect(await a.svc.elect()).toBe(true);
    expect(await b.svc.elect()).toBe(false);
    expect(await a.svc.elect()).toBe(true); // renewal
    await a.svc.onApplicationShutdown(); // releases the lease
    expect(shared.kv.has(CT_LEADER_KEY)).toBe(false);
    expect(await b.svc.elect()).toBe(true);
    await b.svc.onApplicationShutdown();
  });

  it('connects as leader, consumes messages and reconnects after the stream drops', async () => {
    const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise((r) => wss.once('listening', r));
    const url = `ws://127.0.0.1:${(wss.address() as { port: number }).port}/`;
    let connections = 0;
    wss.on('connection', (socket) => {
      connections++;
      socket.send(JSON.stringify({ message_type: 'heartbeat' }));
      socket.send(
        certMsg(connections === 1 ? 'paypa1.com' : 'paypal-billing.net'),
      );
      if (connections === 1) setTimeout(() => socket.close(), 50);
    });
    const { svc, queue } = service({ url });
    await svc.elect();
    const deadline = Date.now() + 10_000;
    while (queue.add.mock.calls.length < 2 && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 50));
    expect(connections).toBe(2);
    expect(
      queue.add.mock.calls
        .map((c) => (c as unknown[])[1] as { domain: string })
        .map((d) => d.domain),
    ).toEqual(['paypa1.com', 'paypal-billing.net']);
    await svc.onApplicationShutdown();
    await new Promise((r) => wss.close(r));
  });

  it('does nothing when disabled', () => {
    const { svc, redis } = service({ enabled: false });
    svc.onApplicationBootstrap();
    expect(redis.set).not.toHaveBeenCalled();
  });

  it('processor tracks registered matches as ct:<kind> look-alikes', async () => {
    const dns = {
      resolve: vi.fn(async (d: string) => ({
        domain: d,
        registered: d !== 'gone.com',
      })),
    };
    const scanned = {
      upsertBatch: vi.fn(async () => ({ inserted: 1, updated: 0 })),
    };
    const p = new CtMatchProcessor(dns as never, scanned as never);
    const job = (domain: string) => ({
      id: '1',
      name: 'ct-match',
      data: {
        originalDomainId: 'b1',
        domain,
        kind: 'combo',
        certName: domain,
        seenAt: '',
      },
    });
    expect(await p.process(job('paypal-login.com') as never)).toEqual({
      tracked: 'paypal-login.com',
      new: true,
    });
    expect(scanned.upsertBatch).toHaveBeenCalledWith({
      originalDomainId: 'b1',
      fuzzerByDomain: { 'paypal-login.com': 'ct:combo' },
      resolutions: [{ domain: 'paypal-login.com', registered: true }],
    });
    expect(await p.process(job('gone.com') as never)).toEqual({
      skipped: 'not registered (yet)',
    });
  });

  it('status endpoint reports leader, connection freshness and counters', async () => {
    const { redis, kv, hashes } = fakeRedis();
    const cfg = {
      get: () => ({ enabled: true, streamUrl: 'wss://ct.example/' }),
    };
    const ctrl = new CtMonitorController(cfg as never, redis as never);
    expect(await ctrl.status()).toMatchObject({
      enabled: true,
      leaderElected: false,
      connected: false,
      certificates: 0,
    });
    kv.set(CT_LEADER_KEY, 'x');
    hashes.set('ct:stats', {
      connected: '1',
      lastMessageAt: new Date().toISOString(),
      certificates: '12',
      matches: '2',
    });
    expect(await ctrl.status()).toMatchObject({
      leaderElected: true,
      connected: true,
      certificates: 12,
      matches: 2,
    });
  });
});
