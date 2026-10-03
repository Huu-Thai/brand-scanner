import { createServer, type Server } from 'node:http';
import {
  BadRequestException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { UnrecoverableError } from 'bullmq';
import { SecretBox } from '../../common/crypto/secret-box.js';
import { fakeBus } from '../../testing/fake-bus.js';
import { AlertChannelsService } from './alert-channels.service.js';
import { AlertCrypto } from './alert-crypto.js';
import {
  AlertTargetGuard,
  isNonPublicAddress,
  UnsafeTargetError,
} from './alert-target.guard.js';
import { maskTarget, type AlertPayload } from './alert.types.js';
import { AlertsService } from './alerts.service.js';
import { ALERT_EVENTS } from './events/alert.events.js';
import { AlertTriggerListener } from './listeners/alert-trigger.listener.js';
import { AlertsProcessor } from './processors/alerts.processor.js';
import {
  AlertSender,
  PermanentDeliveryError,
  signature,
} from './senders/alert-sender.js';

const KEY = 'a'.repeat(64);
const alertsConfig = (over: Record<string, unknown> = {}) => ({
  get: () => ({
    encryptionKey: KEY,
    allowPrivateTargets: false,
    allowInsecureTargets: false,
    timeoutMs: 2_000,
    emailFrom: 'alerts@x.test',
    consoleUrl: 'https://console.test',
    ...over,
  }),
});

class StaticGuard extends AlertTargetGuard {
  constructor(
    cfg: unknown,
    private readonly answers: Record<string, string[]>,
  ) {
    super(cfg as never);
  }
  protected resolve(host: string) {
    const a = this.answers[host];
    return a
      ? Promise.resolve(a.map((address) => ({ address })))
      : Promise.reject(new Error('ENOTFOUND'));
  }
}

const payload = (over: Partial<AlertPayload> = {}): AlertPayload => ({
  eventType: 'HIGH_RISK',
  scannedDomainId: 'sd1',
  domain: 'paypa1.com',
  unicodeDomain: 'paypa1.com',
  brand: 'paypal.com',
  originalDomainId: 'od1',
  fuzzer: 'homoglyph',
  riskScore: 120,
  threatLevel: 'HIGH_RISK',
  status: 'ACTIVE',
  details: ['Matched rule: domain_age'],
  consoleUrl: 'https://console.test/lookalikes/sd1',
  occurredAt: '2026-10-02T12:00:00.000Z',
  ...over,
});

describe('SecretBox', () => {
  it('round-trips, uses a fresh IV each time, and detects tampering or a wrong key', () => {
    const box = new SecretBox(KEY);
    const a = box.seal('https://hooks.slack.com/services/T/B/x');
    expect(a).toMatch(/^v1\./);
    expect(box.seal('same')).not.toBe(box.seal('same'));
    expect(box.open(a)).toBe('https://hooks.slack.com/services/T/B/x');
    const parts = a.split('.');
    parts[3] = Buffer.from('tampered').toString('base64url');
    expect(() => box.open(parts.join('.'))).toThrow();
    expect(() => new SecretBox('b'.repeat(64)).open(a)).toThrow();
    expect(() => new SecretBox('short')).toThrow(/32 bytes/);
  });

  it('AlertCrypto refuses to work without a key', () => {
    const c = new AlertCrypto(
      alertsConfig({ encryptionKey: undefined }) as never,
    );
    expect(c.configured).toBe(false);
    expect(() => c.seal('x')).toThrow(ServiceUnavailableException);
  });
});

describe('SSRF guard', () => {
  it.each([
    ['127.0.0.1', true],
    ['10.1.2.3', true],
    ['172.20.0.1', true],
    ['192.168.1.1', true],
    ['169.254.169.254', true], // cloud metadata
    ['100.64.0.1', true],
    ['::1', true],
    ['fd00::1', true],
    ['fe80::1', true],
    ['::ffff:10.0.0.1', true],
    ['8.8.8.8', false],
    ['2606:4700:4700::1111', false],
  ])('%s non-public=%s', (ip, blocked) => {
    expect(isNonPublicAddress(ip)).toBe(blocked);
  });

  it('accepts public https targets and rejects http, credentials, private resolutions and junk', async () => {
    const guard = new StaticGuard(alertsConfig(), {
      'hooks.example.com': ['93.184.216.34'],
      'internal.example.com': ['93.184.216.34', '10.0.0.5'],
    });
    await expect(
      guard.assertSafeUrl('https://hooks.example.com/a'),
    ).resolves.toBeInstanceOf(URL);
    for (const bad of [
      'http://hooks.example.com/a',
      'https://user:pw@hooks.example.com/a',
      'https://internal.example.com/a', // one private answer is enough to refuse
      'https://169.254.169.254/latest/meta-data',
      'https://nowhere.example.com/',
      'not a url',
    ])
      await expect(guard.assertSafeUrl(bad)).rejects.toBeInstanceOf(
        UnsafeTargetError,
      );
  });

  it('can be relaxed for internal relays', async () => {
    const guard = new StaticGuard(
      alertsConfig({ allowPrivateTargets: true, allowInsecureTargets: true }),
      {},
    );
    await expect(
      guard.assertSafeUrl('http://10.0.0.5:8080/hook'),
    ).resolves.toBeInstanceOf(URL);
  });

  it('masks targets for display', () => {
    expect(
      maskTarget('SLACK', 'https://hooks.slack.com/services/T0/B0/secretXYZ9'),
    ).toBe('https://hooks.slack.com/…XYZ9');
    expect(maskTarget('EMAIL', 'soc@acme.com, ana@acme.com')).toBe(
      's***@acme.com, a***@acme.com',
    );
  });
});

describe('AlertSender', () => {
  let server: Server;
  let base: string;
  const received: {
    headers: Record<string, string | string[] | undefined>;
    body: string;
  }[] = [];
  let status = 200;

  beforeAll(async () => {
    server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        received.push({ headers: req.headers, body });
        res.writeHead(status).end();
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(() => new Promise((r) => server.close(r)));
  beforeEach(() => {
    received.length = 0;
    status = 200;
  });

  const sender = () =>
    new AlertSender(
      alertsConfig() as never,
      new StaticGuard(
        alertsConfig({ allowPrivateTargets: true, allowInsecureTargets: true }),
        {},
      ),
    );

  it('signs webhook payloads (HMAC over timestamp.body)', async () => {
    await sender().send(
      {
        id: 'c',
        name: 'hook',
        type: 'WEBHOOK',
        target: `${base}/hook`,
        signingSecret: 'whsec_test',
      },
      [payload()],
      ['d1'],
    );
    const { headers, body } = received[0];
    expect(JSON.parse(body)).toMatchObject({
      type: 'fuzzer.alert',
      id: 'd1',
      alert: { domain: 'paypa1.com' },
    });
    expect(headers['x-fuzzer-signature']).toBe(
      `sha256=${signature('whsec_test', String(headers['x-fuzzer-timestamp']), body)}`,
    );
  });

  it('formats Slack messages and digests', async () => {
    await sender().send(
      {
        id: 'c',
        name: 's',
        type: 'SLACK',
        target: `${base}/slack`,
        signingSecret: null,
      },
      [payload(), payload({ domain: 'paypai.com' })],
      ['a', 'b'],
    );
    const msg = JSON.parse(received[0].body);
    expect(msg.text).toBe('2 look-alike alerts');
    expect(msg.blocks[0].type).toBe('header');
    expect(msg.blocks[1].text.text).toContain(
      '`paypa1.com` imitates *paypal.com*',
    );
    expect(received[0].headers['x-fuzzer-signature']).toBeUndefined();
  });

  it('classifies failures: 4xx permanent, 429/5xx/network retryable', async () => {
    const ch = {
      id: 'c',
      name: 'h',
      type: 'WEBHOOK' as const,
      target: `${base}/x`,
      signingSecret: null,
    };
    status = 410;
    await expect(sender().send(ch, [payload()], ['d'])).rejects.toBeInstanceOf(
      PermanentDeliveryError,
    );
    status = 429;
    await expect(
      sender().send(ch, [payload()], ['d']),
    ).rejects.not.toBeInstanceOf(PermanentDeliveryError);
    status = 503;
    await expect(sender().send(ch, [payload()], ['d'])).rejects.toThrow(
      /HTTP 503/,
    );
    await expect(
      sender().send(
        { ...ch, target: 'http://127.0.0.1:1/' },
        [payload()],
        ['d'],
      ),
    ).rejects.not.toBeInstanceOf(PermanentDeliveryError);
  });

  it('treats an unsafe target as permanent and e-mail without SMTP as permanent', async () => {
    const strict = new AlertSender(
      alertsConfig() as never,
      new StaticGuard(alertsConfig(), {}),
    );
    await expect(
      strict.send(
        {
          id: 'c',
          name: 'h',
          type: 'WEBHOOK',
          target: `${base}/x`,
          signingSecret: null,
        },
        [payload()],
        ['d'],
      ),
    ).rejects.toBeInstanceOf(PermanentDeliveryError);
    await expect(
      strict.send(
        {
          id: 'c',
          name: 'm',
          type: 'EMAIL',
          target: 'soc@acme.com',
          signingSecret: null,
        },
        [payload()],
        ['d'],
      ),
    ).rejects.toThrow(/SMTP_URL/);
  });
});

describe('AlertChannelsService', () => {
  function setup() {
    const tx = {
      alertChannel: {
        create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
          id: 'c1',
          createdAt: new Date(),
          updatedAt: new Date(),
          ...data,
        })),
      },
    };
    const bus = fakeBus(tx);
    const crypto = new AlertCrypto(alertsConfig() as never);
    const guard = new StaticGuard(alertsConfig(), {
      'hooks.slack.com': ['3.3.3.3'],
      'hooks.acme.com': ['4.4.4.4'],
    });
    const svc = new AlertChannelsService({} as never, bus.bus, crypto, guard);
    return { svc, tx, bus, crypto };
  }

  it('encrypts the target, masks it, and returns the webhook secret only once', async () => {
    const { svc, tx, bus, crypto } = setup();
    const created = await svc.create(
      {
        name: 'SOC hook',
        type: 'WEBHOOK',
        target: 'https://hooks.acme.com/in/abcd',
      },
      'ana',
    );
    const data = tx.alertChannel.create.mock.calls[0][0].data;
    expect(crypto.open(String(data.targetEncrypted))).toBe(
      'https://hooks.acme.com/in/abcd',
    );
    expect(data.targetHint).toBe('https://hooks.acme.com/…abcd');
    expect(created.signingSecret).toMatch(/^whsec_/);
    expect(crypto.open(String(data.signingSecretEncrypted))).toBe(
      created.signingSecret,
    );
    expect(created).toMatchObject({ signed: true, createdBy: 'ana' });
    expect(JSON.stringify(created)).not.toContain('hooks.acme.com/in/abcd');
    expect(bus.afterNames()).toEqual([ALERT_EVENTS.CHANNEL_WRITTEN]);
  });

  it('validates targets per type', async () => {
    const { svc } = setup();
    await expect(
      svc.validateTarget('EMAIL', 'SOC@acme.com, soc@acme.com,ana@acme.com'),
    ).resolves.toBe('soc@acme.com, ana@acme.com');
    await expect(svc.validateTarget('EMAIL', 'nope')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(
      svc.validateTarget('SLACK', 'https://hooks.acme.com/x'),
    ).rejects.toThrow(/hooks.slack.com/);
    await expect(
      svc.validateTarget('WEBHOOK', 'http://hooks.acme.com/x'),
    ).rejects.toThrow(/https/);
  });
});

describe('AlertsService', () => {
  const lookalike = {
    id: 'sd1',
    domain: 'paypa1.com',
    unicodeDomain: 'paypa1.com',
    originalDomainId: 'od1',
    originalDomain: { domain: 'paypal.com' },
    fuzzer: 'homoglyph',
    riskScore: 120,
    threatLevel: 'HIGH_RISK',
    status: 'ACTIVE',
  };

  function setup(
    subs: { id: string; channelId: string; mode: 'IMMEDIATE' | 'DIGEST' }[],
    inserted = true,
  ) {
    const tx = {
      $queryRaw: vi.fn(async () =>
        inserted ? [{ id: `d-${Math.random()}` }] : [],
      ),
    };
    const bus = fakeBus(tx);
    const prisma = {
      alertSubscription: { findMany: vi.fn(async () => subs) },
      alertDelivery: {
        findUnique: vi.fn(),
        update: vi.fn(async () => ({})),
        updateMany: vi.fn(async () => ({})),
        groupBy: vi.fn(async () => []),
        findMany: vi.fn(async () => []),
      },
    };
    const channels = {
      resolve: vi.fn(async () => ({
        id: 'c1',
        name: 'hook',
        type: 'WEBHOOK',
        target: 'https://x',
        signingSecret: null,
        isActive: true,
      })),
    };
    const sender = { send: vi.fn(async () => undefined) };
    const svc = new AlertsService(
      prisma as never,
      bus.bus,
      { getForEnrichment: vi.fn(async () => lookalike) } as never,
      channels as never,
      sender as never,
      alertsConfig() as never,
    );
    return { svc, prisma, tx, bus, sender, channels };
  }

  it('matches subscriptions by event, brand, risk and active channel', async () => {
    const { svc, prisma } = setup([]);
    await svc.raise('HIGH_RISK', 'sd1');
    expect(
      (prisma.alertSubscription.findMany.mock.calls[0] as unknown[])[0],
    ).toMatchObject({
      where: {
        isActive: true,
        eventTypes: { has: 'HIGH_RISK' },
        minRiskScore: { lte: 120 },
        channel: { isActive: true },
        OR: [{ originalDomainId: null }, { originalDomainId: 'od1' }],
      },
    });
  });

  it('records one delivery per subscription, queues only IMMEDIATE ones, idempotently', async () => {
    const { svc, tx, bus } = setup([
      { id: 's1', channelId: 'c1', mode: 'IMMEDIATE' },
      { id: 's2', channelId: 'c2', mode: 'DIGEST' },
    ]);
    expect(
      await svc.raise('HIGH_RISK', 'sd1', ['Matched rule: domain_age']),
    ).toBe(2);
    const sql = (
      tx.$queryRaw.mock.calls[0] as unknown as [TemplateStringsArray]
    )[0].join('?');
    expect(sql).toMatch(/ON CONFLICT \(dedupe_key\) DO NOTHING/);
    const args = tx.$queryRaw.mock.calls[0] as unknown[];
    expect(args).toContain(
      `s1:HIGH_RISK:sd1:${new Date().toISOString().slice(0, 10)}`,
    );
    expect(JSON.parse(String(args.at(-1)))).toMatchObject({
      domain: 'paypa1.com',
      brand: 'paypal.com',
      consoleUrl: 'https://console.test/lookalikes/sd1',
    });
    expect(bus.afterNames()).toEqual([ALERT_EVENTS.QUEUED]);
  });

  it('raises nothing new for an alert already recorded today', async () => {
    const { svc, bus } = setup(
      [{ id: 's1', channelId: 'c1', mode: 'IMMEDIATE' }],
      false,
    );
    expect(await svc.raise('HIGH_RISK', 'sd1')).toBe(0);
    expect(bus.after).toEqual([]);
  });

  it('delivers a pending alert once and records failures', async () => {
    const { svc, prisma, sender } = setup([]);
    prisma.alertDelivery.findUnique.mockResolvedValue({
      id: 'd1',
      status: 'PENDING',
      channelId: 'c1',
      eventType: 'HIGH_RISK',
      payload: payload(),
    } as never);
    expect(await svc.deliver('d1', false)).toBe('sent');
    expect(prisma.alertDelivery.update).toHaveBeenLastCalledWith({
      where: { id: 'd1' },
      data: expect.objectContaining({ status: 'SENT' }),
    });

    sender.send.mockRejectedValueOnce(new Error('HTTP 503'));
    await expect(svc.deliver('d1', false)).rejects.toThrow('HTTP 503');
    expect(prisma.alertDelivery.update).toHaveBeenLastCalledWith({
      where: { id: 'd1' },
      data: expect.not.objectContaining({ status: 'FAILED' }),
    });

    sender.send.mockRejectedValueOnce(new PermanentDeliveryError('HTTP 410'));
    await expect(svc.deliver('d1', false)).rejects.toBeInstanceOf(
      PermanentDeliveryError,
    );
    expect(prisma.alertDelivery.update).toHaveBeenLastCalledWith({
      where: { id: 'd1' },
      data: expect.objectContaining({ status: 'FAILED' }),
    });

    prisma.alertDelivery.findUnique.mockResolvedValueOnce({
      id: 'd1',
      status: 'SENT',
    } as never);
    expect(await svc.deliver('d1', false)).toBe('skipped');
  });

  it('sends one digest message per channel and marks them sent', async () => {
    const { svc, prisma, sender } = setup([]);
    prisma.alertDelivery.groupBy.mockResolvedValueOnce([
      { channelId: 'c1' },
    ] as never);
    prisma.alertDelivery.findMany.mockResolvedValueOnce([
      { id: 'a', payload: payload() },
      { id: 'b', payload: payload({ domain: 'paypai.com' }) },
    ] as never);
    expect(await svc.sendDigests()).toEqual({
      channels: 1,
      sent: 2,
      failed: 0,
    });
    expect((sender.send.mock.calls[0] as unknown[])[1]).toHaveLength(2);
    expect(prisma.alertDelivery.updateMany).toHaveBeenCalledWith({
      where: { id: { in: ['a', 'b'] } },
      data: expect.objectContaining({ status: 'SENT' }),
    });
  });

  it('test() reports channel failures without throwing', async () => {
    const { svc, sender } = setup([]);
    sender.send.mockRejectedValueOnce(new Error('HTTP 404'));
    expect(await svc.test('c1')).toEqual({ ok: false, error: 'HTTP 404' });
    expect(await svc.test('c1')).toEqual({ ok: true });
  });
});

describe('AlertTriggerListener & processor', () => {
  it('maps domain events to alert types', async () => {
    const alerts = { raise: vi.fn(async () => 1) };
    const enqueuer = { enqueue: vi.fn(async () => undefined) };
    const l = new AlertTriggerListener(alerts as never, enqueuer as never);
    await l.onHighRisk({
      scannedDomainId: 'a',
      matchedRules: ['domain_age'],
    } as never);
    await l.onDiscovered({ scannedDomainId: 'b', resolvesToIp: true } as never);
    await l.onStatusChanged({
      scannedDomainId: 'c',
      from: 'NEW',
      to: 'CONFIRMED_THREAT',
      actor: 'ana',
    } as never);
    await l.onStatusChanged({
      scannedDomainId: 'd',
      from: 'INACTIVE',
      to: 'ACTIVE',
      actor: 'system',
    } as never);
    await l.onStatusChanged({
      scannedDomainId: 'e',
      from: 'NEW',
      to: 'UNDER_REVIEW',
      actor: 'ana',
    } as never);
    expect(
      alerts.raise.mock.calls.map((c) => (c as unknown[]).slice(0, 2)),
    ).toEqual([
      ['HIGH_RISK', 'a'],
      ['NEW_LOOKALIKE', 'b'],
      ['CONFIRMED_THREAT', 'c'],
      ['WENT_LIVE', 'd'],
    ]);
    await l.onQueued({ deliveryId: 'd1' } as never);
    expect(enqueuer.enqueue).toHaveBeenCalledWith('d1');
    alerts.raise.mockRejectedValueOnce(new Error('db'));
    await expect(
      l.onHighRisk({ scannedDomainId: 'x', matchedRules: [] } as never),
    ).resolves.toBeUndefined();
  });

  it('processor: permanent failures stop retrying; the last attempt marks FAILED', async () => {
    const alerts = {
      deliver: vi.fn(async () => 'sent'),
      sendDigests: vi.fn(async () => ({ channels: 0 })),
    };
    const p = new AlertsProcessor(alerts as never);
    const job = (attemptsMade: number, name = 'send-alert') => ({
      id: '1',
      name,
      data: { deliveryId: 'd1' },
      attemptsMade,
      opts: { attempts: 6 },
    });
    expect(await p.process(job(0) as never)).toEqual({ result: 'sent' });
    expect(alerts.deliver).toHaveBeenLastCalledWith('d1', false);
    await p.process(job(5) as never);
    expect(alerts.deliver).toHaveBeenLastCalledWith('d1', true);
    alerts.deliver.mockRejectedValueOnce(
      new PermanentDeliveryError('HTTP 410'),
    );
    await expect(p.process(job(0) as never)).rejects.toBeInstanceOf(
      UnrecoverableError,
    );
    expect(await p.process(job(0, 'send-digest') as never)).toEqual({
      channels: 0,
    });
  });
});
