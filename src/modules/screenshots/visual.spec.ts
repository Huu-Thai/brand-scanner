import { createHash } from 'node:crypto';
import sharp from 'sharp';
import { fakeBus } from '../../testing/fake-bus.js';
import { AnalyticsTriggerListener } from '../analytics/listeners/analytics-trigger.listener.js';
import {
  PhishingContentRule,
  VisualSimilarityRule,
} from '../rules/rules/content.rules.js';
import type {
  RuleConfigRecord,
  RuleEvaluationInput,
} from '../rules/rule.types.js';
import {
  BrandReferenceService,
  referenceKey,
} from './brand-reference.service.js';
import { SiteUnreachableError } from './capture/selenium-capture.service.js';
import { collectPageSignals } from './capture/page-signals.js';
import { SCREENSHOT_EVENTS } from './events/screenshot.events.js';

const cfg = (
  key: string,
  points: [string, number][],
  params = {},
): RuleConfigRecord => ({
  key,
  name: key,
  enabled: true,
  points: points.map(([condition, p]) => ({ condition, points: p })),
  params,
});
const visualCfg = cfg(
  'visual_similarity',
  [
    ['identical', 40],
    ['similar', 20],
    ['default', 0],
  ],
  {
    identicalMaxDistance: 6,
    similarMaxDistance: 12,
  },
);
const contentCfg = cfg('phishing_content', [
  ['credential_form', 35],
  ['favicon_clone', 30],
  ['brand_mentions', 10],
  ['default', 0],
]);

const page = (
  over: Partial<NonNullable<RuleEvaluationInput['page']>> = {},
) => ({
  perceptualHash: 'ffff0000ffff0000',
  faviconHash: null,
  title: 'Welcome',
  hasPasswordField: false,
  formActionHosts: [],
  text: '',
  ...over,
});
const input = (
  over: Partial<RuleEvaluationInput> = {},
): RuleEvaluationInput => ({
  originalDomain: 'paypal.com',
  fuzzerDomain: 'paypa1-login.com',
  ...over,
});

describe('VisualSimilarityRule', () => {
  const rule = new VisualSimilarityRule();
  it.each([
    ['ffff0000ffff0000', 'identical', 40, '100%'],
    ['ffff0000ffff003f', 'identical', 40, '91%'], // 6 bits off
    ['ffff0000ffff0fff', 'similar', 20, '81%'], // 12 bits off
    ['0000ffff0000ffff', 'default', 0, '0%'],
  ])('reference %s → %s', async (ref, condition, points, pct) => {
    const r = await rule.evaluate(
      visualCfg,
      input({
        page: page(),
        reference: { perceptualHash: ref, faviconHash: null },
      }),
    );
    expect(r).toMatchObject({
      condition,
      points,
      value: expect.stringContaining(pct),
    });
  });

  it('is not evaluated until both captures exist', async () => {
    expect(
      await rule.evaluate(visualCfg, input({ page: page() })),
    ).toMatchObject({ condition: null, points: 0 });
    expect(await rule.evaluate(visualCfg, input())).toMatchObject({
      condition: null,
      points: 0,
    });
  });
});

describe('PhishingContentRule', () => {
  const rule = new PhishingContentRule();
  const run = (p: Parameters<typeof page>[0], ref?: string) =>
    rule.evaluate(
      contentCfg,
      input({
        page: page(p),
        reference: ref ? { perceptualHash: null, faviconHash: ref } : undefined,
      }),
    );

  it('credential form naming the brand, or posting elsewhere', async () => {
    expect(
      await run({
        hasPasswordField: true,
        text: 'log in to your paypal account',
      }),
    ).toMatchObject({
      condition: 'credential_form',
      points: 35,
      value: 'password form naming "paypal"',
    });
    expect(
      await run({
        hasPasswordField: true,
        formActionHosts: ['collector.evil.ru'],
      }),
    ).toMatchObject({
      condition: 'credential_form',
      value: 'password form posting to collector.evil.ru',
    });
    // A plain login form posting to itself, with no brand, is not phishing evidence.
    expect(
      await run({
        hasPasswordField: true,
        formActionHosts: ['paypa1-login.com'],
      }),
    ).toMatchObject({ condition: 'default', points: 0 });
  });

  it("brand's favicon, then brand mentions", async () => {
    expect(await run({ faviconHash: 'abc' }, 'abc')).toMatchObject({
      condition: 'favicon_clone',
      points: 30,
    });
    expect(await run({ faviconHash: 'abc' }, 'def')).toMatchObject({
      condition: 'default',
    });
    expect(await run({ title: 'PayPal | Secure' })).toMatchObject({
      condition: 'brand_mentions',
      points: 10,
    });
  });

  it('is not evaluated without a capture', async () => {
    expect(await rule.evaluate(contentCfg, input())).toMatchObject({
      condition: null,
      points: 0,
    });
  });
});

describe('collectPageSignals', () => {
  it('reads DOM facts and hashes the favicon fetched by the page', async () => {
    const driver = {
      executeScript: vi.fn(async () => ({
        hasPasswordField: true,
        formActionHosts: ['evil.example'],
        text: '  Sign IN to   PayPal ',
        favicon: 'https://paypa1.com/favicon.ico',
      })),
      executeAsyncScript: vi.fn(async () =>
        Buffer.from('icon-bytes').toString('base64'),
      ),
      manage: () => ({ setTimeouts: vi.fn(async () => undefined) }),
    };
    expect(await collectPageSignals(driver as never)).toEqual({
      hasPasswordField: true,
      formActionHosts: ['evil.example'],
      text: ' sign in to paypal ',
      faviconHash: createHash('sha256').update('icon-bytes').digest('hex'),
    });
  });

  it('never throws: a hostile page yields empty signals', async () => {
    const driver = {
      executeScript: vi.fn(async () =>
        Promise.reject(new Error('script blocked')),
      ),
    };
    expect(await collectPageSignals(driver as never)).toEqual({
      hasPasswordField: false,
      formActionHosts: [],
      text: '',
      faviconHash: null,
    });
  });
});

describe('BrandReferenceService', () => {
  async function setup(
    capture: () => Promise<unknown>,
    existing: Record<string, unknown> | null = null,
  ) {
    const png = await sharp({
      create: { width: 30, height: 20, channels: 3, background: '#0070ba' },
    })
      .png()
      .toBuffer();
    const tx = {
      brandReference: {
        upsert: vi.fn(
          async ({ create }: { create: Record<string, unknown> }) => ({
            id: 'r1',
            ...create,
          }),
        ),
      },
    };
    const bus = fakeBus(tx);
    const prisma = {
      originalDomain: {
        findFirst: vi.fn(async () => ({ id: 'b1', domain: 'paypal.com' })),
        findMany: vi.fn(async () => [{ id: 'b1' }, { id: 'b2' }]),
      },
      brandReference: { findUnique: vi.fn(async () => existing) },
    };
    const storage = {
      putObject: vi.fn(async () => undefined),
      getSignedUrl: vi.fn(async () => 'https://s3/x'),
    };
    const queue = {
      add: vi.fn(async (_n: string, _d: unknown, o: { jobId: string }) => ({
        id: o.jobId,
      })),
    };
    const svc = new BrandReferenceService(
      prisma as never,
      bus.bus,
      {
        capture: vi.fn(
          async () =>
            (await capture()) ?? {
              png,
              finalUrl: 'https://www.paypal.com/',
              pageTitle: 'PayPal',
              signals: { faviconHash: 'f'.repeat(64) },
            },
        ),
      } as never,
      storage as never,
      queue as never,
    );
    return { svc, tx, bus, storage, queue };
  }

  it('captures the brand site, stores it under a deterministic key and emits an event', async () => {
    const { svc, tx, bus, storage } = await setup(async () => undefined);
    const row = await svc.captureNow('b1');
    expect(storage.putObject).toHaveBeenCalledWith(
      referenceKey('b1'),
      expect.any(Buffer),
      'image/png',
    );
    expect(row).toMatchObject({
      status: 'CAPTURED',
      perceptualHash: expect.stringMatching(/^[0-9a-f]{16}$/),
      faviconHash: 'f'.repeat(64),
    });
    expect(tx.brandReference.upsert.mock.calls[0][0]).toMatchObject({
      where: { originalDomainId: 'b1' },
    });
    expect(bus.after[0]).toMatchObject({
      name: SCREENSHOT_EVENTS.REFERENCE_CAPTURED,
      status: 'CAPTURED',
    });
  });

  it('keeps the last good reference when the brand site is temporarily unreachable', async () => {
    const good = { status: 'CAPTURED', perceptualHash: 'ab' };
    const { svc, tx } = await setup(
      async () => Promise.reject(new SiteUnreachableError('down')),
      good,
    );
    expect(await svc.captureNow('b1')).toBe(good);
    expect(tx.brandReference.upsert).not.toHaveBeenCalled();
  });

  it('records FAILED when there is no previous capture; Grid errors propagate (retry)', async () => {
    const down = await setup(async () =>
      Promise.reject(new SiteUnreachableError('down')),
    );
    expect(await down.svc.captureNow('b1')).toMatchObject({
      status: 'FAILED',
      errorMessage: 'down',
    });
    const grid = await setup(async () =>
      Promise.reject(new Error('grid busy')),
    );
    await expect(grid.svc.captureNow('b1')).rejects.toThrow('grid busy');
  });

  it('queues one capture per brand per day, plus on-demand refreshes', async () => {
    const { svc, queue } = await setup(async () => undefined);
    expect(await svc.enqueue('b1')).toBe(
      `brand-ref-b1-${new Date().toISOString().slice(0, 10)}`,
    );
    expect(await svc.enqueue('b1', true)).toMatch(/^brand-ref-b1-manual-/);
    expect(await svc.refreshAll()).toBe(2);
    expect(queue.add).toHaveBeenCalledTimes(4);
  });
});

describe('rescoring triggers', () => {
  it('rescores on a new capture and every captured look-alike when the reference changes', async () => {
    const enqueuer = { enqueue: vi.fn(async () => 'j') };
    const shots = { capturedLookalikes: vi.fn(async () => ['a', 'b']) };
    const l = new AnalyticsTriggerListener(enqueuer as never, shots as never);
    await l.onScreenshot({ scannedDomainId: 'x' } as never);
    await l.onReference({
      originalDomainId: 'b1',
      status: 'CAPTURED',
    } as never);
    await l.onReference({ originalDomainId: 'b1', status: 'FAILED' } as never);
    expect(
      enqueuer.enqueue.mock.calls.map((c) => (c as unknown[]).slice(0, 2)),
    ).toEqual([
      ['x', 'screenshot'],
      ['a', 'reference'],
      ['b', 'reference'],
    ]);
  });
});
