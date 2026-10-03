import { NotFoundException } from '@nestjs/common';
import { fakeBus } from '../../testing/fake-bus.js';
import { OriginalDomainsQuery } from '../original-domains/original-domains.query.js';
import { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import { BrandReferenceController } from '../screenshots/brand-reference.controller.js';
import {
  BrandReferenceListener,
  BrandReferenceScheduler,
} from '../screenshots/listeners/brand-reference.listener.js';
import { ScreenshotsQuery } from '../screenshots/screenshots.query.js';
import { AlertSubscriptionsService } from './alert-subscriptions.service.js';
import { AlertsController } from './alerts.controller.js';
import { AlertsEnqueuer } from './alerts.enqueuer.js';
import { AlertsScheduler } from './alerts.scheduler.js';
import { ALERT_EVENTS } from './events/alert.events.js';

const principal = { name: 'k', scope: 'write' as const, actor: 'ana@x' };

describe('AlertsController', () => {
  it('delegates every route with the acting user', async () => {
    const channels = {
      list: vi.fn(async () => []),
      create: vi.fn(async () => ({})),
      findOne: vi.fn(async () => ({})),
      update: vi.fn(async () => ({})),
      remove: vi.fn(async () => undefined),
      rotateSecret: vi.fn(async () => ({})),
    };
    const subs = {
      list: vi.fn(async () => []),
      create: vi.fn(async () => ({})),
      update: vi.fn(async () => ({})),
      remove: vi.fn(async () => undefined),
    };
    const alerts = {
      test: vi.fn(async () => ({ ok: true })),
      deliveries: vi.fn(async () => ({ data: [] })),
    };
    const c = new AlertsController(
      channels as never,
      subs as never,
      alerts as never,
    );
    await c.listChannels();
    await c.createChannel(
      { name: 'n', type: 'WEBHOOK', target: 'https://x' },
      principal,
    );
    await c.getChannel('id');
    await c.updateChannel('id', { isActive: false }, principal);
    await c.removeChannel('id', principal);
    await c.rotate('id', principal);
    expect(await c.test('id')).toEqual({ ok: true });
    await c.listSubscriptions('ch');
    await c.createSubscription(
      { channelId: 'ch', eventTypes: ['HIGH_RISK'] },
      principal,
    );
    await c.updateSubscription('s', { isActive: false }, principal);
    await c.removeSubscription('s', principal);
    await c.listDeliveries({
      page: 1,
      limit: 25,
      skip: 0,
      order: 'desc',
    } as never);
    expect(channels.create).toHaveBeenCalledWith(expect.anything(), 'ana@x');
    expect(channels.rotateSecret).toHaveBeenCalledWith('id', 'ana@x');
    expect(subs.list).toHaveBeenCalledWith('ch');
    expect(subs.remove).toHaveBeenCalledWith('s', 'ana@x');
    expect(alerts.deliveries).toHaveBeenCalled();
  });
});

describe('AlertSubscriptionsService', () => {
  const row = {
    id: 's1',
    channelId: 'c1',
    channel: { name: 'SOC' },
    originalDomainId: null,
    originalDomain: null,
    eventTypes: ['HIGH_RISK'],
    minRiskScore: 0,
    mode: 'IMMEDIATE',
    isActive: true,
    createdAt: new Date(),
  };
  function setup(exists = true) {
    const tx = {
      alertSubscription: {
        create: vi.fn(async () => row),
        update: vi.fn(async () => row),
        delete: vi.fn(async () => row),
      },
    };
    const bus = fakeBus(tx);
    const prisma = {
      alertSubscription: {
        findMany: vi.fn(async () => [row]),
        findUnique: vi.fn(async () => (exists ? { id: 's1' } : null)),
      },
    };
    return {
      svc: new AlertSubscriptionsService(prisma as never, bus.bus),
      tx,
      bus,
      prisma,
    };
  }

  it('creates (de-duplicating event types), lists, updates and deletes through the bus', async () => {
    const { svc, tx, bus, prisma } = setup();
    expect(
      await svc.create(
        { channelId: 'c1', eventTypes: ['HIGH_RISK', 'HIGH_RISK'] },
        'ana',
      ),
    ).toMatchObject({ channelName: 'SOC', brand: null });
    expect(
      (tx.alertSubscription.create.mock.calls[0] as unknown[])[0],
    ).toMatchObject({
      data: { eventTypes: ['HIGH_RISK'], minRiskScore: 0 },
    });
    expect(await svc.list('c1')).toHaveLength(1);
    expect(
      (prisma.alertSubscription.findMany.mock.calls[0] as unknown[])[0],
    ).toMatchObject({
      where: { channelId: 'c1' },
    });
    await svc.update('s1', { minRiskScore: 80 }, 'ana');
    await svc.remove('s1', 'ana');
    expect(bus.afterNames()).toEqual([
      ALERT_EVENTS.SUBSCRIPTION_WRITTEN,
      ALERT_EVENTS.SUBSCRIPTION_WRITTEN,
      ALERT_EVENTS.SUBSCRIPTION_WRITTEN,
    ]);
  });

  it('404s unknown subscriptions', async () => {
    const { svc } = setup(false);
    await expect(svc.update('nope', {}, 'ana')).rejects.toBeInstanceOf(
      NotFoundException,
    );
    await expect(svc.remove('nope', 'ana')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('alert & reference jobs', () => {
  it('enqueues one alert job per delivery and schedules the digest in UTC', async () => {
    const queue = {
      add: vi.fn(async () => ({})),
      upsertJobScheduler: vi.fn(async () => ({})),
    };
    await new AlertsEnqueuer(queue as never).enqueue('d1');
    expect(queue.add).toHaveBeenCalledWith(
      'send-alert',
      { deliveryId: 'd1' },
      expect.objectContaining({ jobId: 'alert-d1', attempts: 6 }),
    );
    await new AlertsScheduler(
      queue as never,
      { get: () => ({ digestCron: '0 8 * * *' }) } as never,
    ).onApplicationBootstrap();
    expect(queue.upsertJobScheduler).toHaveBeenCalledWith(
      'alerts-digest',
      { pattern: '0 8 * * *', tz: 'UTC' },
      expect.objectContaining({ name: 'send-digest' }),
    );
    await new BrandReferenceScheduler(queue as never).onApplicationBootstrap();
    expect(queue.upsertJobScheduler).toHaveBeenLastCalledWith(
      'brand-references-weekly',
      expect.objectContaining({ tz: 'UTC' }),
      expect.objectContaining({ name: 'refresh-references' }),
    );
  });

  it('captures a brand reference when an active brand is added or re-activated', async () => {
    const refs = { enqueue: vi.fn(async () => 'j') };
    const l = new BrandReferenceListener(refs as never);
    await l.onCreated({
      originalDomain: { id: 'b1', isActive: true },
    } as never);
    await l.onCreated({
      originalDomain: { id: 'b2', isActive: false },
    } as never);
    await l.onUpdated({
      originalDomain: { id: 'b1', isActive: true },
      changedFields: ['isActive'],
    } as never);
    await l.onUpdated({
      originalDomain: { id: 'b1', isActive: true },
      changedFields: ['label'],
    } as never);
    expect(refs.enqueue.mock.calls).toEqual([['b1'], ['b1']]);
    refs.enqueue.mockRejectedValueOnce(new Error('redis'));
    await expect(
      l.onCreated({ originalDomain: { id: 'b3', isActive: true } } as never),
    ).resolves.toBeUndefined();
  });
});

describe('BrandReferenceController', () => {
  const ref = {
    originalDomainId: 'b1',
    status: 'CAPTURED',
    perceptualHash: 'ab',
    faviconHash: null,
    pageTitle: 'PayPal',
    finalUrl: 'https://www.paypal.com/',
    errorMessage: null,
    capturedAt: new Date(),
    storageKey: 'brand-references/b1.png',
  };
  it('shows the reference, redirects to the image and queues refreshes', async () => {
    const refs = {
      get: vi.fn(async () => ref),
      imageUrl: vi.fn(async () => 'https://s3/signed'),
      enqueue: vi.fn(async () => 'job-1'),
    };
    const prisma = {
      originalDomain: {
        findFirst: vi.fn(async ({ where }: { where: { id: string } }) =>
          where.id === 'b1' ? { id: 'b1' } : null,
        ),
      },
    };
    const c = new BrandReferenceController(refs as never, prisma as never);
    expect(await c.get('b1')).toMatchObject({
      status: 'CAPTURED',
      imageUrl: '/api/v1/original-domains/b1/reference/image',
    });
    expect(await c.image('b1')).toEqual({
      url: 'https://s3/signed',
      statusCode: 302,
    });
    expect(await c.refresh('b1')).toEqual({ queued: true, jobId: 'job-1' });
    expect(refs.enqueue).toHaveBeenCalledWith('b1', true);
    await expect(c.refresh('nope')).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('Phase 5 read queries', () => {
  it('select exactly what scoring, CT and alerting need', async () => {
    const prisma = {
      screenshot: { findFirst: vi.fn(async () => null) },
      scannedDomain: {
        findMany: vi.fn(async () => [
          { id: 'a', domain: 'x.com', fuzzer: 'ct:combo' },
        ]),
      },
      brandReference: { findUnique: vi.fn(async () => null) },
      originalDomain: {
        findMany: vi.fn(async () => [{ id: 'b1', domain: 'paypal.com' }]),
      },
    };
    const shots = new ScreenshotsQuery(prisma as never);
    await shots.latestCaptured('sd');
    expect(
      (prisma.screenshot.findFirst.mock.calls[0] as unknown[])[0],
    ).toMatchObject({
      where: { scannedDomainId: 'sd', status: 'CAPTURED' },
    });
    expect(await shots.capturedLookalikes('b1')).toEqual(['a']);
    await shots.reference('b1');
    expect(prisma.brandReference.findUnique).toHaveBeenCalledWith({
      where: { originalDomainId: 'b1' },
    });

    expect(
      await new ScannedDomainsQuery(prisma as never).ctDomains('b1'),
    ).toEqual([['x.com', 'ct:combo']]);
    expect(
      (prisma.scannedDomain.findMany.mock.calls.at(-1) as unknown[])[0],
    ).toMatchObject({
      where: { fuzzer: { startsWith: 'ct:' }, deletedAt: null },
    });
    expect(
      await new OriginalDomainsQuery(prisma as never).listActive(),
    ).toEqual([{ id: 'b1', domain: 'paypal.com' }]);
  });
});
