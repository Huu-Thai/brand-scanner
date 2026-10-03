import { UnrecoverableError } from 'bullmq';
import { DomainStatus as S } from '../../database/generated/prisma/enums.js';
import { ThreatFeedError } from '../../integrations/threat-feed/threat-feed.client.js';
import { ReviewCreatedEvent } from '../reviews/events/review.events.js';
import { ScannedDomainStatusChangedEvent } from '../scanned-domains/events/scanned-domain.events.js';
import {
  indicatorFor,
  pushActionFor,
  severityFor,
} from './indicator.mapper.js';
import { StatusSyncListener } from './listeners/status-sync.listener.js';
import { ThreatFeedPushProcessor } from './processors/threat-feed-push.processor.js';

describe('indicator mapping', () => {
  it.each([
    [S.NEW, S.CONFIRMED_THREAT, 'upsert'],
    [S.UNDER_REVIEW, S.CONFIRMED_THREAT, 'upsert'],
    [S.CONFIRMED_THREAT, S.FALSE_POSITIVE, 'deactivate'],
    [S.CONFIRMED_THREAT, S.ALLOWLISTED, 'deactivate'],
    [S.CONFIRMED_THREAT, S.TAKEN_DOWN, 'deactivate'],
    [S.NEW, S.UNDER_REVIEW, null],
    [S.ACTIVE, S.INACTIVE, null],
  ] as const)('%s → %s = %s', (from, to, action) => {
    expect(pushActionFor(from, to)).toBe(action);
  });

  it('builds a DOMAIN indicator with provenance tags', () => {
    expect(
      indicatorFor(
        {
          domain: 'APYPAL.com',
          fuzzer: 'Transposition',
          threatLevel: 'MEDIUM_RISK',
          originalDomain: { domain: 'paypal.com' },
        },
        'src-1',
      ),
    ).toEqual({
      value: 'apypal.com',
      type: 'DOMAIN',
      sourceId: 'src-1',
      severity: 'high',
      confidence: 95,
      isActive: true,
      tags: [
        'typosquat',
        'source:fuzzer-scanner',
        'fuzzer:transposition',
        'brand:paypal.com',
      ],
    });
    expect(severityFor('HIGH_RISK')).toBe('critical');
  });
});

describe('StatusSyncListener', () => {
  const setup = (pushEnabled = true) => {
    const enqueuer = { enqueue: vi.fn(async () => 'job') };
    const config = { get: () => pushEnabled };
    return {
      listener: new StatusSyncListener(config as never, enqueuer as never),
      enqueuer,
    };
  };
  const changed = (from: S, to: S) =>
    new ScannedDomainStatusChangedEvent(
      'sd',
      'o',
      'a.com',
      from,
      to,
      'review',
      'ana',
    );

  it('queues an upsert when a look-alike is confirmed', async () => {
    const { listener, enqueuer } = setup();
    await listener.onStatusChanged(changed(S.NEW, S.CONFIRMED_THREAT));
    expect(enqueuer.enqueue).toHaveBeenCalledWith({
      scannedDomainId: 'sd',
      domain: 'a.com',
      action: 'upsert',
      actor: 'ana',
    });
  });

  it('ignores irrelevant transitions and does nothing when push is disabled', async () => {
    const on = setup();
    await on.listener.onStatusChanged(changed(S.NEW, S.UNDER_REVIEW));
    expect(on.enqueuer.enqueue).not.toHaveBeenCalled();
    const off = setup(false);
    await off.listener.onStatusChanged(changed(S.NEW, S.CONFIRMED_THREAT));
    expect(off.enqueuer.enqueue).not.toHaveBeenCalled();
  });

  it('re-publishes on a repeated MALICIOUS review (no status change)', async () => {
    const { listener, enqueuer } = setup();
    await listener.onReviewed(
      new ReviewCreatedEvent(
        'r',
        'sd',
        'MALICIOUS',
        S.CONFIRMED_THREAT,
        S.CONFIRMED_THREAT,
        'ana',
      ),
    );
    await listener.onReviewed(
      new ReviewCreatedEvent(
        'r',
        'sd',
        'MALICIOUS',
        S.NEW,
        S.CONFIRMED_THREAT,
        'ana',
      ),
    );
    expect(enqueuer.enqueue).toHaveBeenCalledTimes(1); // the second is handled by status-changed
  });

  it('never throws when the queue is unavailable', async () => {
    const { listener, enqueuer } = setup();
    enqueuer.enqueue.mockRejectedValueOnce(new Error('redis down'));
    await expect(
      listener.onStatusChanged(changed(S.NEW, S.CONFIRMED_THREAT)),
    ).resolves.toBeUndefined();
  });
});

describe('ThreatFeedPushProcessor', () => {
  const row = (status: S) => ({
    id: 'sd',
    domain: 'apypal.com',
    fuzzer: 'transposition',
    status,
    threatLevel: 'HIGH_RISK',
    originalDomain: { domain: 'paypal.com' },
  });

  function setup(status: S | null, existing: Record<string, unknown> | null) {
    const client = {
      enabled: true,
      findIndicator: vi.fn(async () => existing),
      createIndicator: vi.fn(async () => ({})),
      updateIndicator: vi.fn(async () => ({})),
      sourceId: vi.fn(async () => 'src'),
    };
    const reputation = { invalidate: vi.fn(async () => undefined) };
    const query = {
      getForEnrichment: vi.fn(async () => (status ? row(status) : null)),
    };
    return {
      p: new ThreatFeedPushProcessor(
        client as never,
        reputation as never,
        query as never,
      ),
      client,
      reputation,
    };
  }
  const data = {
    scannedDomainId: 'sd',
    domain: 'apypal.com',
    action: 'upsert' as const,
    actor: 'ana',
  };

  it('creates the indicator for a confirmed threat and invalidates the reputation cache', async () => {
    const { p, client, reputation } = setup(S.CONFIRMED_THREAT, null);
    expect(await p.run(data)).toEqual({ outcome: 'created' });
    expect(client.createIndicator).toHaveBeenCalledWith(
      expect.objectContaining({
        value: 'apypal.com',
        type: 'DOMAIN',
        sourceId: 'src',
        severity: 'critical',
        isActive: true,
      }),
    );
    expect(reputation.invalidate).toHaveBeenCalledWith('DOMAIN', 'apypal.com');
  });

  it('reactivates an existing indicator, keeping tags added in manage-feed', async () => {
    const { p, client } = setup(S.CONFIRMED_THREAT, {
      id: 'f1',
      isActive: false,
      tags: ['campaign-x', 'typosquat'],
    });
    expect(await p.run(data)).toEqual({ outcome: 'updated' });
    const [id, changes] = client.updateIndicator.mock.calls[0] as unknown as [
      string,
      Record<string, unknown>,
    ];
    expect(id).toBe('f1');
    expect(changes).toMatchObject({ isActive: true, severity: 'critical' });
    expect(changes).not.toHaveProperty('sourceId');
    expect(changes.tags).toEqual([
      'campaign-x',
      'typosquat',
      'source:fuzzer-scanner',
      'fuzzer:transposition',
      'brand:paypal.com',
    ]);
  });

  it('converges on the current status: a stale upsert for a false positive deactivates', async () => {
    const { p, client } = setup(S.FALSE_POSITIVE, {
      id: 'f1',
      isActive: true,
      tags: [],
    });
    expect(await p.run(data)).toEqual({ outcome: 'deactivated' });
    expect(client.updateIndicator).toHaveBeenCalledWith('f1', {
      isActive: false,
    });
    expect(client.createIndicator).not.toHaveBeenCalled();
  });

  it('deactivates for deleted look-alikes and is a no-op when nothing is published', async () => {
    const gone = setup(null, { id: 'f1', isActive: true, tags: [] });
    expect(await gone.p.run({ ...data, action: 'deactivate' })).toEqual({
      outcome: 'deactivated',
    });
    const none = setup(S.ALLOWLISTED, null);
    expect(await none.p.run({ ...data, action: 'deactivate' })).toEqual({
      outcome: 'absent',
    });
  });

  it('fails permanently on permission errors but retries outages', async () => {
    const denied = setup(S.CONFIRMED_THREAT, null);
    denied.client.createIndicator.mockRejectedValue(
      new ThreatFeedError('HTTP 403', 403),
    );
    await expect(denied.p.run(data)).rejects.toBeInstanceOf(UnrecoverableError);

    const down = setup(S.CONFIRMED_THREAT, null);
    down.client.findIndicator.mockRejectedValue(
      new ThreatFeedError('HTTP 503', 503),
    );
    await expect(down.p.run(data)).rejects.not.toBeInstanceOf(
      UnrecoverableError,
    );
  });

  it('skips when the integration is disabled', async () => {
    const { p, client } = setup(S.CONFIRMED_THREAT, null);
    client.enabled = false;
    expect(await p.run(data)).toEqual({ outcome: 'skipped' });
  });
});
