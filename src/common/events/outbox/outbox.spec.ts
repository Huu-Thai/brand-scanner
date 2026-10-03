import { EventEmitter2 } from '@nestjs/event-emitter';
import { BaseEvent } from '../base.event.js';
import { backoffMs, OutboxDispatcher } from './outbox.dispatcher.js';
import { OutboxRelay, rehydrate } from './outbox.relay.js';

class Ping extends BaseEvent {
  readonly name = 'thing.pinged';
  constructor(readonly id: string) {
    super();
  }
}

function config(over: Record<string, unknown> = {}) {
  const values: Record<string, unknown> = {
    processRole: 'worker',
    outbox: {
      relayEnabled: true,
      relayIntervalMs: 1_000,
      graceMs: 30_000,
      maxAttempts: 3,
    },
    ...over,
  };
  return { get: (k: string) => values[k] } as never;
}

function setup(cfg = config()) {
  const events = new EventEmitter2();
  const prisma = {
    outboxEvent: {
      deleteMany: vi.fn(async () => ({ count: 0 })),
      update: vi.fn(async () => ({})),
    },
    $queryRaw: vi.fn(async (): Promise<unknown[]> => []),
  };
  const dispatcher = new OutboxDispatcher(prisma as never, events, cfg);
  return { events, prisma, dispatcher };
}

describe('OutboxDispatcher', () => {
  it('records events in the transaction with the process role and a grace period', async () => {
    const { dispatcher } = setup();
    const tx = {
      outboxEvent: { createMany: vi.fn(async () => ({ count: 1 })) },
    };
    const before = Date.now();
    const entries = await dispatcher.record(tx as never, [new Ping('a')]);
    expect(entries).toEqual([
      { id: expect.any(String), event: expect.any(Ping), attempts: 0 },
    ]);
    const { data } = (
      tx.outboxEvent.createMany.mock.calls[0] as unknown as [
        { data: Record<string, unknown>[] },
      ]
    )[0];
    expect(data[0]).toMatchObject({
      id: entries[0].id,
      eventName: 'thing.pinged',
      origin: 'worker',
      payload: {
        name: 'thing.pinged',
        id: 'a',
        occurredAt: expect.any(String),
      },
    });
    expect((data[0].availableAt as Date).getTime()).toBeGreaterThanOrEqual(
      before + 30_000,
    );
    expect(await dispatcher.record(tx as never, [])).toEqual([]);
    expect(tx.outboxEvent.createMany).toHaveBeenCalledTimes(1);
  });

  it('delivers in order, awaits listeners, then deletes delivered rows', async () => {
    const { dispatcher, events, prisma } = setup();
    const seen: string[] = [];
    events.on('thing.pinged', async (e: Ping) => {
      await new Promise((r) => setTimeout(r, 5));
      seen.push(e.id);
    });
    const result = await dispatcher.dispatch([
      { id: 'r1', event: new Ping('a'), attempts: 0 },
      { id: 'r2', event: new Ping('b'), attempts: 0 },
    ]);
    expect(result).toEqual({ delivered: 2, failed: 0 });
    expect(seen).toEqual(['a', 'b']);
    expect(prisma.outboxEvent.deleteMany).toHaveBeenCalledWith({
      where: { id: { in: ['r1', 'r2'] } },
    });
  });

  it('keeps a failed row with backoff, and parks it after the last attempt', async () => {
    const { dispatcher, events, prisma } = setup();
    events.on('thing.pinged', () => {
      throw new Error('listener down');
    });
    await dispatcher.dispatch([
      { id: 'r1', event: new Ping('a'), attempts: 1 },
    ]);
    expect(prisma.outboxEvent.deleteMany).not.toHaveBeenCalled();
    expect(prisma.outboxEvent.update).toHaveBeenLastCalledWith({
      where: { id: 'r1' },
      data: {
        attempts: 1,
        lastError: 'listener down',
        availableAt: expect.any(Date),
      },
    });
    await dispatcher.dispatch([
      { id: 'r1', event: new Ping('a'), attempts: 3 },
    ]);
    expect(prisma.outboxEvent.update).toHaveBeenLastCalledWith({
      where: { id: 'r1' },
      data: {
        attempts: 3,
        lastError: 'listener down',
        failedAt: expect.any(Date),
      },
    });
  });

  it('never loses an event when clearing delivered rows fails', async () => {
    const { dispatcher, prisma } = setup();
    prisma.outboxEvent.deleteMany.mockRejectedValueOnce(new Error('db blip'));
    await expect(
      dispatcher.dispatch([{ id: 'r1', event: new Ping('a'), attempts: 0 }]),
    ).resolves.toEqual({
      delivered: 1,
      failed: 0,
    });
  });

  it('waits for background deliveries on shutdown', async () => {
    const { dispatcher, events } = setup();
    let done = false;
    events.on('thing.pinged', async () => {
      await new Promise((r) => setTimeout(r, 20));
      done = true;
    });
    dispatcher.dispatchInBackground([
      { id: 'r1', event: new Ping('a'), attempts: 0 },
    ]);
    expect(done).toBe(false);
    await dispatcher.onApplicationShutdown();
    expect(done).toBe(true);
  });

  it('backs off exponentially up to an hour', () => {
    expect([1, 2, 3].map((a) => backoffMs(a, 30_000))).toEqual([
      30_000, 60_000, 120_000,
    ]);
    expect(backoffMs(50, 30_000)).toBe(3_600_000);
  });
});

describe('OutboxRelay', () => {
  it('rehydrates stored payloads', () => {
    const e = rehydrate('thing.pinged', {
      id: 'a',
      occurredAt: '2026-10-02T00:00:00.000Z',
    }) as unknown as Ping;
    expect(e.name).toBe('thing.pinged');
    expect(e.id).toBe('a');
    expect(e.occurredAt).toEqual(new Date('2026-10-02T00:00:00.000Z'));
  });

  it('claims due rows of its own role and redelivers them oldest first', async () => {
    const { dispatcher, prisma, events } = setup();
    const seen: string[] = [];
    events.on('thing.pinged', (e: Ping) => seen.push(e.id));
    prisma.$queryRaw.mockResolvedValueOnce([
      {
        id: 'r2',
        event_name: 'thing.pinged',
        payload: { id: 'b', occurredAt: '2026-10-02T00:00:02Z' },
        attempts: 1,
      },
      {
        id: 'r1',
        event_name: 'thing.pinged',
        payload: { id: 'a', occurredAt: '2026-10-02T00:00:01Z' },
        attempts: 1,
      },
    ]);
    const relay = new OutboxRelay(prisma as never, dispatcher, config());
    expect(await relay.tick()).toBe(2);
    expect(seen).toEqual(['a', 'b']);
    const sql = prisma.$queryRaw.mock.calls[0] as unknown as [
      TemplateStringsArray,
      ...unknown[],
    ];
    expect(sql[0].join('?')).toMatch(/FOR UPDATE SKIP LOCKED/);
    expect(sql.slice(1)).toContain('worker');
    expect(prisma.outboxEvent.deleteMany).toHaveBeenCalledWith({
      where: { id: { in: ['r1', 'r2'] } },
    });
    expect(await relay.tick()).toBe(0);
  });

  it('does not overlap passes and survives database errors', async () => {
    const { dispatcher, prisma } = setup();
    let release!: (v: unknown[]) => void;
    prisma.$queryRaw.mockImplementationOnce(
      () => new Promise((r) => (release = r)),
    );
    const relay = new OutboxRelay(prisma as never, dispatcher, config());
    const first = relay.tick();
    expect(relay.tick()).toBe(first);
    release([]);
    await first;
    prisma.$queryRaw.mockRejectedValueOnce(new Error('db down'));
    await expect(relay.tick()).resolves.toBe(0);
  });

  it('schedules itself only when enabled', async () => {
    vi.useFakeTimers();
    try {
      const { dispatcher, prisma } = setup();
      const off = new OutboxRelay(
        prisma as never,
        dispatcher,
        config({ outbox: { relayEnabled: false, relayIntervalMs: 1_000 } }),
      );
      off.onApplicationBootstrap();
      const on = new OutboxRelay(prisma as never, dispatcher, config());
      on.onApplicationBootstrap();
      await vi.advanceTimersByTimeAsync(2_500);
      expect(prisma.$queryRaw).toHaveBeenCalledTimes(2);
      await on.onModuleDestroy();
      await off.onModuleDestroy();
    } finally {
      vi.useRealTimers();
    }
  });
});
