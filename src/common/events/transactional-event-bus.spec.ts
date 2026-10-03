import { EventEmitter2 } from '@nestjs/event-emitter';
import type { PrismaService } from '../../database/prisma.service.js';
import { BaseEvent } from './base.event.js';
import type {
  OutboxDispatcher,
  OutboxEntry,
} from './outbox/outbox.dispatcher.js';
import { TransactionalEventBus } from './transactional-event-bus.js';

class TestEvent extends BaseEvent {
  constructor(
    readonly name: string,
    readonly id = 'x',
  ) {
    super();
  }
}

function setup(commit: 'ok' | 'fail' = 'ok') {
  const order: string[] = [];
  const events = new EventEmitter2();
  const tx = { marker: 'tx' };
  const prisma = {
    $transaction: vi.fn(async (work: (t: unknown) => Promise<unknown>) => {
      order.push('tx:start');
      const result = await work(tx);
      if (commit === 'fail') throw new Error('rollback');
      order.push('tx:commit');
      return result;
    }),
  } as unknown as PrismaService;
  events.on('thing.before-create', () => order.push('before'));
  events.on('thing.created', () => order.push('after'));
  const outbox = {
    record: vi.fn(async (t: unknown, list: BaseEvent[]) => {
      expect(t).toBe(tx); // written inside the transaction
      order.push(`outbox:${list.length}`);
      return list.map((event, i) => ({ id: `o${i}`, event, attempts: 0 }));
    }),
    dispatchInBackground: vi.fn((entries: OutboxEntry[]) =>
      entries.forEach((e) => events.emit(e.event.name, e.event)),
    ),
  };
  return {
    outbox,
    bus: new TransactionalEventBus(
      prisma,
      events,
      outbox as unknown as OutboxDispatcher,
    ),
    events,
    order,
    prisma,
    tx,
  };
}

describe('TransactionalEventBus', () => {
  it('emits before → transaction → after, in that order', async () => {
    const { bus, order, tx } = setup();
    const result = await bus.write({
      before: new TestEvent('thing.before-create'),
      work: async (t, after) => {
        expect(t).toBe(tx);
        order.push('work');
        after.add(new TestEvent('thing.created'));
        return 42;
      },
    });
    expect(result).toBe(42);
    expect(order).toEqual([
      'before',
      'tx:start',
      'work',
      'outbox:1',
      'tx:commit',
      'after',
    ]);
  });

  it('never emits after events when the transaction rolls back', async () => {
    const { bus, order, outbox } = setup('fail');
    await expect(
      bus.write({
        before: new TestEvent('thing.before-create'),
        work: async (_t, after) => {
          after.add(new TestEvent('thing.created'));
        },
      }),
    ).rejects.toThrow('rollback');
    expect(order).not.toContain('after');
    expect(outbox.dispatchInBackground).not.toHaveBeenCalled();
  });

  it('lets a before-listener veto the write (no transaction is started)', async () => {
    const { bus, events, prisma } = setup();
    events.on('thing.before-create', () => {
      throw new Error('vetoed');
    });
    await expect(
      bus.write({
        before: new TestEvent('thing.before-create'),
        work: async () => undefined,
      }),
    ).rejects.toThrow('vetoed');
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('passes isolation level and timeout to Prisma', async () => {
    const { bus, prisma } = setup();
    await bus.write({
      before: new TestEvent('thing.before-create'),
      work: async () => undefined,
      isolationLevel: 'Serializable',
      timeoutMs: 5_000,
    });
    expect(prisma.$transaction).toHaveBeenCalledWith(expect.any(Function), {
      isolationLevel: 'Serializable',
      timeout: 5_000,
    });
  });
});
