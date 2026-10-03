import { vi } from 'vitest';
import { AfterEvents, type BaseEvent } from '../common/events/base.event.js';
import type {
  TransactionalEventBus,
  TransactionalWrite,
} from '../common/events/transactional-event-bus.js';

/**
 * Test double for TransactionalEventBus: runs `work` against the given fake transaction
 * client and records before/after events, mirroring the real ordering (after events only
 * when `work` resolves).
 */
export function fakeBus(tx: unknown) {
  const before: BaseEvent[] = [];
  const after: BaseEvent[] = [];
  const bus = {
    write: vi.fn(async <T>(spec: TransactionalWrite<T>) => {
      before.push(spec.before);
      const pending = new AfterEvents();
      const result = await spec.work(tx as never, pending);
      after.push(...pending.drain());
      return result;
    }),
  } as unknown as TransactionalEventBus;
  const names = (list: BaseEvent[]) => list.map((e) => e.name);
  return {
    bus,
    before,
    after,
    beforeNames: () => names(before),
    afterNames: () => names(after),
  };
}
