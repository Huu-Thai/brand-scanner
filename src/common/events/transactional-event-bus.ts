import { Injectable } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { Prisma } from '../../database/generated/prisma/client.js';
import {
  PrismaService,
  type PrismaTransaction,
} from '../../database/prisma.service.js';
import { AfterEvents, type BaseEvent } from './base.event.js';
import {
  OutboxDispatcher,
  type OutboxEntry,
} from './outbox/outbox.dispatcher.js';

export interface TransactionalWrite<T> {
  /** Emitted (awaited) before the transaction. Listeners may throw to veto; they must not write. */
  before: BaseEvent;
  /** The transactional work. Register after-commit events on `after`. */
  work: (tx: PrismaTransaction, after: AfterEvents) => Promise<T>;
  isolationLevel?: Prisma.TransactionIsolationLevel;
  timeoutMs?: number;
}

/**
 * The single write path for every module (PLAN.md §4):
 *   1. before event (sync, may veto)
 *   2. Prisma $transaction
 *   3. after events — written to the outbox inside the transaction, delivered once it has
 *      committed (never on rollback), and redelivered by the relay if this process dies first.
 *
 * NOTE: `@OnEvent` listeners have errors suppressed by default. A before-listener that
 * vetoes (or any listener whose failure must fail the caller) needs
 * `@OnEvent(name, { suppressErrors: false })`.
 */
@Injectable()
export class TransactionalEventBus {
  constructor(
    private readonly prisma: PrismaService,
    private readonly events: EventEmitter2,
    private readonly outbox: OutboxDispatcher,
  ) {}

  async write<T>(spec: TransactionalWrite<T>): Promise<T> {
    await this.events.emitAsync(spec.before.name, spec.before);

    const after = new AfterEvents();
    let pending: OutboxEntry[] = [];
    const result = await this.prisma.$transaction(
      async (tx) => {
        const value = await spec.work(tx, after);
        pending = await this.outbox.record(tx, after.drain());
        return value;
      },
      {
        isolationLevel: spec.isolationLevel ?? 'ReadCommitted',
        timeout: spec.timeoutMs ?? 15_000,
      },
    );

    this.outbox.dispatchInBackground(pending);
    return result;
  }
}
