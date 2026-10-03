import { randomUUID } from 'node:crypto';
import { Injectable, Logger, type OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { AppConfig } from '../../../config/configuration.js';
import {
  PrismaService,
  type PrismaTransaction,
} from '../../../database/prisma.service.js';
import type { BaseEvent } from '../base.event.js';

export interface OutboxEntry {
  id: string;
  event: BaseEvent;
  /** Attempts already recorded on the row (0 for a fresh write). */
  attempts: number;
}

/** Exponential backoff for redelivery: 30 s, 1 min, 2 min … capped at 1 h. */
export function backoffMs(attempts: number, baseMs: number): number {
  return Math.min(baseMs * 2 ** Math.max(0, attempts - 1), 3_600_000);
}

/**
 * Transactional outbox (PLAN.md §1.2). `record` writes after-commit events in the producing
 * transaction; `dispatch` delivers them in-process once committed and deletes the rows. A row
 * left behind (process crash, delivery error) is redelivered by the OutboxRelay — so listeners
 * see each event at least once and must be idempotent.
 */
@Injectable()
export class OutboxDispatcher implements OnApplicationShutdown {
  private readonly logger = new Logger(OutboxDispatcher.name);
  private readonly inFlight = new Set<Promise<unknown>>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly events: EventEmitter2,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  private get settings() {
    return this.config.get('outbox', { infer: true });
  }

  /** Inside the transaction: persist the events next to the change that produced them. */
  async record(
    tx: PrismaTransaction,
    events: BaseEvent[],
  ): Promise<OutboxEntry[]> {
    if (!events.length) return [];
    const entries = events.map((event) => ({
      id: randomUUID(),
      event,
      attempts: 0,
    }));
    const availableAt = new Date(Date.now() + this.settings.graceMs);
    await tx.outboxEvent.createMany({
      data: entries.map(({ id, event }) => ({
        id,
        eventName: event.name,
        payload: JSON.parse(JSON.stringify(event)),
        origin: this.config.get('processRole', { infer: true }),
        availableAt,
      })),
    });
    return entries;
  }

  /** After commit: deliver without blocking the caller; shutdown waits for in-flight deliveries. */
  dispatchInBackground(entries: OutboxEntry[]): void {
    if (!entries.length) return;
    const p: Promise<unknown> = this.dispatch(entries)
      .catch((e: Error) =>
        this.logger.error(`Outbox dispatch failed: ${e.message}`),
      )
      .finally(() => this.inFlight.delete(p));
    this.inFlight.add(p);
  }

  /** Delivers in order; delivered rows are deleted, failed ones rescheduled (or parked). */
  async dispatch(
    entries: OutboxEntry[],
  ): Promise<{ delivered: number; failed: number }> {
    const delivered: string[] = [];
    let failed = 0;
    for (const entry of entries) {
      try {
        await this.events.emitAsync(entry.event.name, entry.event);
        delivered.push(entry.id);
      } catch (e) {
        failed++;
        await this.recordFailure(entry, e as Error);
      }
    }
    if (delivered.length) {
      await this.prisma.outboxEvent
        .deleteMany({ where: { id: { in: delivered } } })
        .catch((e: Error) =>
          // Rows stay and are redelivered later — at-least-once, never lost.
          this.logger.warn(
            `Could not clear ${delivered.length} delivered outbox rows: ${e.message}`,
          ),
        );
    }
    return { delivered: delivered.length, failed };
  }

  private async recordFailure(entry: OutboxEntry, error: Error): Promise<void> {
    const { maxAttempts, graceMs } = this.settings;
    const attempts = Math.max(entry.attempts, 1);
    const dead = attempts >= maxAttempts;
    this.logger.error(
      `Outbox delivery of ${entry.event.name} (${entry.id}) failed (attempt ${attempts}/${maxAttempts})${dead ? ' — parked as dead letter' : ''}: ${error.message}`,
    );
    await this.prisma.outboxEvent
      .update({
        where: { id: entry.id },
        data: {
          attempts,
          lastError: error.message.slice(0, 2_000),
          ...(dead
            ? { failedAt: new Date() }
            : {
                availableAt: new Date(
                  Date.now() + backoffMs(attempts, graceMs),
                ),
              }),
        },
      })
      .catch(() => undefined);
  }

  async onApplicationShutdown(): Promise<void> {
    await Promise.allSettled(this.inFlight);
  }
}
