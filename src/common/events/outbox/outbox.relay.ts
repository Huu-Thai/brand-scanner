import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../../config/configuration.js';
import { PrismaService } from '../../../database/prisma.service.js';
import type { BaseEvent } from '../base.event.js';
import { backoffMs, OutboxDispatcher } from './outbox.dispatcher.js';

interface ClaimedRow {
  id: string;
  event_name: string;
  payload: Record<string, unknown>;
  attempts: number;
}

/** Rebuilds an event from its stored JSON (payloads are plain data; `occurredAt` back to a Date). */
export function rehydrate(
  name: string,
  payload: Record<string, unknown>,
): BaseEvent {
  return {
    ...payload,
    name,
    occurredAt: new Date(String(payload.occurredAt ?? Date.now())),
  } as unknown as BaseEvent;
}

/**
 * Redelivers outbox rows whose producer did not clear them in time (crash, delivery failure).
 * Runs in every process; `FOR UPDATE SKIP LOCKED` + a lease on `available_at` let replicas
 * share the work without double-claiming. Only rows of this process's role are taken, because
 * only that role has every listener the event needs.
 */
@Injectable()
export class OutboxRelay implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(OutboxRelay.name);
  private timer?: NodeJS.Timeout;
  private running?: Promise<number>;
  static readonly BATCH = 100;

  constructor(
    private readonly prisma: PrismaService,
    private readonly dispatcher: OutboxDispatcher,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  onApplicationBootstrap(): void {
    const { relayEnabled, relayIntervalMs } = this.config.get('outbox', {
      infer: true,
    });
    if (!relayEnabled) return;
    this.timer = setInterval(() => void this.tick(), relayIntervalMs);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    clearInterval(this.timer);
    await this.running;
  }

  /** One relay pass; returns how many rows it claimed. Overlapping passes are skipped. */
  tick(): Promise<number> {
    this.running ??= this.relayOnce()
      .catch((e: Error) => {
        this.logger.error(`Outbox relay pass failed: ${e.message}`);
        return 0;
      })
      .finally(() => (this.running = undefined));
    return this.running;
  }

  private async relayOnce(): Promise<number> {
    const { graceMs } = this.config.get('outbox', { infer: true });
    const origin = this.config.get('processRole', { infer: true });
    // The lease covers the redelivery itself; a crash mid-redelivery makes the row due again.
    const leaseSeconds = graceMs / 1000;
    const rows = await this.prisma.$queryRaw<ClaimedRow[]>`
      UPDATE outbox_events
         SET attempts = attempts + 1,
             available_at = now() + make_interval(secs => ${leaseSeconds}::double precision)
       WHERE id IN (
         SELECT id FROM outbox_events
          WHERE origin = ${origin} AND failed_at IS NULL AND available_at <= now()
          ORDER BY available_at
          LIMIT ${OutboxRelay.BATCH}
          FOR UPDATE SKIP LOCKED)
      RETURNING id, event_name, payload, attempts`;
    if (!rows.length) return 0;
    rows.sort((a, b) =>
      String(a.payload.occurredAt).localeCompare(String(b.payload.occurredAt)),
    );
    const { delivered, failed } = await this.dispatcher.dispatch(
      rows.map((r) => ({
        id: r.id,
        event: rehydrate(r.event_name, r.payload),
        attempts: r.attempts,
      })),
    );
    this.logger.warn(
      `Outbox relay redelivered ${delivered} event(s)${failed ? `, ${failed} failed (next try in ≥ ${Math.round(backoffMs(1, graceMs) / 1000)}s)` : ''}`,
    );
    return rows.length;
  }
}
