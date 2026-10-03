import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TransactionalEventBus } from '../../common/events/transactional-event-bus.js';
import { type Paginated, paginated } from '../../common/dto/pagination.dto.js';
import type { AppConfig } from '../../config/configuration.js';
import type { Prisma } from '../../database/generated/prisma/client.js';
import {
  AlertDeliveryStatus,
  AlertMode,
  type AlertEventType,
} from '../../database/generated/prisma/enums.js';
import { PrismaService } from '../../database/prisma.service.js';
import { alertsTotal } from '../../metrics/metrics.js';
import { ScannedDomainsQuery } from '../scanned-domains/scanned-domains.query.js';
import { AlertChannelsService } from './alert-channels.service.js';
import type { AlertPayload } from './alert.types.js';
import type {
  AlertDeliveryDto,
  ListAlertDeliveriesQueryDto,
} from './dto/alert.dto.js';
import {
  AlertBeforeRaiseEvent,
  AlertQueuedEvent,
} from './events/alert.events.js';
import { AlertSender, PermanentDeliveryError } from './senders/alert-sender.js';

/** Max alerts in one digest message; larger backlogs go out as several messages. */
export const DIGEST_BATCH = 200;

@Injectable()
export class AlertsService {
  private readonly logger = new Logger(AlertsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly bus: TransactionalEventBus,
    private readonly scannedDomains: ScannedDomainsQuery,
    private readonly channels: AlertChannelsService,
    private readonly sender: AlertSender,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  /**
   * Matches an event against active subscriptions and records one delivery per match.
   * Idempotent per subscription + event + look-alike + UTC day (redelivered events, rescans).
   * Returns the number of NEW deliveries.
   */
  async raise(
    eventType: AlertEventType,
    scannedDomainId: string,
    details: string[] = [],
  ): Promise<number> {
    const d = await this.scannedDomains.getForEnrichment(scannedDomainId);
    if (!d) return 0;
    const subs = await this.prisma.alertSubscription.findMany({
      where: {
        isActive: true,
        eventTypes: { has: eventType },
        minRiskScore: { lte: d.riskScore },
        channel: { isActive: true },
        OR: [
          { originalDomainId: null },
          { originalDomainId: d.originalDomainId },
        ],
      },
      select: { id: true, channelId: true, mode: true },
    });
    if (!subs.length) return 0;

    const consoleUrl = this.config.get('alerts', { infer: true }).consoleUrl;
    const payload: AlertPayload = {
      eventType,
      scannedDomainId,
      domain: d.domain,
      unicodeDomain: d.unicodeDomain,
      brand: d.originalDomain.domain,
      originalDomainId: d.originalDomainId,
      fuzzer: d.fuzzer,
      riskScore: d.riskScore,
      threatLevel: d.threatLevel,
      status: d.status,
      details,
      consoleUrl: consoleUrl
        ? `${consoleUrl}/lookalikes/${scannedDomainId}`
        : null,
      occurredAt: new Date().toISOString(),
    };
    const day = payload.occurredAt.slice(0, 10);

    return this.bus.write({
      before: new AlertBeforeRaiseEvent(
        eventType,
        scannedDomainId,
        subs.length,
      ),
      work: async (tx, after) => {
        let created = 0;
        for (const s of subs) {
          const rows = await tx.$queryRaw<{ id: string }[]>`
            INSERT INTO alert_deliveries (subscription_id, channel_id, scanned_domain_id, event_type, mode, dedupe_key, payload)
            VALUES (${s.id}::uuid, ${s.channelId}::uuid, ${scannedDomainId}::uuid,
                    ${eventType}::"AlertEventType", ${s.mode}::"AlertMode",
                    ${`${s.id}:${eventType}:${scannedDomainId}:${day}`}, ${JSON.stringify(payload)}::jsonb)
            ON CONFLICT (dedupe_key) DO NOTHING
            RETURNING id`;
          if (!rows.length) continue;
          created++;
          if (s.mode === AlertMode.IMMEDIATE)
            after.add(new AlertQueuedEvent(rows[0].id, s.channelId, eventType));
        }
        return created;
      },
    });
  }

  /** Sends one immediate delivery. Throws for retryable failures; PermanentDeliveryError otherwise. */
  async deliver(
    deliveryId: string,
    finalAttempt: boolean,
  ): Promise<'sent' | 'skipped'> {
    const delivery = await this.prisma.alertDelivery.findUnique({
      where: { id: deliveryId },
    });
    if (!delivery || delivery.status !== AlertDeliveryStatus.PENDING)
      return 'skipped';
    const channel = await this.channels.resolve(delivery.channelId);
    if (!channel.isActive) return 'skipped';
    try {
      await this.sender.send(
        channel,
        [delivery.payload as unknown as AlertPayload],
        [delivery.id],
      );
    } catch (e) {
      const permanent = e instanceof PermanentDeliveryError;
      await this.prisma.alertDelivery.update({
        where: { id: deliveryId },
        data: {
          attempts: { increment: 1 },
          lastError: (e as Error).message.slice(0, 2_000),
          ...(permanent || finalAttempt
            ? { status: AlertDeliveryStatus.FAILED }
            : {}),
        },
      });
      alertsTotal.inc({
        event_type: delivery.eventType,
        channel_type: channel.type,
        result: permanent || finalAttempt ? 'failed' : 'retry',
      });
      throw e;
    }
    await this.prisma.alertDelivery.update({
      where: { id: deliveryId },
      data: {
        status: AlertDeliveryStatus.SENT,
        sentAt: new Date(),
        attempts: { increment: 1 },
        lastError: null,
      },
    });
    alertsTotal.inc({
      event_type: delivery.eventType,
      channel_type: channel.type,
      result: 'sent',
    });
    return 'sent';
  }

  /** Sends every pending DIGEST delivery, one message per channel (per DIGEST_BATCH alerts). */
  async sendDigests(): Promise<{
    channels: number;
    sent: number;
    failed: number;
  }> {
    const pending = await this.prisma.alertDelivery.groupBy({
      by: ['channelId'],
      where: { status: AlertDeliveryStatus.PENDING, mode: AlertMode.DIGEST },
    });
    const result = { channels: 0, sent: 0, failed: 0 };
    for (const { channelId } of pending) {
      const channel = await this.channels.resolve(channelId);
      if (!channel.isActive) continue;
      result.channels++;
      for (;;) {
        const batch = await this.prisma.alertDelivery.findMany({
          where: {
            channelId,
            status: AlertDeliveryStatus.PENDING,
            mode: AlertMode.DIGEST,
          },
          orderBy: { createdAt: 'asc' },
          take: DIGEST_BATCH,
        });
        if (!batch.length) break;
        const ids = batch.map((b) => b.id);
        try {
          await this.sender.send(
            channel,
            batch.map((b) => b.payload as unknown as AlertPayload),
            ids,
          );
          await this.prisma.alertDelivery.updateMany({
            where: { id: { in: ids } },
            data: {
              status: AlertDeliveryStatus.SENT,
              sentAt: new Date(),
              attempts: { increment: 1 },
              lastError: null,
            },
          });
          result.sent += ids.length;
          alertsTotal.inc(
            {
              event_type: 'DIGEST',
              channel_type: channel.type,
              result: 'sent',
            },
            ids.length,
          );
        } catch (e) {
          // Keep them PENDING (retried next digest) unless the channel itself is broken.
          const permanent = e instanceof PermanentDeliveryError;
          await this.prisma.alertDelivery.updateMany({
            where: { id: { in: ids } },
            data: {
              attempts: { increment: 1 },
              lastError: (e as Error).message.slice(0, 2_000),
              ...(permanent ? { status: AlertDeliveryStatus.FAILED } : {}),
            },
          });
          result.failed += ids.length;
          alertsTotal.inc(
            {
              event_type: 'DIGEST',
              channel_type: channel.type,
              result: 'failed',
            },
            ids.length,
          );
          this.logger.warn(
            `Digest to ${channel.name} failed: ${(e as Error).message}`,
          );
          break;
        }
        if (batch.length < DIGEST_BATCH) break;
      }
    }
    return result;
  }

  /** Synthetic alert to check a channel end to end (nothing is recorded). */
  async test(channelId: string): Promise<{ ok: boolean; error?: string }> {
    const channel = await this.channels.resolve(channelId);
    const sample: AlertPayload = {
      eventType: 'HIGH_RISK',
      scannedDomainId: '00000000-0000-0000-0000-000000000000',
      domain: 'examp1e-login.com',
      unicodeDomain: 'examp1e-login.com',
      brand: 'example.com',
      originalDomainId: '00000000-0000-0000-0000-000000000000',
      fuzzer: 'homoglyph',
      riskScore: 125,
      threatLevel: 'HIGH_RISK',
      status: 'ACTIVE',
      details: ['This is a test alert from Fuzzer Scanner'],
      consoleUrl: null,
      occurredAt: new Date().toISOString(),
    };
    try {
      await this.sender.send(channel, [sample], ['test']);
      return { ok: true };
    } catch (e) {
      return { ok: false, error: (e as Error).message };
    }
  }

  async deliveries(
    q: ListAlertDeliveriesQueryDto,
  ): Promise<Paginated<AlertDeliveryDto>> {
    const where: Prisma.AlertDeliveryWhereInput = {
      status: q.status?.length ? { in: q.status } : undefined,
      eventType: q.eventType?.length ? { in: q.eventType } : undefined,
      channelId: q.channelId,
    };
    const [rows, total] = await Promise.all([
      this.prisma.alertDelivery.findMany({
        where,
        orderBy: { createdAt: q.order },
        skip: q.skip,
        take: q.limit,
        include: { channel: { select: { name: true } } },
      }),
      this.prisma.alertDelivery.count({ where }),
    ]);
    return paginated(
      rows.map((r) => {
        const p = r.payload as unknown as AlertPayload;
        return {
          id: r.id,
          channelId: r.channelId,
          channelName: r.channel.name,
          eventType: r.eventType,
          mode: r.mode,
          scannedDomainId: r.scannedDomainId,
          domain: p.domain,
          brand: p.brand,
          riskScore: p.riskScore,
          status: r.status,
          attempts: r.attempts,
          lastError: r.lastError,
          createdAt: r.createdAt,
          sentAt: r.sentAt,
        };
      }),
      total,
      q,
    );
  }
}
