import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import {
  AlertEventType,
  DomainStatus,
} from '../../../database/generated/prisma/enums.js';
import {
  ANALYTICS_EVENTS,
  type HighRiskAlertEvent,
} from '../../analytics/events/analytics.events.js';
import {
  SCANNED_DOMAIN_EVENTS,
  type ScannedDomainDiscoveredEvent,
  type ScannedDomainStatusChangedEvent,
} from '../../scanned-domains/events/scanned-domain.events.js';
import { AlertsEnqueuer } from '../alerts.enqueuer.js';
import { AlertsService } from '../alerts.service.js';
import { ALERT_EVENTS, type AlertQueuedEvent } from '../events/alert.events.js';

/** Turns domain events into alerts (one decorator per event — see PLAN §4). */
@Injectable()
export class AlertTriggerListener {
  private readonly logger = new Logger(AlertTriggerListener.name);

  constructor(
    private readonly alerts: AlertsService,
    private readonly enqueuer: AlertsEnqueuer,
  ) {}

  @OnEvent(ANALYTICS_EVENTS.ALERT_HIGH_RISK, { async: true, promisify: true })
  onHighRisk(e: HighRiskAlertEvent): Promise<void> {
    return this.raise(
      AlertEventType.HIGH_RISK,
      e.scannedDomainId,
      e.matchedRules.map((r) => `Matched rule: ${r}`),
    );
  }

  @OnEvent(SCANNED_DOMAIN_EVENTS.DISCOVERED, { async: true, promisify: true })
  onDiscovered(e: ScannedDomainDiscoveredEvent): Promise<void> {
    return this.raise(
      AlertEventType.NEW_LOOKALIKE,
      e.scannedDomainId,
      e.resolvesToIp ? ['Resolves to an IP address'] : [],
    );
  }

  @OnEvent(SCANNED_DOMAIN_EVENTS.STATUS_CHANGED, {
    async: true,
    promisify: true,
  })
  async onStatusChanged(e: ScannedDomainStatusChangedEvent): Promise<void> {
    if (e.to === DomainStatus.CONFIRMED_THREAT)
      return this.raise(AlertEventType.CONFIRMED_THREAT, e.scannedDomainId, [
        `Confirmed by ${e.actor}`,
      ]);
    if (
      e.to === DomainStatus.ACTIVE &&
      (e.from === DomainStatus.INACTIVE || e.from === DomainStatus.PARKED)
    )
      return this.raise(AlertEventType.WENT_LIVE, e.scannedDomainId, [
        `Was ${e.from.toLowerCase()}, resolves again`,
      ]);
  }

  /** Committed immediate delivery → job. Delivered via the outbox, so a crash can't lose it. */
  @OnEvent(ALERT_EVENTS.QUEUED, {
    async: true,
    promisify: true,
    suppressErrors: false,
  })
  onQueued(e: AlertQueuedEvent): Promise<void> {
    return this.enqueuer.enqueue(e.deliveryId);
  }

  private async raise(
    type: AlertEventType,
    scannedDomainId: string,
    details: string[],
  ): Promise<void> {
    try {
      await this.alerts.raise(type, scannedDomainId, details);
    } catch (e) {
      this.logger.error(
        `Could not raise ${type} alert for ${scannedDomainId}: ${(e as Error).message}`,
      );
    }
  }
}
