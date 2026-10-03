import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OnEvent } from '@nestjs/event-emitter';
import type { AppConfig } from '../../../config/configuration.js';
import {
  SCANNED_DOMAIN_EVENTS,
  type ScannedDomainStatusChangedEvent,
} from '../../scanned-domains/events/scanned-domain.events.js';
import {
  REVIEW_EVENTS,
  type ReviewCreatedEvent,
} from '../../reviews/events/review.events.js';
import {
  pushActionFor,
  PUBLISHED_STATUSES,
  type PushAction,
} from '../indicator.mapper.js';
import { ThreatFeedPushEnqueuer } from '../threat-feed-push.enqueuer.js';

/** Publishes analyst decisions to manage-feed (threat-feed) — asynchronously, with retries. */
@Injectable()
export class StatusSyncListener {
  private readonly logger = new Logger(StatusSyncListener.name);

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly enqueuer: ThreatFeedPushEnqueuer,
  ) {}

  @OnEvent(SCANNED_DOMAIN_EVENTS.STATUS_CHANGED, {
    async: true,
    promisify: true,
  })
  async onStatusChanged(event: ScannedDomainStatusChangedEvent): Promise<void> {
    const action = pushActionFor(event.from, event.to);
    if (action)
      await this.push(event.scannedDomainId, event.domain, action, event.actor);
  }

  /**
   * Re-confirming an already-confirmed look-alike changes no status, but must still (re)publish —
   * e.g. after the indicator was deactivated in manage-feed or an earlier push failed.
   */
  @OnEvent(REVIEW_EVENTS.CREATED, { async: true, promisify: true })
  async onReviewed(event: ReviewCreatedEvent): Promise<void> {
    if (
      event.previousStatus === event.newStatus &&
      PUBLISHED_STATUSES.includes(event.newStatus)
    )
      await this.push(event.scannedDomainId, '', 'upsert', event.reviewer);
  }

  private async push(
    scannedDomainId: string,
    domain: string,
    action: PushAction,
    actor: string,
  ): Promise<void> {
    if (!this.config.get('threatFeed.pushEnabled', { infer: true })) return;
    try {
      await this.enqueuer.enqueue({ scannedDomainId, domain, action, actor });
    } catch (e) {
      this.logger.error(
        `Could not queue threat-feed ${action} for ${domain || scannedDomainId}: ${(e as Error).message}`,
      );
    }
  }
}
