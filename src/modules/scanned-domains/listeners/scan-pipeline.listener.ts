import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import {
  ANALYTICS_EVENTS,
  type AnalyticsComputedEvent,
} from '../../analytics/events/analytics.events.js';
import {
  REVIEW_EVENTS,
  type ReviewCreatedEvent,
} from '../../reviews/events/review.events.js';
import {
  SCAN_EVENTS,
  type ScanBatchResolvedEvent,
  type ScanFinishedEvent,
} from '../../scans/events/scan.events.js';
import {
  type UpsertBatchResult,
  ScannedDomainsService,
} from '../scanned-domains.service.js';

/** Connects the scan pipeline to scanned_domains — via events only. */
@Injectable()
export class ScanPipelineListener {
  private readonly logger = new Logger(ScanPipelineListener.name);

  constructor(private readonly service: ScannedDomainsService) {}

  /**
   * Awaited by the DNS processor (emitAsync). Errors are NOT suppressed so a failed write
   * fails the job, which BullMQ retries — the upsert is idempotent.
   */
  @OnEvent(SCAN_EVENTS.BATCH_RESOLVED, {
    async: true,
    promisify: true,
    suppressErrors: false,
  })
  onBatchResolved(event: ScanBatchResolvedEvent): Promise<UpsertBatchResult> {
    return this.service.upsertBatch({
      scanId: event.scanId,
      originalDomainId: event.originalDomainId,
      fuzzerByDomain: event.fuzzerByDomain,
      resolutions: event.resolutions,
      enrichment: event.enrichment,
    });
  }

  /** Only a full scan can conclude that an unseen look-alike is no longer registered. */
  @OnEvent(SCAN_EVENTS.COMPLETED, { async: true, promisify: true })
  async onScanCompleted(event: ScanFinishedEvent): Promise<void> {
    if (!event.fullScan) return;
    try {
      const ids = await this.service.markUnseenInactive(
        event.originalDomainId,
        event.scanId,
      );
      if (ids.length)
        this.logger.log(
          `Marked ${ids.length} look-alikes inactive after scan ${event.scanId}`,
        );
    } catch (e) {
      this.logger.error(
        `Could not mark unseen domains inactive for scan ${event.scanId}: ${(e as Error).message}`,
      );
    }
  }

  /** Keep the look-alike's current risk in step with its newest score. */
  @OnEvent(ANALYTICS_EVENTS.COMPUTED, { async: true, promisify: true })
  async onScored(event: AnalyticsComputedEvent): Promise<void> {
    try {
      await this.service.updateRisk(
        event.scannedDomainId,
        event.totalScore,
        event.threatLevel,
      );
    } catch (e) {
      this.logger.error(
        `Could not update risk for ${event.scannedDomainId}: ${(e as Error).message}`,
      );
    }
  }

  /** A review's verdict decides the look-alike's status (reviews are authoritative). */
  @OnEvent(REVIEW_EVENTS.CREATED, { async: true, promisify: true })
  async onReviewed(event: ReviewCreatedEvent): Promise<void> {
    try {
      await this.service.changeStatus(
        [event.scannedDomainId],
        event.newStatus,
        { source: 'review', actor: event.reviewer },
      );
    } catch (e) {
      this.logger.error(
        `Could not apply review ${event.reviewId} to ${event.scannedDomainId}: ${(e as Error).message}`,
      );
    }
  }
}
