import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import type { AnalyticsTrigger } from '../../../queue/jobs.js';
import {
  SCANNED_DOMAIN_EVENTS,
  type ScannedDomainDiscoveredEvent,
  type ScannedDomainUpdatedEvent,
} from '../../scanned-domains/events/scanned-domain.events.js';
import {
  WHOIS_EVENTS,
  type WhoisInformationCreatedEvent,
  type WhoisInformationFailedEvent,
} from '../../whois-informations/events/whois-information.events.js';
import {
  SCREENSHOT_EVENTS,
  type BrandReferenceCapturedEvent,
  type ScreenshotCapturedEvent,
} from '../../screenshots/events/screenshot.events.js';
import { ScreenshotsQuery } from '../../screenshots/screenshots.query.js';
import { AnalyticsEnqueuer } from '../analytics.enqueuer.js';

/**
 * When to (re)score a look-alike:
 *   discovered  → after WHOIS (domain age is a signal); immediately if WHOIS is disabled
 *   WHOIS saved / WHOIS gave up → score
 *   DNS changed → rescore now (a fresh WHOIS, if due, triggers another rescore later)
 */
@Injectable()
export class AnalyticsTriggerListener {
  private readonly logger = new Logger(AnalyticsTriggerListener.name);

  constructor(
    private readonly enqueuer: AnalyticsEnqueuer,
    private readonly screenshots: ScreenshotsQuery,
  ) {}

  @OnEvent(SCANNED_DOMAIN_EVENTS.DISCOVERED, { async: true, promisify: true })
  async onDiscovered(e: ScannedDomainDiscoveredEvent): Promise<void> {
    if (!e.enrichment.whois)
      await this.enqueue(e.scannedDomainId, 'discovered', e.scanId);
  }

  @OnEvent(SCANNED_DOMAIN_EVENTS.UPDATED, { async: true, promisify: true })
  async onDnsChanged(e: ScannedDomainUpdatedEvent): Promise<void> {
    await this.enqueue(e.scannedDomainId, 'dns-changed', e.scanId);
  }

  @OnEvent(WHOIS_EVENTS.CREATED, { async: true, promisify: true })
  async onWhois(e: WhoisInformationCreatedEvent): Promise<void> {
    await this.enqueue(e.scannedDomainId, 'whois', e.scanId);
  }

  @OnEvent(WHOIS_EVENTS.FAILED, { async: true, promisify: true })
  async onWhoisFailed(e: WhoisInformationFailedEvent): Promise<void> {
    await this.enqueue(e.scannedDomainId, 'whois-failed', e.scanId);
  }

  /** A fresh capture can change visual / content signals. */
  @OnEvent(SCREENSHOT_EVENTS.CAPTURED, { async: true, promisify: true })
  async onScreenshot(e: ScreenshotCapturedEvent): Promise<void> {
    await this.enqueue(e.scannedDomainId, 'screenshot');
  }

  /** The brand's reference page changed: rescore every look-alike that has a capture. */
  @OnEvent(SCREENSHOT_EVENTS.REFERENCE_CAPTURED, {
    async: true,
    promisify: true,
  })
  async onReference(e: BrandReferenceCapturedEvent): Promise<void> {
    if (e.status !== 'CAPTURED') return;
    for (const id of await this.screenshots.capturedLookalikes(
      e.originalDomainId,
    ))
      await this.enqueue(id, 'reference');
  }

  private async enqueue(
    scannedDomainId: string,
    trigger: AnalyticsTrigger,
    scanId?: string,
  ) {
    try {
      await this.enqueuer.enqueue(scannedDomainId, trigger, scanId);
    } catch (err) {
      this.logger.error(
        `Could not enqueue scoring for ${scannedDomainId}: ${(err as Error).message}`,
      );
    }
  }
}
