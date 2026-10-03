import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import {
  SCANNED_DOMAIN_EVENTS,
  type ScannedDomainDiscoveredEvent,
  type ScannedDomainUpdatedEvent,
} from '../../scanned-domains/events/scanned-domain.events.js';
import { ScreenshotEnqueuer } from '../screenshot.enqueuer.js';

/** Capture new look-alikes that resolve to an IP, and ones whose web-facing records changed. */
@Injectable()
export class ScreenshotTriggerListener {
  private readonly logger = new Logger(ScreenshotTriggerListener.name);

  constructor(private readonly enqueuer: ScreenshotEnqueuer) {}

  @OnEvent(SCANNED_DOMAIN_EVENTS.DISCOVERED, { async: true, promisify: true })
  async onDiscovered(e: ScannedDomainDiscoveredEvent): Promise<void> {
    if (e.enrichment.screenshots && e.resolvesToIp)
      await this.enqueue(e.scannedDomainId, e.domain, e.scanId);
  }

  @OnEvent(SCANNED_DOMAIN_EVENTS.UPDATED, { async: true, promisify: true })
  async onUpdated(e: ScannedDomainUpdatedEvent): Promise<void> {
    const webChanged =
      e.firstEnrichment ||
      e.changedFields.includes('dnsA') ||
      e.changedFields.includes('dnsAaaa');
    if (e.enrichment.screenshots && e.resolvesToIp && webChanged)
      await this.enqueue(e.scannedDomainId, e.domain, e.scanId);
  }

  private async enqueue(
    scannedDomainId: string,
    domain: string,
    scanId: string | undefined,
  ) {
    try {
      await this.enqueuer.enqueue({ scannedDomainId, domain, scanId });
    } catch (err) {
      this.logger.error(
        `Could not enqueue screenshot for ${domain}: ${(err as Error).message}`,
      );
    }
  }
}
