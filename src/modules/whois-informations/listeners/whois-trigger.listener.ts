import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OnEvent } from '@nestjs/event-emitter';
import type { AppConfig } from '../../../config/configuration.js';
import {
  SCANNED_DOMAIN_EVENTS,
  type ScannedDomainDiscoveredEvent,
  type ScannedDomainUpdatedEvent,
} from '../../scanned-domains/events/scanned-domain.events.js';
import { WhoisEnqueuer } from '../whois.enqueuer.js';
import { WhoisInformationsQuery } from '../whois-informations.query.js';

/** New look-alikes always get WHOIS; changed ones only when the last snapshot is stale. */
@Injectable()
export class WhoisTriggerListener {
  private readonly logger = new Logger(WhoisTriggerListener.name);

  constructor(
    private readonly enqueuer: WhoisEnqueuer,
    private readonly query: WhoisInformationsQuery,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  @OnEvent(SCANNED_DOMAIN_EVENTS.DISCOVERED, { async: true, promisify: true })
  async onDiscovered(event: ScannedDomainDiscoveredEvent): Promise<void> {
    if (!event.enrichment.whois) return;
    await this.enqueue(event.scannedDomainId, event.domain, event.scanId);
  }

  @OnEvent(SCANNED_DOMAIN_EVENTS.UPDATED, { async: true, promisify: true })
  async onUpdated(event: ScannedDomainUpdatedEvent): Promise<void> {
    if (!event.enrichment.whois) return;
    if (event.force) {
      await this.enqueue(
        event.scannedDomainId,
        event.domain,
        event.scanId,
        true,
      );
      return;
    }
    const days = this.config.get('enrichment', {
      infer: true,
    }).whoisRefreshDays;
    if (await this.query.isStale(event.scannedDomainId, days)) {
      await this.enqueue(event.scannedDomainId, event.domain, event.scanId);
    }
  }

  private async enqueue(
    scannedDomainId: string,
    domain: string,
    scanId: string | undefined,
    force = false,
  ) {
    try {
      await this.enqueuer.enqueue({
        scannedDomainId,
        domain,
        scanId,
        ...(force ? { force } : {}),
      });
    } catch (e) {
      this.logger.error(
        `Could not enqueue WHOIS for ${domain}: ${(e as Error).message}`,
      );
    }
  }
}
