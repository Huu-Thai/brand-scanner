import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import {
  SCAN_EVENTS,
  type ScanFinishedEvent,
} from '../../scans/events/scan.events.js';
import { OriginalDomainsService } from '../original-domains.service.js';

/** Keeps `last_scanned_at` current — reacts to the scans module via events only. */
@Injectable()
export class ScanCompletedListener {
  private readonly logger = new Logger(ScanCompletedListener.name);

  constructor(private readonly service: OriginalDomainsService) {}

  @OnEvent(SCAN_EVENTS.COMPLETED, { async: true, promisify: true })
  async onScanCompleted(event: ScanFinishedEvent): Promise<void> {
    try {
      await this.service.markScanned(event.originalDomainId, event.occurredAt);
    } catch (e) {
      this.logger.error(
        `Could not record lastScannedAt for ${event.originalDomainId}: ${(e as Error).message}`,
      );
    }
  }
}
