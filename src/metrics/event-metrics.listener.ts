import { Injectable } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import {
  RETENTION_EVENTS,
  type RetentionPurgedEvent,
} from '../modules/retention/events/retention.events.js';
import { SCREENSHOT_EVENTS } from '../modules/screenshots/events/screenshot.events.js';
import { WHOIS_EVENTS } from '../modules/whois-informations/events/whois-information.events.js';
import {
  retentionObjectsTotal,
  retentionPurgedTotal,
  screenshotsTotal,
  whoisTotal,
} from './metrics.js';

/** Domain counters derived from after-commit events (one decorator per event — see PLAN §4). */
@Injectable()
export class EventMetricsListener {
  @OnEvent(SCREENSHOT_EVENTS.CAPTURED)
  captured(): void {
    screenshotsTotal.inc({ result: 'captured' });
  }

  @OnEvent(SCREENSHOT_EVENTS.FAILED)
  captureFailed(): void {
    screenshotsTotal.inc({ result: 'failed' });
  }

  @OnEvent(WHOIS_EVENTS.CREATED)
  whoisCreated(): void {
    whoisTotal.inc({ result: 'created' });
  }

  @OnEvent(WHOIS_EVENTS.FAILED)
  whoisFailed(): void {
    whoisTotal.inc({ result: 'failed' });
  }

  @OnEvent(RETENTION_EVENTS.PURGED)
  purged(e: RetentionPurgedEvent): void {
    retentionPurgedTotal.inc({ table: e.table }, e.rows);
    if (e.objects) retentionObjectsTotal.inc(e.objects);
  }
}
