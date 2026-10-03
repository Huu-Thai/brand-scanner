import { BaseEvent } from '../../../common/events/base.event.js';

export const RETENTION_EVENTS = {
  BEFORE_PURGE: 'retention.before-purge',
  PURGED: 'retention.purged',
} as const;

export type RetentionTable =
  | 'screenshots'
  | 'analytics'
  | 'whois_informations'
  | 'scans'
  | 'scanned_domains'
  | 'original_domains'
  | 'outbox_events'
  | 'alert_deliveries';

/** Before each batch (one short transaction). A listener may throw to stop the run. */
export class RetentionBeforePurgeEvent extends BaseEvent {
  readonly name = RETENTION_EVENTS.BEFORE_PURGE;
  constructor(
    readonly table: RetentionTable,
    readonly cutoff: string,
    readonly batchSize: number,
  ) {
    super();
  }
}

/** After each committed batch that removed rows. */
export class RetentionPurgedEvent extends BaseEvent {
  readonly name = RETENTION_EVENTS.PURGED;
  constructor(
    readonly table: RetentionTable,
    readonly rows: number,
    readonly objects = 0,
  ) {
    super();
  }
}
