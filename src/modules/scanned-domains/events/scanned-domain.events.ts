import { BaseEvent } from '../../../common/events/base.event.js';
import type {
  DomainStatus,
  ThreatLevel,
} from '../../../database/generated/prisma/enums.js';
import type { StatusChangeSource } from '../status-rules.js';
import type { EnrichmentFlags } from '../../scans/events/scan.events.js';

export const SCANNED_DOMAIN_EVENTS = {
  BEFORE_UPSERT: 'scanned-domain.before-upsert',
  DISCOVERED: 'scanned-domain.discovered',
  UPDATED: 'scanned-domain.updated',
  BATCH_UPSERTED: 'scanned-domain.batch-upserted',
  BEFORE_STATUS_CHANGE: 'scanned-domain.before-status-change',
  STATUS_CHANGED: 'scanned-domain.status-changed',
  BEFORE_TAGS_UPDATE: 'scanned-domain.before-tags-update',
  TAGS_UPDATED: 'scanned-domain.tags-updated',
  BEFORE_DELETE: 'scanned-domain.before-delete',
  DELETED: 'scanned-domain.deleted',
  BEFORE_RISK_UPDATE: 'scanned-domain.before-risk-update',
  RISK_UPDATED: 'scanned-domain.risk-updated',
  BEFORE_MARK_INACTIVE: 'scanned-domain.before-mark-inactive',
  MARKED_INACTIVE: 'scanned-domain.marked-inactive',
} as const;

export class ScannedDomainBeforeUpsertEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.BEFORE_UPSERT;
  constructor(
    readonly originalDomainId: string,
    /** undefined for discoveries outside a scan (rescan of a purged scan, CT monitoring). */
    readonly scanId: string | undefined,
    readonly domains: string[],
  ) {
    super();
  }
}

/** First time this look-alike was seen registered. Phase 2 enqueues WHOIS + screenshot on this. */
export class ScannedDomainDiscoveredEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.DISCOVERED;
  constructor(
    readonly scannedDomainId: string,
    readonly originalDomainId: string,
    /** undefined for discoveries outside a scan (rescan of a purged scan, CT monitoring). */
    readonly scanId: string | undefined,
    readonly domain: string,
    readonly resolvesToIp: boolean,
    readonly enrichment: EnrichmentFlags,
  ) {
    super();
  }
}

/**
 * Seen again with different DNS records — or seen again but never enriched yet
 * (`firstEnrichment`, e.g. look-alikes discovered before enrichment existed).
 */
export class ScannedDomainUpdatedEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.UPDATED;
  constructor(
    readonly scannedDomainId: string,
    readonly originalDomainId: string,
    /** undefined for discoveries outside a scan (rescan of a purged scan, CT monitoring). */
    readonly scanId: string | undefined,
    readonly domain: string,
    readonly changedFields: string[],
    readonly resolvesToIp: boolean,
    readonly enrichment: EnrichmentFlags,
    readonly firstEnrichment = false,
    /** Manual rescan: refresh WHOIS and screenshot regardless of freshness. */
    readonly force = false,
  ) {
    super();
  }
}

export class ScannedDomainBatchUpsertedEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.BATCH_UPSERTED;
  constructor(
    readonly scanId: string,
    readonly inserted: number,
    readonly updated: number,
  ) {
    super();
  }
}

export class ScannedDomainBeforeMarkInactiveEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.BEFORE_MARK_INACTIVE;
  constructor(
    readonly originalDomainId: string,
    readonly scanId: string,
  ) {
    super();
  }
}

export class ScannedDomainMarkedInactiveEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.MARKED_INACTIVE;
  constructor(
    readonly originalDomainId: string,
    readonly scanId: string,
    readonly scannedDomainIds: string[],
  ) {
    super();
  }
}

export class ScannedDomainBeforeRiskUpdateEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.BEFORE_RISK_UPDATE;
  constructor(
    readonly scannedDomainId: string,
    readonly riskScore: number,
    readonly threatLevel: ThreatLevel,
  ) {
    super();
  }
}

export class ScannedDomainRiskUpdatedEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.RISK_UPDATED;
  constructor(
    readonly scannedDomainId: string,
    readonly riskScore: number,
    readonly threatLevel: ThreatLevel,
    readonly previousThreatLevel: ThreatLevel,
  ) {
    super();
  }
}

/** Vetoable: the status-rules listener throws (422) for transitions that aren't allowed. */
export class ScannedDomainBeforeStatusChangeEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.BEFORE_STATUS_CHANGE;
  constructor(
    readonly scannedDomainIds: string[],
    readonly to: DomainStatus,
    readonly source: StatusChangeSource,
    readonly actor: string,
  ) {
    super();
  }
}

export class ScannedDomainStatusChangedEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.STATUS_CHANGED;
  constructor(
    readonly scannedDomainId: string,
    readonly originalDomainId: string,
    readonly domain: string,
    readonly from: DomainStatus,
    readonly to: DomainStatus,
    readonly source: StatusChangeSource,
    readonly actor: string,
  ) {
    super();
  }
}

export class ScannedDomainBeforeTagsUpdateEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.BEFORE_TAGS_UPDATE;
  constructor(
    readonly scannedDomainIds: string[],
    readonly add: string[],
    readonly remove: string[],
  ) {
    super();
  }
}

export class ScannedDomainTagsUpdatedEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.TAGS_UPDATED;
  constructor(
    readonly scannedDomainIds: string[],
    readonly actor: string,
  ) {
    super();
  }
}

export class ScannedDomainBeforeDeleteEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.BEFORE_DELETE;
  constructor(readonly scannedDomainId: string) {
    super();
  }
}

export class ScannedDomainDeletedEvent extends BaseEvent {
  readonly name = SCANNED_DOMAIN_EVENTS.DELETED;
  constructor(
    readonly scannedDomainId: string,
    readonly domain: string,
    readonly actor: string,
  ) {
    super();
  }
}
