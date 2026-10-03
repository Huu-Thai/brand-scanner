import { BaseEvent } from '../../../common/events/base.event.js';
import type {
  ScanStatus,
  ScanTrigger,
} from '../../../database/generated/prisma/enums.js';
import type { DnsResolution } from '../../dns-resolver/dns.types.js';

export const SCAN_EVENTS = {
  BEFORE_CREATE: 'scan.before-create',
  CREATED: 'scan.created',
  BEFORE_STATUS_CHANGE: 'scan.before-status-change',
  STATUS_CHANGED: 'scan.status-changed',
  BEFORE_PROGRESS: 'scan.before-progress',
  PROGRESS: 'scan.progress',
  BATCH_RESOLVED: 'scan.batch-resolved',
  COMPLETED: 'scan.completed',
  FAILED: 'scan.failed',
  CANCELLED: 'scan.cancelled',
} as const;

export interface ScanOptions {
  fuzzers?: string[];
  includeWhois?: boolean;
  includeScreenshots?: boolean;
}

/** Which per-domain enrichments a scan asked for (both default to on). */
export interface EnrichmentFlags {
  whois: boolean;
  screenshots: boolean;
}

export function enrichmentFlags(
  options: ScanOptions | null | undefined,
): EnrichmentFlags {
  return {
    whois: options?.includeWhois !== false,
    screenshots: options?.includeScreenshots !== false,
  };
}

export class ScanBeforeCreateEvent extends BaseEvent {
  readonly name = SCAN_EVENTS.BEFORE_CREATE;
  constructor(
    readonly originalDomainId: string,
    readonly triggeredBy: ScanTrigger,
    readonly options: ScanOptions,
  ) {
    super();
  }
}

export class ScanCreatedEvent extends BaseEvent {
  readonly name = SCAN_EVENTS.CREATED;
  constructor(
    readonly scanId: string,
    readonly originalDomainId: string,
    readonly triggeredBy: ScanTrigger,
  ) {
    super();
  }
}

export class ScanBeforeStatusChangeEvent extends BaseEvent {
  readonly name = SCAN_EVENTS.BEFORE_STATUS_CHANGE;
  constructor(
    readonly scanId: string,
    readonly to: ScanStatus,
  ) {
    super();
  }
}

export class ScanStatusChangedEvent extends BaseEvent {
  readonly name = SCAN_EVENTS.STATUS_CHANGED;
  constructor(
    readonly scanId: string,
    readonly originalDomainId: string,
    readonly from: ScanStatus,
    readonly to: ScanStatus,
  ) {
    super();
  }
}

export class ScanBeforeProgressEvent extends BaseEvent {
  readonly name = SCAN_EVENTS.BEFORE_PROGRESS;
  constructor(
    readonly scanId: string,
    readonly resolved: number,
  ) {
    super();
  }
}

export class ScanProgressEvent extends BaseEvent {
  readonly name = SCAN_EVENTS.PROGRESS;
  constructor(
    readonly scanId: string,
    readonly resolvedCount: number,
    readonly permutationsTotal: number,
  ) {
    super();
  }
}

/**
 * A DNS batch finished. Emitted with `emitAsync` and awaited by the processor, so the
 * scanned-domains listener's persistence is part of the job: if it fails, the job retries.
 */
export class ScanBatchResolvedEvent extends BaseEvent {
  readonly name = SCAN_EVENTS.BATCH_RESOLVED;
  constructor(
    readonly scanId: string,
    readonly originalDomainId: string,
    readonly fuzzerByDomain: Record<string, string>,
    readonly resolutions: DnsResolution[],
    readonly enrichment: EnrichmentFlags = { whois: true, screenshots: true },
  ) {
    super();
  }
}

export interface ScanCounts {
  permutationsTotal: number;
  resolvedCount: number;
  registeredCount: number;
  newCount: number;
  failedCount: number;
}

export class ScanFinishedEvent extends BaseEvent {
  constructor(
    readonly name:
      | typeof SCAN_EVENTS.COMPLETED
      | typeof SCAN_EVENTS.FAILED
      | typeof SCAN_EVENTS.CANCELLED,
    readonly scanId: string,
    readonly originalDomainId: string,
    /** True when every technique ran — only then can "not seen" mean "no longer registered". */
    readonly fullScan: boolean,
    readonly counts?: ScanCounts,
    readonly errorMessage?: string,
  ) {
    super();
  }
}
