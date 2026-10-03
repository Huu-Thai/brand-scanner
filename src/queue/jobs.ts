/** Job names and payloads. Payloads carry ids (and DNS batches), never whole DB rows. */
export const JOBS = {
  ORCHESTRATE: 'orchestrate',
  RESOLVE: 'resolve',
  FINALIZE: 'finalize',
  SCHEDULED_SCAN: 'scheduled-scan',
  WHOIS_LOOKUP: 'whois-lookup',
  CAPTURE: 'capture',
  SCORE: 'score',
  RESCAN: 'rescan',
  PUSH_INDICATOR: 'push-indicator',
  RETENTION_RUN: 'retention-run',
  ORPHAN_SWEEP: 'orphan-sweep',
  SEND_ALERT: 'send-alert',
  SEND_DIGEST: 'send-digest',
  CT_MATCH: 'ct-match',
  CAPTURE_REFERENCE: 'capture-reference',
  REFRESH_REFERENCES: 'refresh-references',
} as const;

export const SCAN_FLOW_PRODUCER = 'scan-flow';

export interface OrchestrateJobData {
  scanId: string;
}

export interface ResolveJobData {
  scanId: string;
  originalDomainId: string;
  batchIndex: number;
  /** [domain, fuzzer] pairs — compact to keep Redis payloads small. */
  permutations: [string, string][];
}

export interface FinalizeJobData {
  scanId: string;
  batchSize: number;
  permutationsTotal: number;
}

export interface ScheduledScanJobData {
  originalDomainId: string;
}

export interface WhoisJobData {
  scannedDomainId: string;
  domain: string;
  scanId?: string;
  /** Ignore the WHOIS_REFRESH_DAYS freshness window (manual refresh). */
  force?: boolean;
  /** Times the job was re-parked because its registry's rate window was full. */
  busyBounces?: number;
}

export interface ScreenshotJobData {
  scannedDomainId: string;
  domain: string;
  scanId?: string;
}

export type AnalyticsTrigger =
  | 'discovered'
  | 'dns-changed'
  | 'whois'
  | 'whois-failed'
  | 'manual'
  | 'screenshot'
  | 'reference';

export interface AnalyticsJobData {
  scannedDomainId: string;
  scanId?: string;
  trigger: AnalyticsTrigger;
}

export interface RescanJobData {
  scannedDomainId: string;
  domain: string;
  actor: string;
}

export interface ThreatFeedPushJobData {
  scannedDomainId: string;
  domain: string;
  /** upsert = confirmed threat (active indicator); deactivate = cleared */
  action: 'upsert' | 'deactivate';
  actor: string;
}

export const jobIds = {
  orchestrate: (scanId: string) => `orchestrate-${scanId}`,
  resolve: (scanId: string, index: number) => `resolve-${scanId}-${index}`,
  finalize: (scanId: string) => `finalize-${scanId}`,
  schedule: (originalDomainId: string) => `schedule-${originalDomainId}`,
  // Enrichment ids are unique per scan + trigger so a later scan (or the WHOIS-driven rescore)
  // is never deduplicated against an earlier completed job still kept in Redis.
  whois: (scannedDomainId: string, scope: string) =>
    `whois-${scannedDomainId}-${scope}`,
  screenshot: (scannedDomainId: string, scope: string) =>
    `screenshot-${scannedDomainId}-${scope}`,
  rescan: (scannedDomainId: string) =>
    `rescan-${scannedDomainId}-${Date.now()}`,
  push: (scannedDomainId: string, action: string) =>
    `push-${scannedDomainId}-${action}-${Date.now()}`,
  analytics: (
    scannedDomainId: string,
    scope: string,
    trigger: AnalyticsTrigger,
  ) => `analytics-${scannedDomainId}-${scope}-${trigger}`,
};

export interface RetentionJobData {
  /** 'schedule' or the API key / user that asked for a manual run. */
  requestedBy: string;
}

export interface AlertJobData {
  /** SEND_ALERT: one immediate delivery. */
  deliveryId?: string;
}

export interface CtMatchJobData {
  originalDomainId: string;
  /** Registrable domain to track. */
  domain: string;
  /** Certificate name that matched (may be a subdomain of `domain`). */
  certName: string;
  kind: 'typo' | 'tld-swap' | 'combo' | 'subdomain';
  seenAt: string;
}

export interface BrandReferenceJobData {
  originalDomainId: string;
}
