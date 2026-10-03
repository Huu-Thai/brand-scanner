/** Queue names (PLAN.md §5). Always reference these constants, never string literals. */
export const QUEUES = {
  SCAN_ORCHESTRATOR: 'scan-orchestrator',
  DNS_RESOLVE: 'dns-resolve',
  SCAN_FINALIZE: 'scan-finalize',
  WHOIS: 'whois',
  SCREENSHOT: 'screenshot',
  ANALYTICS: 'analytics',
  SCHEDULER: 'scheduler',
  THREAT_FEED_PUSH: 'threat-feed-push',
  RETENTION: 'retention',
  DOMAIN_RESCAN: 'domain-rescan',
  ALERTS: 'alerts',
  CT_MATCHES: 'ct-matches',
} as const;

export type QueueName = (typeof QUEUES)[keyof typeof QUEUES];
export const ALL_QUEUES: QueueName[] = Object.values(QUEUES);
