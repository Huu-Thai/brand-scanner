import {
  Counter,
  Gauge,
  Histogram,
  Registry,
  collectDefaultMetrics,
} from 'prom-client';

/**
 * Prometheus metrics (PLAN.md §12). One registry per process; module-level metric objects so
 * any code path can record without DI. Scrape-time gauges (queues, DB) are wired in MetricsCollector.
 * Every series is prefixed `fuzzer_`; Prometheus adds `instance` / `job` (api, worker).
 */
export const registry = new Registry();
collectDefaultMetrics({ register: registry, prefix: 'fuzzer_' });

const r = { registers: [registry] };

export const httpDuration = new Histogram({
  name: 'fuzzer_http_request_duration_seconds',
  help: 'API request latency by route template',
  labelNames: ['method', 'route', 'status'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  ...r,
});

export const jobDuration = new Histogram({
  name: 'fuzzer_job_duration_seconds',
  help: 'BullMQ job processing time (processedOn → finishedOn)',
  labelNames: ['queue', 'status'] as const,
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300],
  ...r,
});

export const jobsTotal = new Counter({
  name: 'fuzzer_jobs_total',
  help: 'BullMQ jobs finished by queue and status (failed counts every failed attempt)',
  labelNames: ['queue', 'status'] as const,
  ...r,
});

export const queueJobs = new Gauge({
  name: 'fuzzer_queue_jobs',
  help: 'Jobs per queue and state (scrape time)',
  labelNames: ['queue', 'state'] as const,
  ...r,
});

export const queueOldestWaiting = new Gauge({
  name: 'fuzzer_queue_oldest_waiting_seconds',
  help: 'Age of the oldest waiting job per queue — queue lag (scrape time)',
  labelNames: ['queue'] as const,
  ...r,
});

export const dnsLookupDuration = new Histogram({
  name: 'fuzzer_dns_lookup_duration_seconds',
  help: 'Full per-domain resolution (NS, A, AAAA, MX with failover) by outcome',
  labelNames: ['outcome'] as const,
  buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  ...r,
});

export const screenshotsTotal = new Counter({
  name: 'fuzzer_screenshots_total',
  help: 'Screenshot attempts by result (captured | failed)',
  labelNames: ['result'] as const,
  ...r,
});

export const whoisTotal = new Counter({
  name: 'fuzzer_whois_lookups_total',
  help: 'WHOIS/RDAP lookups by result (created | failed)',
  labelNames: ['result'] as const,
  ...r,
});

export const threatFeedPushTotal = new Counter({
  name: 'fuzzer_threat_feed_push_total',
  help: 'Indicator pushes to threat-feed by outcome',
  labelNames: ['outcome'] as const,
  ...r,
});

export const retentionPurgedTotal = new Counter({
  name: 'fuzzer_retention_rows_purged_total',
  help: 'Rows removed by retention, per table',
  labelNames: ['table'] as const,
  ...r,
});

export const retentionObjectsTotal = new Counter({
  name: 'fuzzer_retention_objects_deleted_total',
  help: 'Object-storage objects removed by retention',
  ...r,
});

export const scansByStatus = new Gauge({
  name: 'fuzzer_scans',
  help: 'Scans per status (scrape time; retained window only)',
  labelNames: ['status'] as const,
  ...r,
});

export const outboxPending = new Gauge({
  name: 'fuzzer_outbox_pending',
  help: 'Outbox rows not yet delivered, by origin role (scrape time)',
  labelNames: ['origin'] as const,
  ...r,
});

export const outboxOldestPending = new Gauge({
  name: 'fuzzer_outbox_oldest_pending_seconds',
  help: 'Age of the oldest undelivered outbox row (scrape time)',
  ...r,
});

export const outboxDeadLetters = new Gauge({
  name: 'fuzzer_outbox_dead_letters',
  help: 'Outbox rows parked after the last delivery attempt (scrape time)',
  ...r,
});

export const lastRetentionRun = new Gauge({
  name: 'fuzzer_retention_last_success_timestamp_seconds',
  help: 'Unix time the last retention run finished (scrape time)',
  ...r,
});

export const alertsTotal = new Counter({
  name: 'fuzzer_alerts_total',
  help: 'Alert deliveries by event type, channel type and result (sent | failed | retry)',
  labelNames: ['event_type', 'channel_type', 'result'] as const,
  ...r,
});

export const ctCertificatesTotal = new Counter({
  name: 'fuzzer_ct_certificates_total',
  help: 'Certificates received from the CT stream (leader only)',
  ...r,
});

export const ctMatchesTotal = new Counter({
  name: 'fuzzer_ct_matches_total',
  help: 'New brand look-alike candidates found in CT, by match kind',
  labelNames: ['kind'] as const,
  ...r,
});

export const ctStreamConnected = new Gauge({
  name: 'fuzzer_ct_stream_connected',
  help: '1 while this process is the CT leader and connected to the stream',
  ...r,
});
