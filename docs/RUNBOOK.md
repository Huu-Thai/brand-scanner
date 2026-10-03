# Fuzzer Scanner — operations runbook

Who this is for: whoever is on call for fuzzer-scanner. It covers what runs where, how to check the
service is healthy, what each alert means and what to do about it, and the routine jobs (retention,
key rotation, scaling). Design background lives in [PLAN.md](../PLAN.md).

## 1. What runs where

| Process | Command | Listens | Notes |
|---|---|---|---|
| API | `node dist/main.js` (image target `api`) | `:3000` — `/api/v1/*`, `/api/v1/health`, `/api/v1/metrics` | Stateless; scale horizontally behind a load balancer |
| Worker | `node dist/worker.main.js` (image target `worker`) | `:9464/metrics` (`METRICS_PORT`) | `WORKER_QUEUES` picks the queues a deployment serves (empty = all) |
| Migrations | `prisma migrate deploy` (image target `migrate`) | — | One-off release job **before** rolling out API/worker |

Dependencies: PostgreSQL 16, Redis 7 (password / ACL required), S3 or MinIO (private bucket),
Selenium Grid (screenshots), threat-feed API (reputation lookups + publishing confirmed threats).

Observability (`docker compose --profile observability up -d`): Prometheus `:9090`, Alertmanager
`:9093`, Grafana `:3001` (dashboard **Fuzzer Scanner**). Prometheus targets are in
`ops/observability/targets/*.json`; alert rules in `ops/observability/alerts.yml`.

## 2. Is it healthy?

```bash
curl -s https://<api>/api/v1/health | jq .status          # db, redis, storage, selenium (+ threat-feed)
node scripts/queues.mjs stats                              # depth, failed, oldest waiting per queue
curl -s -H "x-api-key: $ADMIN_KEY" https://<api>/api/v1/admin/retention | jq '{lastRun: .lastRun.finishedAt, nextRun}'
```

Grafana → *Fuzzer Scanner*: the **Overview** row should show API and workers up, no firing alerts,
outbox pending near 0, dead letters 0, last retention < 1 day.

## 3. Alerts

Severity: **critical** = page, **warning** = next business hours, **info** = review weekly.

### FuzzerTargetDown
An API or worker process stopped answering `/metrics` for 2 minutes.
1. Check the process / pod (`kubectl get pods`, `docker compose ps`) and its last logs.
2. Crash loop at boot: the log line `Config validation error` names the bad variable (env is validated
   with Joi at start-up). Common: missing `REDIS_PASSWORD`, `THREAT_FEED_PUSH_ENABLED=true` without
   `THREAT_FEED_ENABLED=true`, an invalid `RETENTION_CRON`.
3. Running but not scraped: check `METRICS_TOKEN` matches Prometheus' credentials and the target in
   `ops/observability/targets/`.

Nothing is lost while a worker is down: jobs wait in Redis and domain events wait in the outbox.

### FuzzerApiErrorRate
More than 5% of API requests return 5xx.
1. `/api/v1/health` — a dependency down (database, Redis) explains most cases.
2. Logs: every 5xx is logged by `AllExceptionsFilter` with the `requestId` the client received.
3. Postgres connection exhaustion: look for `Timed out fetching a new connection`; reduce API
   replicas or add PgBouncer (PLAN §13).

### FuzzerApiLatencyHigh
p95 above 500 ms for 10 minutes (exports excluded).
1. Grafana → *p95 latency by route* shows which route.
2. List endpoints: check slow queries (`pg_stat_statements`); a missing index or a very large
   unfiltered `GET /scanned-domains` page is the usual cause.
3. During a large scan the database is busy with batch upserts. If this coincides, scale the
   `dns-resolve` workers down rather than the API up.

### FuzzerDnsQueueLag
The oldest DNS batch has waited more than 90 minutes. The SLO is a full scan within 2 hours.
1. Workers serving `dns-resolve` running? (`node scripts/queues.mjs stats`, active > 0.)
2. Grafana → *DNS lookups / s by outcome*: many `error` outcomes mean the resolvers time out. Check
   `DNS_NAMESERVERS`, use resolvers close to the workers (PLAN §13), and lower `DNS_CONCURRENCY` if
   upstream resolvers rate-limit you.
3. Add `dns-resolve` capacity: more replicas of a worker deployment with `WORKER_QUEUES=dns-resolve`.

### FuzzerWhoisQueueLag
The oldest WHOIS job has waited more than 5 hours. The SLO is WHOIS within 6 hours.
WHOIS is deliberately slow. RDAP registries are rate-limited per **client IP**, and the client
keeps each registry host under 8 requests / 11 s **per process**. `.com`/`.net` (Verisign) carries
most look-alikes, so one egress IP processes about **0.7 `.com` look-alikes per second, roughly 2,600
per hour**. See §6 for the measured numbers.
1. Expected after onboarding several large brands at once: the backlog drains at that rate.
2. Do **not** just add WHOIS workers behind the same egress IP: each process gets its own rate budget,
   so Verisign starts returning 429 and WHOIS gets slower overall. Run `WORKER_QUEUES=whois` in **one
   replica per egress IP**. Add egress IPs (e.g. NAT gateways) to go faster.
3. Many `failed` results: `node scripts/queues.mjs failed whois`. RDAP `429` responses mean the limit
   above is exceeded somewhere, for example two deployments sharing one IP.

### FuzzerQueueLag
Another queue (analytics, scan orchestration and finalisation, threat-feed push, retention) has had
a job waiting more than 15 minutes. Check that some worker serves that queue (`WORKER_QUEUES`) and is
up. These queues are small and fast, so lag nearly always means "no consumer".

### FuzzerJobFailureRate
More than 10% of job attempts on a queue fail.
1. `node scripts/queues.mjs failed <queue>` shows the errors.
2. Fix the cause, then `node scripts/queues.mjs retry-failed <queue>`. Jobs are idempotent.
3. `screenshot` failures are normal for dead or parked sites and are excluded from the lag alert.

### FuzzerFailedJobsAccumulating
More than 500 failed jobs are kept on a queue. Failed jobs expire after 7 days. Review them with
`failed <queue>`, then retry them or `clean-failed <queue> <hours>`.

### FuzzerOutboxBacklog
A domain event has stayed undelivered for more than 5 minutes. Every after-commit event (for example
"look-alike discovered → enqueue WHOIS") is written to `outbox_events` in the same transaction and
delivered right after commit. If the process dies first, the **outbox relay** of a process with the
same role (`api` or `worker`) redelivers it after `OUTBOX_GRACE_MS`.
1. Which role? `fuzzer_outbox_pending{origin=…}`. If all processes of that role are down, rows wait
   for them. Start one.
2. Rows pending with processes up: check the logs for `Outbox relay pass failed` (database errors).

### FuzzerOutboxDeadLetters
An event failed `OUTBOX_MAX_ATTEMPTS` times and was parked.
```sql
SELECT id, event_name, origin, attempts, last_error, created_at FROM outbox_events WHERE failed_at IS NOT NULL;
-- after fixing the cause, redeliver:
UPDATE outbox_events SET failed_at = NULL, attempts = 0, available_at = now() WHERE id = '<id>';
```
Dead letters are purged by retention after 31 days.

### FuzzerRetentionStale
No successful retention run in 2 days.
1. `GET /api/v1/admin/retention`: `nextRun` is null when no worker serves the `retention` queue.
2. A run that was killed is resumable. Trigger one with
   `curl -X POST -H "x-api-key: $ADMIN_KEY" https://<api>/api/v1/admin/retention/run`.
3. `objectsFailed > 0` in `lastRun`: S3 refused deletes (check credentials and `s3:DeleteObject`).
   Those rows are kept on purpose and retried next run.

### FuzzerAlertDeliveryFailures
Alert notifications (Slack, webhook, e-mail) are failing.
1. Alerts page (manage-feed) → *Recent deliveries*, or `GET /api/v1/alert-deliveries?status=FAILED`;
   `lastError` holds the reason.
2. `HTTP 4xx` (410 / 404 / 403): the endpoint was removed or revoked. These fail at once without retries.
   Fix the channel's target and use **Send test alert**.
3. `non-public address` / `must use https`: the SSRF guard refused the target (PLAN §14 #6).
4. E-mail: `SMTP_URL` missing or wrong. 5xx and timeouts retry for about 30 minutes; digests stay pending
   until the next digest run.

### FuzzerCtStreamDown
CT monitoring is enabled but no worker is connected to the certificate stream.
1. `GET /api/v1/ct-monitor/status`. `leaderElected: false` means no worker serves the `ct-matches` queue
   (check `WORKER_QUEUES`).
2. Leader elected but not connected: check that `CT_STREAM_URL` is reachable from the workers. The public
   certstream endpoint is best-effort, so self-host `certstream-server-go` and point `CT_STREAM_URL` at it.
3. The consumer reconnects with backoff (1 s up to 60 s) and after `CT_STALL_TIMEOUT_MS` without a message.
   Certificates issued during an outage are not replayed. Full scans still cover fuzzer-generated
   look-alikes in the meantime.

### FuzzerThreatFeedPushErrors
Confirmed threats aren't reaching manage-feed.
1. `node scripts/queues.mjs failed threat-feed-push`.
2. `HTTP 403 … lacks this permission`: the threat-feed service role needs `GET`/`POST /feeds`,
   `PATCH /feeds/*` and `GET`/`POST /sources` (or set `THREAT_FEED_SOURCE_ID`). These failures are
   permanent and are not retried. Fix the role, then `retry-failed threat-feed-push`.
3. 5xx / timeouts: threat-feed is down. Jobs retry with backoff for about an hour.

## 4. Routine operations

**Retention** runs daily at 03:30 UTC (`RETENTION_CRON`); the orphan sweep runs Sundays at 04:00
(`RETENTION_SWEEP_CRON`). History older than `RETENTION_DAYS` (31) is deleted in batches of
`RETENTION_BATCH_SIZE`, keeping the newest WHOIS, score, screenshot and scan per look-alike
(`RETENTION_KEEP_LATEST=true`). Look-alikes and brands soft-deleted more than 31 days ago are purged
together with their reviews. Object-storage deletes always happen before row deletes.

**API keys:** `npm run apikey:generate -- <name> <read|write|admin>` prints a key and its
`API_KEYS` entry. Add the new entry, deploy, switch the client, remove the old entry, deploy. The
manage-feed gateway key must be listed in `TRUSTED_PROXY_KEYS`.

**User tokens (Phase 5):** with `AUTH_JWT_SECRET` set, threat-feed user tokens are accepted.
Rotating threat-feed's `JWT_SECRET` must be done in both places at once (all sessions end). A user
whose role or activation changes in threat-feed is affected within `AUTH_IDENTITY_CACHE_MS` (60 s).
If threat-feed is down, user-token requests fail with 503 (API keys keep working).

**Alerting:** losing `ALERT_ENCRYPTION_KEY` makes existing channel targets unreadable; re-create the
channels. To rotate it, re-enter each channel's target after deploying the new key.

**CT monitoring:** exactly one worker consumes the stream (Redis lease `lock:ct-stream`). Matches are
de-duplicated for 7 days in `ct:seen:*`. To re-process a domain sooner, delete its key.

**Brand references:** each brand's own site is recaptured weekly (Mondays 05:00 UTC). If a brand site
blocks automated browsers, its reference stays FAILED and the `visual_similarity` rule is skipped
for that brand. `phishing_content` still works.

**Rate limits:** every API key gets `THROTTLE_LIMIT` requests per `THROTTLE_TTL_MS`. Scan triggers,
exports, rescans, rescore, recapture and bulk updates get a separate `THROTTLE_EXPENSIVE_LIMIT` per
route. A 429 response carries `Retry-After`.

**Backups:** PostgreSQL is the source of truth (PITR / daily dumps). Redis holds queues only and can
be rebuilt: scheduled scans are reconciled from the database at API start, and lost in-flight
jobs are recovered by re-triggering scans. Screenshots in S3 are reproducible by recapture.

**Releases:** run migrations (`migrate` target), then roll the API, then the workers. Workers finish
their active jobs on SIGTERM; pending domain events are delivered or left in the outbox.

## 5. Scaling

| Pressure | Lever |
|---|---|
| Scan discovery slower than 2 h | More `dns-resolve` replicas; resolvers close to the workers; `DNS_CONCURRENCY` |
| WHOIS backlog | One `whois` replica **per egress IP**; add egress IPs, not replicas (§3 FuzzerWhoisQueueLag) |
| Screenshots | Selenium Grid nodes (`SCREENSHOT_CONCURRENCY` per worker ≤ grid slots) |
| API latency | API replicas; PgBouncer; read replica for list/summary (PLAN §13) |

## 6. Capacity (load test, 2026-10-02)

Measured at the PLAN §16 sizing target with `load/` (one API, one worker, a laptop-class host):

| Stage | Measured | Scales with |
|---|---|---|
| Discovery: 422,917 lookups (10 brands at once) | 46 s for the slowest scan, about 7,000 lookups/s against a 25 ms resolver | `dns-resolve` replicas, `DNS_CONCURRENCY`, resolver latency |
| WHOIS: 6,361 look-alikes (73% `.com`/`.net`) | 2 h 28 min, about 0.73/s for `.com` plus the other registries in parallel | egress IPs (registry limits are per IP) |
| API p95 under that load | list 25 ms, summary 12 ms, scans 8 ms | API replicas |

Rule of thumb: one egress IP gives about **2,600 new `.com` look-alikes per hour**. WHOIS is refreshed only
every `WHOIS_REFRESH_DAYS` (7), so daily rescans of known brands cost almost no WHOIS. Onboarding many
large brands at once is the only time the 6 h SLO comes into play.
See `load/README.md` to re-run the test.

## Alert routing

`ops/observability/alertmanager.yml` ships a no-op `default` receiver. Point it at your pager or chat
(for example `slack_configs` or `pagerduty_configs`). Route `severity="critical"` to paging and the rest
to a channel.
