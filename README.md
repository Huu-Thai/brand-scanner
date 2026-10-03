# Fuzzer Scanner

Typosquatting / look-alike domain discovery service. Given an **original domain**, it generates
permutations (dnstwist-compatible fuzzer), resolves which are registered, enriches them
(WHOIS/RDAP, Selenium screenshots, rule-based scoring) and exposes them for review over a REST API.

Full design: [PLAN.md](PLAN.md). Delivered: **Phase 0 — Foundation**, **Phase 1 — Fuzzer + scans**, **Phase 2 — Enrichment**, **Phase 3 — Review & manage** and **Phase 4 — Hardening** and **Phase 5 — Expansion** (§15). Operations: [docs/RUNBOOK.md](docs/RUNBOOK.md).

| | |
|---|---|
| Runtime | Node ≥ 24, NestJS 12 (ESM), TypeScript 6 |
| Data | PostgreSQL ≥ 13 via Prisma 7 (`@prisma/adapter-pg`) |
| Queues | BullMQ 6 on Redis 7 — **password required** |
| Storage | S3 / MinIO (private bucket, presigned URLs) |
| Screenshots | Selenium Grid |
| Logging | Winston (JSON in production, correlation ids, secret redaction) |
| Tests | Vitest unit (coverage gate 80/75) + e2e with Testcontainers |

## Quick start

```bash
cp .env.example .env
#  - set REDIS_PASSWORD and S3_SECRET_ACCESS_KEY to long random values
#  - create API keys and paste the printed entries into API_KEYS:
npm run apikey:generate -- local-admin admin
npm run apikey:generate -- local-reader read

npm install                 # also runs prisma generate
docker compose up -d        # Postgres, Redis (requirepass), MinIO (+ private bucket), Selenium
npm run migrate:deploy      # apply reviewed migrations
npm run seed                # sample original domain (reference data ships in migrations)
npm run start:dev           # API  → http://localhost:3000/api/v1
npm run start:worker:dev    # worker process (processors arrive in Phase 1+)
```

- Swagger UI: http://localhost:3000/api/docs (JSON at `/api/docs-json`) — click **Authorize** and paste an API key.
- Health: `GET /api/v1/health` (public) — database, authenticated Redis, bucket, Selenium Grid.
- If host ports clash with other stacks, set `FS_POSTGRES_PORT`, `FS_REDIS_PORT`, `FS_MINIO_PORT`,
  `FS_SELENIUM_PORT` in `.env` (and point `DATABASE_URL` / `REDIS_PORT` / `S3_ENDPOINT` at them).
- Full containerised stack: `docker compose --profile app up -d --build` (migrate → api + worker).

## Scanning

```bash
# 1. register the brand domain (IDN accepted; optional cron schedule in UTC)
curl -X POST localhost:3000/api/v1/original-domains -H "x-api-key: $KEY" -H 'content-type: application/json' \
     -d '{"domain":"example.com","scanSchedule":"0 2 * * *"}'
# 2. trigger a scan (202 = queued; 200 = a scan is already running for this domain)
curl -X POST localhost:3000/api/v1/scans -H "x-api-key: $KEY" -H 'content-type: application/json' \
     -H 'Idempotency-Key: deploy-2026-10-02-001' \
     -d '{"domain":"example.com","options":{"fuzzers":["omission","transposition","homoglyph"]}}'
# 3. poll progress, then list what was found
curl localhost:3000/api/v1/scans/<scanId> -H "x-api-key: $KEY"
curl "localhost:3000/api/v1/scanned-domains?scanId=<scanId>" -H "x-api-key: $KEY"
```

Pipeline (worker process): `scan-orchestrator` generates permutations (dnstwist-compatible, 20
techniques) → a BullMQ flow of `dns-resolve` batches (`SCAN_BATCH_SIZE`) → `scan-finalize` computes
totals from the database. Registered look-alikes are upserted into `scanned_domains`; after a **full**
scan (no `fuzzers` subset) look-alikes that no longer resolve become `INACTIVE`.

- At most one scan per original domain runs at a time — enforced by a partial unique index.
- DNS: 16 public resolvers by default (`DNS_NAMESERVERS`), per-server failover, NS-first NXDOMAIN short-circuit.
- `WORKER_QUEUES=dns-resolve` runs only that processor, so DNS capacity scales separately.
- The fuzzer is pinned to Reporting's implementation by `fuzzer.parity.spec.ts`; re-record with
  `npx tsx scripts/record-fuzzer-fingerprints.ts` only when the reference changes on purpose.

## Enrichment (Phase 2)

Every registered look-alike is enriched asynchronously by event-driven workers:

| Step | Queue | What it does |
|---|---|---|
| WHOIS | `whois` | RDAP (IANA bootstrap) first, port-43 WHOIS fallback with registrar referral; refreshed at most every `WHOIS_REFRESH_DAYS` |
| Screenshot | `screenshot` | Selenium Grid capture (https → http), dHash, stored privately in S3/MinIO; `GET /screenshots/:id/image` → presigned URL |
| Score | `analytics` | 10 DB-configurable rules → `analytics` row + `risk_score` / `threat_level` on the look-alike; `alert.high-risk` on entering HIGH_RISK |

Scoring runs after WHOIS (domain age is a signal), immediately if WHOIS is disabled for the scan,
and again whenever DNS changes. A scan's status reflects discovery (DNS); enrichment continues per
domain afterwards — watch `threatLevel` leave `UNSCORED`.

**Reputation (manage-feed).** The `reputation_check` rule asks the threat-feed API (the backend of
manage-feed) whether the look-alike — or its first IPv4 — is an active indicator. Configure a
dedicated read-only service user (self-registration lands in the `viewer` role):

```bash
THREAT_FEED_ENABLED=true
THREAT_FEED_URL=http://threat-feed:8080/api/v1
THREAT_FEED_EMAIL=fuzzer-scanner@service.local
THREAT_FEED_PASSWORD=<secret>
```

Results are cached in Redis; an outage opens a circuit breaker and the rule scores 0 ("unknown")
instead of failing the scan.

**Tuning.** `GET /api/v1/scoring` shows rules and bands; `PATCH /api/v1/scoring/rules/:key` and
`PUT /api/v1/scoring/thresholds` (admin key) apply immediately; `POST /scanned-domains/:id/analytics/rescore`
re-scores on demand.

## Analyst workflow (Phase 3)

| Action | Endpoint |
|---|---|
| Triage list (filters, sort) | `GET /scanned-domains?status=NEW,UNDER_REVIEW&threatLevel=HIGH_RISK&sort=riskScore` |
| Record a verdict | `POST /scanned-domains/:id/reviews` `{ "verdict": "MALICIOUS", "notes": "…" }` |
| Review history / audit trail | `GET /scanned-domains/:id/reviews`, `GET /reviews?verdict=&reviewer=&originalDomainId=` |
| Status / tags (one or up to 500) | `PATCH /scanned-domains/:id`, `PATCH /scanned-domains/bulk` `{ ids, status?, addTags?, removeTags? }` |
| Re-resolve + re-enrich now | `POST /scanned-domains/:id/rescan` (202) |
| Soft delete | `DELETE /scanned-domains/:id` (204) |
| Export (same filters as the list) | `GET /scanned-domains/export?format=csv\|json\|stix` — streamed, capped at `EXPORT_MAX_ROWS` |

**Verdict → status:** `MALICIOUS` → `CONFIRMED_THREAT` · `SUSPICIOUS`/`NEEDS_INFO` → `UNDER_REVIEW` ·
`BENIGN` → `ACTIVE` · `FALSE_POSITIVE` → `FALSE_POSITIVE`. Reviews are authoritative. Manual changes
are limited to `UNDER_REVIEW`, `CONFIRMED_THREAT`, `FALSE_POSITIVE`, `ALLOWLISTED`, `TAKEN_DOWN`
(only after `CONFIRMED_THREAT`) and `ACTIVE` (reopen). Scans never overwrite an analyst decision.
A disallowed transition rejects the whole request with 422, and nothing changes.

**Publishing to manage-feed.** With `THREAT_FEED_PUSH_ENABLED=true`, entering `CONFIRMED_THREAT`
upserts a `DOMAIN` indicator in threat-feed (source `THREAT_FEED_SOURCE_NAME`, severity `high`, or
`critical` for HIGH_RISK, confidence 95, tags `typosquat`, `source:fuzzer-scanner`, `fuzzer:<technique>`,
`brand:<domain>`). Leaving it (false positive, allowlisted, taken down, …) deactivates the indicator.
Pushes run on the `threat-feed-push` queue with retries, and they converge on the look-alike's
*current* status. That makes retries and out-of-order jobs harmless. 4xx errors such as missing
permissions fail fast. The service account's role needs `GET /feeds`, `POST /feeds`, `PATCH /feeds/*`,
plus `GET` and `POST /sources` unless `THREAT_FEED_SOURCE_ID` is set.

**Console.** manage-feed's Brand protection pages (Brands, Look-alikes, Review queue) call this API
through its `/api/lookalikes/*` gateway, using a `write` key whose name is listed in
`TRUSTED_PROXY_KEYS`. That lets reviews be recorded as the signed-in analyst (`x-acting-user`).

## Alerting (Phase 5)

Channels (Slack, e-mail, signed webhooks) receive alerts according to subscriptions. A subscription is
a channel × brand (or every brand) × events × minimum risk score × *immediate* or *daily digest*.

| Event | Fires when |
|---|---|
| `HIGH_RISK` | a look-alike's score enters the HIGH_RISK band |
| `CONFIRMED_THREAT` | an analyst confirms a look-alike (review or status change) |
| `NEW_LOOKALIKE` | a scan finds a newly registered look-alike (best used as a digest) |
| `WENT_LIVE` | a look-alike that had stopped resolving resolves again |

```bash
curl -X POST -H "x-api-key: $KEY" -H 'content-type: application/json' $API/alert-channels \
  -d '{"name":"SOC Slack","type":"SLACK","target":"https://hooks.slack.com/services/…"}'
curl -X POST -H "x-api-key: $KEY" -H 'content-type: application/json' $API/alert-subscriptions \
  -d '{"channelId":"<id>","eventTypes":["HIGH_RISK","CONFIRMED_THREAT"],"minRiskScore":80}'
curl -X POST -H "x-api-key: $KEY" $API/alert-channels/<id>/test      # sample alert, reports ok/error
```

- **Secrets:** targets and webhook signing secrets are encrypted at rest (AES-256-GCM, `ALERT_ENCRYPTION_KEY`).
  The API only ever returns a masked hint, and the signing secret only once (on create or rotate).
- **Webhook payloads** are signed: `X-Fuzzer-Signature: sha256=hex(HMAC-SHA256(secret, "${X-Fuzzer-Timestamp}.${body}"))`.
- **SSRF guard:** targets must be https and resolve to public addresses. This is checked when a channel is
  saved and again before every send, and redirects are never followed.
- **Reliable delivery:** alerts are recorded in the producing transaction and queued through the outbox.
  Each subscription alerts at most once per look-alike, event and day. 5xx responses and timeouts are
  retried with backoff; 4xx responses fail at once (`GET /alert-deliveries`).
- In manage-feed, use **Brand protection → Alerts**.

## Certificate Transparency monitoring (Phase 5)

With `CT_MONITOR_ENABLED=true`, one worker (elected through a Redis lease) consumes a certstream-compatible
CT stream and checks every certificate name against the active brands:

| Match | Example for `paypal.com` |
|---|---|
| `typo`: edit distance ≤ 1–2 after homoglyph and confusable normalisation | `paypa1.com`, `pаypal.com` (Cyrillic а), `paypall.com` |
| `tld-swap`: same label, different suffix | `paypal.net` |
| `combo`: brand keyword inside another label (labels ≥ `CT_MIN_KEYWORD_LENGTH`) | `paypal-secure-login.com` |
| `subdomain`: brand used as a subdomain of someone else's domain | `paypal.com.account-verify.xyz` → `account-verify.xyz` |

Matches are de-duplicated for 7 days, resolved, and tracked as look-alikes with technique
`ct:<kind>`. WHOIS, screenshot, scoring and alerts then follow as for scan results. Every full scan of the
brand re-resolves its CT finds, so they go INACTIVE when they stop resolving. This catches look-alikes the
fuzzer never generates. Status: `GET /api/v1/ct-monitor/status`.

## Visual similarity & page content (Phase 5)

Each brand's own site is captured as a **reference**: on creation, weekly, or with
`POST /original-domains/:id/reference`. Every look-alike capture also records **page signals**:
a password field, the hosts its forms post to, a text sample, and the favicon's SHA-256. All of
these are gathered inside the browser session; the worker never fetches attacker-controlled URLs
itself. Two scoring rules use them:

| Rule | Fires when | Points (default) |
|---|---|---|
| `visual_similarity` | the screenshot's dHash is within 6 bits (≈ 91%) / 12 bits (≈ 81%) of the brand reference | 40 / 20 |
| `phishing_content` | a password form naming the brand or posting to a third-party host · the brand's own favicon · the brand named on the page | 35 · 30 · 10 |

Look-alikes are rescored when a new screenshot arrives, and all captured look-alikes of a brand are
rescored when its reference changes. The console's look-alike page compares the capture with the
brand site side by side.

## Authentication with threat-feed users (Phase 5)

With `AUTH_JWT_SECRET` (threat-feed's `JWT_SECRET`) set, a threat-feed **user token** works anywhere
an API key does:

```bash
curl -H "Authorization: Bearer $THREAT_FEED_ACCESS_TOKEN" $API/scanned-domains
```

- The signature (HS256 only) and expiry are verified locally. Identity and role then come from threat-feed
  `GET /auth/me`, so deactivated users and role changes take effect within `AUTH_IDENTITY_CACHE_MS`.
- Role → scope: full access (`* * *`) → admin; may create indicators (`POST /feeds`) → write; may read
  indicators (`GET /feeds`) → read; otherwise 403.
- The user acts as themselves: reviews and status changes record their e-mail, `x-acting-user` is
  ignored, and rate limits are per user.
- manage-feed's gateway uses this automatically when it has no `FUZZER_SCANNER_API_KEY`
  (`FUZZER_SCANNER_AUTH=jwt`), forwarding the analyst's own session token.

## Investigation views (Phase 6)

| Endpoint | Returns |
|---|---|
| `GET /scanned-domains/:id/related` | `{ nodes, edges }`: brand, IPs, nameservers, mail servers, registrar, and other look-alikes sharing them (≤ 12 per node; `sharedBy` gives the full count) |
| `GET /scanned-domains/:id/timeline` | Discovery, WHOIS, captures, risk-band changes, reviews and alerts, newest first |

They power the console's Infrastructure graph and Activity timeline on each look-alike.

## Operations (Phase 4)

| Concern | What exists | Where |
|---|---|---|
| Data retention | Daily at 03:30 UTC: history older than 31 days (keeping each look-alike's newest WHOIS, score, screenshot and scan), soft-deleted rows, S3 objects. Weekly orphan sweep. `GET/POST /api/v1/admin/retention` (admin key) | PLAN §6a |
| Event delivery | Transactional outbox: after-commit events are stored with the change and redelivered after a crash | PLAN §1.2 |
| Rate limits | Per API key (`THROTTLE_LIMIT`) plus a stricter per-route budget for expensive endpoints (`THROTTLE_EXPENSIVE_LIMIT`); WHOIS per-registry windows | RUNBOOK §4 |
| Metrics | `/api/v1/metrics` (API) and `:9464/metrics` (each worker): HTTP latency, queue depth and lag, job throughput, failure ratio and duration, DNS, WHOIS, screenshots, outbox, retention | `src/metrics/` |
| Dashboards and alerts | `docker compose --profile observability up -d`: Prometheus + 12 alert rules, Alertmanager, Grafana dashboard *Fuzzer Scanner* | `ops/observability/` |
| Queue admin | `node scripts/queues.mjs stats \| failed <q> \| retry-failed <q> \| clean-failed <q> <h>` | RUNBOOK §3 |
| Load test | Hermetic run at the sizing target (10 brands × ~42k permutations) with SLO verdict | `load/README.md` |

## Authentication

Every route except `/health` requires `x-api-key`. Keys are configured as
`name:scope:sha256(key)` — raw keys are never stored. Scopes: `read` (GET), `write` (mutations),
`admin` (everything, incl. admin endpoints). The key **name** is recorded as the actor
(e.g. `reviews.reviewer`). Keys named in `TRUSTED_PROXY_KEYS` may instead name the end user with the
`x-acting-user` header. Other keys can't spoof it, because the header is ignored for them.

## Scripts

| Command | Purpose |
|---|---|
| `npm run start:dev` / `start:worker:dev` | API / worker in watch mode |
| `npm run build` · `start:prod` · `start:worker:prod` | Production build / run |
| `npm run check` | typecheck + lint + format check + unit tests with coverage gate |
| `npm test` · `test:cov` · `test:e2e` | Unit · coverage · e2e (needs Docker) |
| `npm run migrate:dev` | Create a new migration (`--create-only`, review before applying) |
| `npm run migrate:deploy` · `migrate:status` · `migrate:diff` | Apply · status · drift check vs schema |
| `npm run seed` | Development sample data |
| `npm run apikey:generate -- <name> <scope>` | New API key + its `API_KEYS` entry |

## Database & migrations

Schema: `src/database/prisma/schema.prisma`; migrations: `src/database/prisma/migrations/`.

- Every table has a UUID primary key `pk_<table>` (`DEFAULT gen_random_uuid()`).
- Every relationship is a named foreign key `fk_<table>_<column>` with explicit `ON DELETE` / `ON UPDATE`,
  and **every FK column is indexed**.
- Migrations are written/reviewed by hand and applied with `migrate deploy` (never on app boot).
  `test/migrations.e2e-spec.ts` verifies no drift, all PKs, the exact FK set and actions, FK indexes
  and cascade / set-null behaviour on a fresh database.
- Rollback for the initial migration set: `src/database/prisma/rollback.sql` (destructive, manual only).

## Project layout

```
src/
├── main.ts · worker.main.ts · bootstrap.ts   entrypoints + shared HTTP pipeline
├── app.module.ts · worker.module.ts
├── config/        typed config + Joi validation (fails fast)
├── logger/        Winston setup, AsyncLocalStorage request context, redaction
├── common/        API-key guard, exception filter, request-context middleware,
│                  TransactionalEventBus (before event → tx → after-commit events)
├── database/      Prisma service, schema, migrations, constraint map, seed
├── redis/         the only Redis connection factory (password enforced)
├── queue/         BullMQ registration + queue names
├── storage/       S3/MinIO StorageService
├── health/        Terminus checks
├── system/        /system/info (auth smoke endpoint)
└── modules/
    ├── fuzzer/            dnstwist port + dictionaries (pure)
    ├── dns-resolver/      registration check (failover across resolvers)
    ├── original-domains/  brand domains: CRUD, schedules
    ├── scans/             trigger/list/cancel API, orchestrator · DNS · finalize · scheduler processors
    ├── scanned-domains/   look-alike persistence (bulk upsert), risk mirror + read API
    ├── whois-informations/ RDAP + port-43 lookup, history API
    ├── screenshots/       Selenium capture, S3 storage, image API
    ├── rules/             10 scoring rules, engine, scoring admin API
    └── analytics/         scoring processor, history / summary / trends API
src/integrations/threat-feed/  manage-feed reputation client (service account, cache, breaker)
test/              e2e suites + Testcontainers helpers
```

## Production notes

- `REDIS_PASSWORD` must be ≥ 16 characters when `NODE_ENV=production`; prefer an ACL user (`REDIS_USERNAME`) and `REDIS_TLS=true`.
- Run `prisma migrate deploy` as a release job (`docker build --target migrate`).
- Images: `docker build --target api|worker|migrate .` — non-root, health-checked.
