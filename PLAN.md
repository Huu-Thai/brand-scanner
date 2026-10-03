# Fuzzer Scanner — Implementation Plan

Typosquatting / look-alike domain discovery service. Given an **original domain** (a brand the
customer owns), the service generates permutations with a dnstwist-compatible fuzzer, resolves
which ones are registered, enriches them (WHOIS/RDAP, screenshot, scoring), and exposes them for
analyst review through a REST API.

| | |
|---|---|
| Runtime | Node 24 LTS, **NestJS 12** (ESM-only), TypeScript 6 strict |
| Database | PostgreSQL 16 + **Prisma 7** (`@prisma/adapter-pg`, generated client in-repo) |
| Queue | **BullMQ** on Redis 7 (**password required**, optional ACL user + TLS) |
| Screenshots | **Selenium WebDriver** → Selenium Grid (headless Chrome), PNGs in **S3 / MinIO** |
| Reputation | Indicators curated in **manage-feed** (stored in the `threat-feed` API) |
| Auth | API key (`x-api-key`) for v1 |
| Retention | **31 days** for history (scans, screenshots, WHOIS, analytics) — §6a |
| API | REST, global prefix **`api/v1`**, **Swagger** at `/api/docs` |
| Logging | **Winston** (`nest-winston`), JSON in prod, request/job correlation IDs |
| Tests | **Vitest** unit tests (gate: 80% lines / 75% branches) + e2e with Testcontainers + migration constraint tests |

Conventions are aligned with the sibling `threat-feed` service so both codebases read the same.

**Revision 3 (2026-10-02) — Phase 0 delivered.** Tooling follows NestJS 12, whose packages are
**ESM-only**: Vitest replaces Jest (native ESM, Jest-compatible API) and oxlint + Prettier replace
ESLint. `pgcrypto` is dropped because `gen_random_uuid()` is built into PostgreSQL ≥ 13. See §15 for status.

**Revision 2 (2026-10-02):** open questions resolved (§16); migrations now specify every primary
key, foreign key, referential action and FK index (§3.3); 31-day retention added (§6a); reputation
source switched to manage-feed / threat-feed; storage fixed to S3/MinIO.

---

## 0. Decisions locked in

1. **One NestJS module per table** — `original-domains`, `scanned-domains`, `screenshots`,
   `reviews`, `whois-informations`, `analytics` — each owning its controller, service, DTOs and events.
2. **Every insert/update runs in a Prisma `$transaction`** and emits a **before** event (sync,
   may veto by throwing) and an **after** event (only once the transaction has committed).
3. **Modules talk via events**, never by injecting another module's service for side effects.
   Reads across modules go through each module's public *query* service only.
4. **The fuzzer is a pure library** (`src/modules/fuzzer/`) — the existing TS port of dnstwist from
   `Reporting/src/modules/wsd-scanner-worker/utils/dnstwist-fuzzer.util.ts` plus the dictionaries in
   `Reporting/dictionaries/`, copied in and covered by parity tests.
5. **Scoring rules** are ported from `Reporting/.../services/rule-configs/` (10 rules, DB-configurable
   points) — results land in the `analytics` table.
6. **Three extra tables (approved)** — `scans` (makes "trigger scan via API" trackable) and
   `rule_configs` + `scoring_thresholds` (scoring configurable without a deploy). See §3.2.
7. Separate **API** and **worker** entrypoints from day one (same codebase), so screenshot/WHOIS
   capacity scales independently of the API.
8. **`analytics` = rule-scoring results per scanned domain per scan** (an append-only time series).
   Dashboard aggregates are computed from it (§7.4); they are not stored in it.
9. **Every relationship is a real foreign key** with a named constraint, an explicit `ON DELETE` /
   `ON UPDATE` action and a supporting index. No "id stored as a plain string" columns (§3.3).

---

## 1. Architecture

```
            ┌──────────────── API process (main.ts) ────────────────┐
 Client ───▶│ /api/v1  ApiKeyGuard · Throttler · ValidationPipe      │
            │ original-domains · scans · scanned-domains · reviews … │
            └───────────┬───────────────────────────────▲────────────┘
                        │ enqueue (BullMQ)              │ read
                        ▼                               │
   Redis (requirepass) ─┬─ scan-orchestrator ─┐   PostgreSQL
                        ├─ dns-resolve        │        ▲
                        ├─ whois              │        │ tx + events
                        ├─ screenshot ────────┼──▶ Selenium Grid (hub + chrome nodes)
                        ├─ analytics          │        │
                        └─ scan-finalize      │   Object storage (S3 / MinIO) ◀─ PNGs
            ┌───────────── Worker process(es) (worker.main.ts) ─────┐
            │ processors per queue, concurrency + rate limits        │
            └────────────────────────────────────────────────────────┘
```

### 1.1 Scan pipeline

1. **Trigger** — `POST /api/v1/scans` (or a scheduler tick) → `ScansService.create()` writes a
   `scans` row (`QUEUED`) in a transaction → after-commit `scan.created` → listener enqueues
   `scan-orchestrator` with `jobId = scan:<originalDomainId>` (dedupes concurrent scans of the same domain).
2. **Fuzz** — orchestrator loads the original domain, runs `DnstwistFuzzer.generate()` (typically
   5k–60k permutations depending on enabled fuzzers and `tlds.dict`), updates `scans.permutationsTotal`,
   then uses a **BullMQ FlowProducer**: parent `scan-finalize`, children = `dns-resolve` batches of
   500 permutations. The parent runs only when every child has finished.
3. **Resolve** — each batch resolves A / AAAA / MX / NS with `dns.promises.Resolver` against a
   configured nameserver pool (per-lookup timeout, `p-limit` concurrency). Registered permutations
   (any A/AAAA/NS record) are **bulk-upserted** into `scanned_domains` in one transaction per batch
   → after-commit `scanned-domain.discovered` (new) / `scanned-domain.updated` (changed DNS).
4. **Enrich** (event-driven, parallel):
   - `scanned-domain.discovered|updated` → `WhoisListener` enqueues `whois` (RDAP first, port-43 fallback).
   - `scanned-domain.discovered` with A/AAAA → `ScreenshotListener` enqueues `screenshot`.
   - `whois-information.created` → `AnalyticsListener` enqueues `analytics` (scoring needs domain age).
5. **Score** — `analytics` worker evaluates the 10 rules → inserts an `analytics` row and updates
   `scanned_domains.risk_score / threat_level` in one transaction → `analytics.computed`; when the
   level becomes `HIGH_RISK` it also emits `alert.high-risk` (hook for notifications, §12).
6. **Finalize** — `scan-finalize` aggregates counts (`registered`, `new`, `failed`), marks
   `COMPLETED`/`FAILED`, and flags domains not seen in this scan → `scan.completed`.

### 1.2 Cross-process events (important)

`@nestjs/event-emitter` is **in-process**. Because workers run in separate processes, every
event that must cross the process boundary is turned into a **BullMQ job** by a listener running
where the event was emitted (that's what steps 1 and 4 do). Phase 3 replaces this with a
**transactional outbox** (an `outbox_events` row written inside the same transaction plus a relay),
so no after-commit event can be lost if a process crashes between commit and enqueue (§11).

---

## 2. Project structure

```
fuzzer-scanner/
├── src/
│   ├── main.ts                       # API bootstrap (prefix, swagger, pipes, winston)
│   ├── worker.main.ts                # Worker bootstrap (no HTTP; WORKER_QUEUES selects processors)
│   ├── app.module.ts / worker.module.ts
│   ├── register-paths.ts
│   ├── common/
│   │   ├── constants/                # API_PREFIX, QUEUE_NAMES, EVENT_NAMES
│   │   ├── decorators/               # @Public, @ApiPaginatedResponse
│   │   ├── dto/                      # PaginationQueryDto, PaginatedResponseDto
│   │   ├── events/                   # BaseEvent, BeforeEvent/AfterEvent, TransactionalEventBus
│   │   ├── filters/                  # AllExceptionsFilter (uniform error body)
│   │   ├── guards/                   # ApiKeyGuard
│   │   ├── interceptors/             # LoggingInterceptor (duration, status)
│   │   └── utils/                    # chunk, sleep, retry
│   ├── config/
│   │   ├── configuration.ts
│   │   └── validation.schema.ts      # Joi — REDIS_PASSWORD required, etc.
│   ├── database/
│   │   ├── prisma/{schema.prisma, seed.ts, migrations/}
│   │   ├── generated/prisma/         # Prisma 7 client output
│   │   ├── prisma.module.ts
│   │   └── prisma.service.ts         # runInTransaction(work, opts)
│   ├── logger/
│   │   ├── logger.module.ts          # WinstonModule.forRootAsync
│   │   ├── winston.config.ts         # formats, transports, redaction
│   │   └── request-context.ts        # AsyncLocalStorage: requestId / jobId / scanId
│   ├── redis/
│   │   ├── redis.module.ts           # ioredis factory (password, username, TLS, db index)
│   │   └── redis.health.ts
│   ├── queue/
│   │   ├── queue.module.ts           # BullModule.forRootAsync (shared authenticated connection)
│   │   ├── queue.constants.ts
│   │   └── flow.service.ts           # FlowProducer wrapper
│   ├── storage/
│   │   ├── storage.module.ts         # StorageService interface
│   │   └── s3.storage.ts             # S3 / MinIO (only implementation)
│   ├── integrations/
│   │   └── threat-feed/              # ThreatFeedClient (service account, token cache, breaker)
│   ├── health/                       # Terminus: db, redis, selenium grid, storage
│   └── modules/
│       ├── fuzzer/                   # pure library — no DB, no Nest deps in core
│       │   ├── dnstwist-fuzzer.ts    # ported from Reporting
│       │   ├── dictionaries/         # abused_tlds.dict, english.dict, tlds.dict, wordlist.txt, tld_names.dat
│       │   ├── dictionary.loader.ts
│       │   ├── word-splitter.ts      # wordninja-style splitter for englishsplit/wordswap
│       │   └── fuzzer.service.ts     # Nest wrapper: options → Permutation[]
│       ├── dns-resolver/             # DnsResolverService + dns-resolve.processor
│       ├── rules/                    # BaseRule + 10 rules + RuleEngineService + rule_configs repo
│       ├── scans/                    # (recommended table) trigger, orchestrator, finalize processors
│       ├── original-domains/
│       ├── scanned-domains/
│       ├── whois-informations/       # RdapClient, WhoisClient, parser, whois.processor
│       ├── screenshots/              # SeleniumDriverFactory, screenshot.processor, phash
│       ├── reviews/
│       ├── analytics/                # analytics.processor, summary/trends queries
│       └── retention/                # 31-day purge scheduler + orphan sweep (no table of its own)
│   (each table module:)
│       ├── <name>.module.ts
│       ├── <name>.controller.ts
│       ├── <name>.service.ts         # writes: transactions + events
│       ├── <name>.query.service.ts   # read-only, safe to inject cross-module
│       ├── dto/
│       ├── events/<name>.events.ts
│       ├── listeners/                # reactions to other modules' events
│       ├── processors/               # BullMQ WorkerHost (worker process only)
│       └── *.spec.ts
├── test/                             # e2e (supertest), jest-e2e.json
├── docker/                           # selenium grid, minio, redis.conf
├── docker-compose.yml
├── Dockerfile                        # multi-stage: api + worker targets
├── .env.example
└── PLAN.md
```

---

## 3. Database (PostgreSQL + Prisma)

### 3.1 Conventions

- **Primary keys**: every table has a single-column `id UUID` primary key, generated by the database
  (`DEFAULT gen_random_uuid()`, built into PG 13+), and the constraint is named `pk_<table>`.
- **Foreign keys**: every relationship is a real FK column of type `UUID` with a named constraint
  `fk_<table>_<column>`, an explicit `ON DELETE` and `ON UPDATE CASCADE`, and **an index on the FK column**.
  Postgres does not index FKs automatically; without these indexes, joins and cascading deletes do sequential scans.
- Prisma `relationMode` stays at the default `"foreignKeys"`, so constraints are enforced by Postgres, not emulated by Prisma.
- `snake_case` tables/columns via `@map`/`@@map`; `created_at`/`updated_at` (`TIMESTAMPTZ(3)`) everywhere.
- Soft delete (`deleted_at`) on user-managed entities (`original_domains`, `scanned_domains`). History
  tables (`whois_informations`, `analytics`, `reviews`, `screenshots`) are append-only.
- Domains are stored **ASCII/punycode** (`domain`) plus the human form (`unicode_domain`).
- Schema at `src/database/prisma/schema.prisma`, configured by `prisma.config.ts` (same as `threat-feed`).

### 3.2 Schema

Constraint names are pinned with `map:` so the generated SQL, the migration test (§3.3) and
error handling (e.g. mapping `P2003` on `fk_reviews_scanned_domain_id`) all refer to the same names.

```prisma
generator client {
  provider = "prisma-client"
  output   = "../generated/prisma"
}
datasource db { provider = "postgresql" }

enum ScanStatus       { QUEUED FUZZING RESOLVING ENRICHING COMPLETED FAILED CANCELLED }
enum ScanTrigger      { API SCHEDULE RESCAN }
enum DomainStatus     { NEW ACTIVE PARKED INACTIVE UNDER_REVIEW CONFIRMED_THREAT FALSE_POSITIVE TAKEN_DOWN ALLOWLISTED }
enum ThreatLevel      { UNSCORED LOW_RISK MEDIUM_RISK HIGH_RISK }
enum ScreenshotStatus { PENDING CAPTURED FAILED SKIPPED }
enum WhoisSource      { RDAP WHOIS }
enum ReviewVerdict    { MALICIOUS SUSPICIOUS BENIGN FALSE_POSITIVE NEEDS_INFO }

/// Brands/domains the customer owns and wants monitored.
model OriginalDomain {
  id             String    @id(map: "pk_original_domains") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  domain         String    @unique(map: "uq_original_domains_domain")   // ASCII / punycode
  unicodeDomain  String    @map("unicode_domain")
  label          String?
  isActive       Boolean   @default(true) @map("is_active")
  scanSchedule   String?   @map("scan_schedule")                        // cron; null = manual only
  scanOptions    Json      @default("{}") @map("scan_options")
  lastScannedAt  DateTime? @map("last_scanned_at") @db.Timestamptz(3)
  scans          Scan[]
  scannedDomains ScannedDomain[]
  deletedAt      DateTime? @map("deleted_at") @db.Timestamptz(3)
  createdAt      DateTime  @default(now()) @map("created_at") @db.Timestamptz(3)
  updatedAt      DateTime  @updatedAt @map("updated_at") @db.Timestamptz(3)

  @@map("original_domains")
}

/// One row per scan run — what the trigger API returns and polls.
model Scan {
  id                String         @id(map: "pk_scans") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  originalDomainId  String         @map("original_domain_id") @db.Uuid
  originalDomain    OriginalDomain @relation(fields: [originalDomainId], references: [id], onDelete: Cascade, onUpdate: Cascade, map: "fk_scans_original_domain_id")
  status            ScanStatus     @default(QUEUED)
  triggeredBy       ScanTrigger    @default(API) @map("triggered_by")
  options           Json           @default("{}")
  permutationsTotal Int            @default(0) @map("permutations_total")
  resolvedCount     Int            @default(0) @map("resolved_count")
  registeredCount   Int            @default(0) @map("registered_count")
  newCount          Int            @default(0) @map("new_count")
  failedCount       Int            @default(0) @map("failed_count")
  errorMessage      String?        @map("error_message")
  idempotencyKey    String?        @unique(map: "uq_scans_idempotency_key") @map("idempotency_key")
  startedAt         DateTime?      @map("started_at") @db.Timestamptz(3)
  finishedAt        DateTime?      @map("finished_at") @db.Timestamptz(3)
  analytics         Analytics[]
  screenshots       Screenshot[]
  lastSeenDomains   ScannedDomain[] @relation("ScannedDomainLastScan")
  createdAt         DateTime       @default(now()) @map("created_at") @db.Timestamptz(3)
  updatedAt         DateTime       @updatedAt @map("updated_at") @db.Timestamptz(3)

  @@index([originalDomainId, createdAt(sort: Desc)], map: "ix_scans_original_domain_id_created_at")
  @@index([status], map: "ix_scans_status")
  @@index([createdAt], map: "ix_scans_created_at")                       // retention sweep
  @@map("scans")
}

/// A registered permutation of an original domain.
model ScannedDomain {
  id                String         @id(map: "pk_scanned_domains") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  originalDomainId  String         @map("original_domain_id") @db.Uuid
  originalDomain    OriginalDomain @relation(fields: [originalDomainId], references: [id], onDelete: Cascade, onUpdate: Cascade, map: "fk_scanned_domains_original_domain_id")
  lastScanId        String?        @map("last_scan_id") @db.Uuid
  lastScan          Scan?          @relation("ScannedDomainLastScan", fields: [lastScanId], references: [id], onDelete: SetNull, onUpdate: Cascade, map: "fk_scanned_domains_last_scan_id")
  domain            String                                               // ASCII / punycode
  unicodeDomain     String         @map("unicode_domain")
  fuzzer            String
  dnsA              String[]       @map("dns_a")
  dnsAaaa           String[]       @map("dns_aaaa")
  dnsMx             String[]       @map("dns_mx")
  dnsNs             String[]       @map("dns_ns")
  dnsTtl            Int?           @map("dns_ttl")
  status            DomainStatus   @default(NEW)
  riskScore         Int            @default(0) @map("risk_score")
  threatLevel       ThreatLevel    @default(UNSCORED) @map("threat_level")
  tags              String[]
  firstSeenAt       DateTime       @default(now()) @map("first_seen_at") @db.Timestamptz(3)
  lastSeenAt        DateTime       @default(now()) @map("last_seen_at") @db.Timestamptz(3)
  whoisInformations WhoisInformation[]
  screenshots       Screenshot[]
  reviews           Review[]
  analytics         Analytics[]
  deletedAt         DateTime?      @map("deleted_at") @db.Timestamptz(3)
  createdAt         DateTime       @default(now()) @map("created_at") @db.Timestamptz(3)
  updatedAt         DateTime       @updatedAt @map("updated_at") @db.Timestamptz(3)

  @@unique([originalDomainId, domain], map: "uq_scanned_domains_original_domain_id_domain") // also serves the FK index
  @@index([lastScanId], map: "ix_scanned_domains_last_scan_id")
  @@index([threatLevel, riskScore(sort: Desc)], map: "ix_scanned_domains_threat_level_risk_score")
  @@index([status], map: "ix_scanned_domains_status")
  @@index([lastSeenAt], map: "ix_scanned_domains_last_seen_at")
  @@map("scanned_domains")
}

/// WHOIS/RDAP snapshots (append-only; latest = max(fetched_at)).
model WhoisInformation {
  id                String        @id(map: "pk_whois_informations") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  scannedDomainId   String        @map("scanned_domain_id") @db.Uuid
  scannedDomain     ScannedDomain @relation(fields: [scannedDomainId], references: [id], onDelete: Cascade, onUpdate: Cascade, map: "fk_whois_informations_scanned_domain_id")
  source            WhoisSource
  registrar         String?
  registrantOrg     String?       @map("registrant_org")
  registrantCountry String?       @map("registrant_country")
  abuseEmail        String?       @map("abuse_email")
  emails            String[]
  nameServers       String[]      @map("name_servers")
  statuses          String[]
  dnssec            String?
  whoisServer       String?       @map("whois_server")
  createdDate       DateTime?     @map("created_date") @db.Timestamptz(3)
  updatedDate       DateTime?     @map("updated_date") @db.Timestamptz(3)
  expiresDate       DateTime?     @map("expires_date") @db.Timestamptz(3)
  rawText           String?       @map("raw_text")
  parseSucceeded    Boolean       @default(true) @map("parse_succeeded")
  fetchedAt         DateTime      @default(now()) @map("fetched_at") @db.Timestamptz(3)
  createdAt         DateTime      @default(now()) @map("created_at") @db.Timestamptz(3)

  @@index([scannedDomainId, fetchedAt(sort: Desc)], map: "ix_whois_informations_scanned_domain_id_fetched_at")
  @@index([fetchedAt], map: "ix_whois_informations_fetched_at")          // retention sweep
  @@map("whois_informations")
}

/// Website captures via Selenium; the image lives in S3/MinIO under storage_key.
model Screenshot {
  id                   String           @id(map: "pk_screenshots") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  scannedDomainId      String           @map("scanned_domain_id") @db.Uuid
  scannedDomain        ScannedDomain    @relation(fields: [scannedDomainId], references: [id], onDelete: Cascade, onUpdate: Cascade, map: "fk_screenshots_scanned_domain_id")
  scanId               String?          @map("scan_id") @db.Uuid
  scan                 Scan?            @relation(fields: [scanId], references: [id], onDelete: SetNull, onUpdate: Cascade, map: "fk_screenshots_scan_id")
  status               ScreenshotStatus @default(PENDING)
  storageBucket        String?          @map("storage_bucket")
  storageKey           String?          @unique(map: "uq_screenshots_storage_key") @map("storage_key")
  mimeType             String?          @map("mime_type")
  sizeBytes            Int?             @map("size_bytes")
  width                Int?
  height               Int?
  requestedUrl         String           @map("requested_url")
  finalUrl             String?          @map("final_url")
  httpStatus           Int?             @map("http_status")
  pageTitle            String?          @map("page_title")
  perceptualHash       String?          @map("perceptual_hash")
  similarityToOriginal Float?           @map("similarity_to_original")
  errorMessage         String?          @map("error_message")
  capturedAt           DateTime?        @map("captured_at") @db.Timestamptz(3)
  createdAt            DateTime         @default(now()) @map("created_at") @db.Timestamptz(3)
  updatedAt            DateTime         @updatedAt @map("updated_at") @db.Timestamptz(3)

  @@index([scannedDomainId, createdAt(sort: Desc)], map: "ix_screenshots_scanned_domain_id_created_at")
  @@index([scanId], map: "ix_screenshots_scan_id")
  @@index([createdAt], map: "ix_screenshots_created_at")                // retention sweep
  @@map("screenshots")
}

/// Analyst decisions. A review may change the scanned domain's status (via event).
model Review {
  id              String        @id(map: "pk_reviews") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  scannedDomainId String        @map("scanned_domain_id") @db.Uuid
  scannedDomain   ScannedDomain @relation(fields: [scannedDomainId], references: [id], onDelete: Cascade, onUpdate: Cascade, map: "fk_reviews_scanned_domain_id")
  verdict         ReviewVerdict
  notes           String?
  reviewer        String         // API-key name (v1 auth has no users table — becomes an FK when users exist)
  previousStatus  DomainStatus   @map("previous_status")
  newStatus       DomainStatus   @map("new_status")
  createdAt       DateTime       @default(now()) @map("created_at") @db.Timestamptz(3)

  @@index([scannedDomainId, createdAt(sort: Desc)], map: "ix_reviews_scanned_domain_id_created_at")
  @@map("reviews")
}

/// Rule-engine scoring results per scanned domain per scan (append-only time series).
model Analytics {
  id                  String        @id(map: "pk_analytics") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  scannedDomainId     String        @map("scanned_domain_id") @db.Uuid
  scannedDomain       ScannedDomain @relation(fields: [scannedDomainId], references: [id], onDelete: Cascade, onUpdate: Cascade, map: "fk_analytics_scanned_domain_id")
  scanId              String?       @map("scan_id") @db.Uuid
  scan                Scan?         @relation(fields: [scanId], references: [id], onDelete: SetNull, onUpdate: Cascade, map: "fk_analytics_scan_id")
  totalScore          Int           @map("total_score")
  threatLevel         ThreatLevel   @map("threat_level")
  ruleResults         Json          @map("rule_results")    // [{ key, matched, condition, value, points }]
  levenshteinDistance Int?          @map("levenshtein_distance")
  domainAgeDays       Int?          @map("domain_age_days")
  sslStatus           String?       @map("ssl_status")
  dmarcPolicy         String?       @map("dmarc_policy")
  hasMx               Boolean?      @map("has_mx")
  spamhausListed      Boolean?      @map("spamhaus_listed")
  reputationHit       Boolean?      @map("reputation_hit")
  computedAt          DateTime      @default(now()) @map("computed_at") @db.Timestamptz(3)

  @@index([scannedDomainId, computedAt(sort: Desc)], map: "ix_analytics_scanned_domain_id_computed_at")
  @@index([scanId], map: "ix_analytics_scan_id")
  @@index([threatLevel, computedAt], map: "ix_analytics_threat_level_computed_at")
  @@index([computedAt], map: "ix_analytics_computed_at")                // retention sweep
  @@map("analytics")
}

/// DB-configurable scoring — seeded from Reporting's 20260831010000_seed_rule_configs.
model RuleConfig {
  id        String   @id(map: "pk_rule_configs") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  key       String   @unique(map: "uq_rule_configs_key")
  name      String
  enabled   Boolean  @default(true)
  points    Json     // [{ condition, points }]
  params    Json     @default("{}")
  createdAt DateTime @default(now()) @map("created_at") @db.Timestamptz(3)
  updatedAt DateTime @updatedAt @map("updated_at") @db.Timestamptz(3)
  @@map("rule_configs")
}

model ScoringThreshold {
  id                  String   @id(map: "pk_scoring_thresholds") @default(dbgenerated("gen_random_uuid()")) @db.Uuid
  key                 String   @unique(map: "uq_scoring_thresholds_key")   // "global_score"
  thresholdMediumRisk Int      @map("threshold_medium_risk")
  thresholdLowRisk    Int      @map("threshold_low_risk")
  createdAt           DateTime @default(now()) @map("created_at") @db.Timestamptz(3)
  updatedAt           DateTime @updatedAt @map("updated_at") @db.Timestamptz(3)
  @@map("scoring_thresholds")
}
```

**Relationship map**

```
original_domains 1──* scans
original_domains 1──* scanned_domains *──0..1 scans (last_scan_id)
scanned_domains  1──* whois_informations
scanned_domains  1──* screenshots *──0..1 scans
scanned_domains  1──* reviews
scanned_domains  1──* analytics   *──0..1 scans
rule_configs, scoring_thresholds   (standalone configuration)
```

### 3.3 Migrations — primary & foreign keys

Migrations are generated with `prisma migrate dev --create-only`, **reviewed by hand** (constraint
names, referential actions, indexes) and committed. `prisma migrate deploy` applies them in CI and
production. Never use `db push` outside a throwaway local database.

**Migration set**

| # | Migration | Contents |
|---|---|---|
| 1 | `0001_init_enums` | All enum types (PostgreSQL ≥ 13 required for built-in `gen_random_uuid()`) |
| 2 | `0002_core_tables` | `original_domains`, `scans`, `scanned_domains` with PKs, uniques and FKs |
| 3 | `0003_enrichment_tables` | `whois_informations`, `screenshots`, `reviews`, `analytics` with PKs and FKs |
| 4 | `0004_scoring_config` | `rule_configs`, `scoring_thresholds` + seed rows (from Reporting) |
| 5 | `0005_indexes` | every FK-supporting and query index listed in §3.2 |

**Primary keys**: every table is `id UUID NOT NULL DEFAULT gen_random_uuid()` with
`CONSTRAINT pk_<table> PRIMARY KEY (id)`.

**Foreign keys**: all FKs, their referential actions and the index that backs each one:

| Constraint | Column → references | ON DELETE | ON UPDATE | Backing index | Why |
|---|---|---|---|---|---|
| `fk_scans_original_domain_id` | `scans.original_domain_id → original_domains.id` | CASCADE | CASCADE | `ix_scans_original_domain_id_created_at` | Scans have no meaning without their domain |
| `fk_scanned_domains_original_domain_id` | `scanned_domains.original_domain_id → original_domains.id` | CASCADE | CASCADE | `uq_scanned_domains_original_domain_id_domain` (leading column) | Look-alikes belong to one brand |
| `fk_scanned_domains_last_scan_id` | `scanned_domains.last_scan_id → scans.id` | SET NULL | CASCADE | `ix_scanned_domains_last_scan_id` | Retention may delete old scans; the domain stays |
| `fk_whois_informations_scanned_domain_id` | `whois_informations.scanned_domain_id → scanned_domains.id` | CASCADE | CASCADE | `ix_whois_informations_scanned_domain_id_fetched_at` | History of the domain |
| `fk_screenshots_scanned_domain_id` | `screenshots.scanned_domain_id → scanned_domains.id` | CASCADE | CASCADE | `ix_screenshots_scanned_domain_id_created_at` | History of the domain (S3 objects deleted by a listener, §6a) |
| `fk_screenshots_scan_id` | `screenshots.scan_id → scans.id` | SET NULL | CASCADE | `ix_screenshots_scan_id` | Keep capture if scan row expires |
| `fk_reviews_scanned_domain_id` | `reviews.scanned_domain_id → scanned_domains.id` | CASCADE | CASCADE | `ix_reviews_scanned_domain_id_created_at` | Decisions belong to the domain |
| `fk_analytics_scanned_domain_id` | `analytics.scanned_domain_id → scanned_domains.id` | CASCADE | CASCADE | `ix_analytics_scanned_domain_id_computed_at` | Scores belong to the domain |
| `fk_analytics_scan_id` | `analytics.scan_id → scans.id` | SET NULL | CASCADE | `ix_analytics_scan_id` | Keep score if scan row expires |

Hard deletes are rare because user-facing deletes are soft (`deleted_at`). The CASCADE rules exist so
that an admin purge or a retention sweep can never leave orphaned rows.

**Excerpt of the reviewed SQL** (`0002_core_tables` / `0003_enrichment_tables`):

```sql
CREATE TABLE "scans" (
  "id"                 UUID         NOT NULL DEFAULT gen_random_uuid(),
  "original_domain_id" UUID         NOT NULL,
  "status"             "ScanStatus" NOT NULL DEFAULT 'QUEUED',
  -- … remaining columns …
  "created_at"         TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at"         TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "pk_scans" PRIMARY KEY ("id"),
  CONSTRAINT "fk_scans_original_domain_id" FOREIGN KEY ("original_domain_id")
    REFERENCES "original_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "analytics" (
  "id"                UUID          NOT NULL DEFAULT gen_random_uuid(),
  "scanned_domain_id" UUID          NOT NULL,
  "scan_id"           UUID,
  "total_score"       INTEGER       NOT NULL,
  "threat_level"      "ThreatLevel" NOT NULL,
  "rule_results"      JSONB         NOT NULL,
  -- … remaining columns …
  "computed_at"       TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "pk_analytics" PRIMARY KEY ("id"),
  CONSTRAINT "fk_analytics_scanned_domain_id" FOREIGN KEY ("scanned_domain_id")
    REFERENCES "scanned_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "fk_analytics_scan_id" FOREIGN KEY ("scan_id")
    REFERENCES "scans" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
CREATE INDEX "ix_analytics_scanned_domain_id_computed_at" ON "analytics" ("scanned_domain_id", "computed_at" DESC);
CREATE INDEX "ix_analytics_scan_id" ON "analytics" ("scan_id");
```

**Order & safety**
- Tables are created parent → child (`original_domains` → `scans` → `scanned_domains` → enrichment)
  so every FK target exists before it is referenced. The `down` path (a documented rollback script)
  drops tables child → parent.
- Later migrations that add a FK to a large existing table use `ADD CONSTRAINT … NOT VALID` followed by
  `VALIDATE CONSTRAINT` in a separate statement, and `CREATE INDEX CONCURRENTLY` (in its own
  non-transactional migration), to avoid long locks.
- Seeds (`seed.ts`) insert parents before children and use `upsert` keyed on natural uniques
  (`original_domains.domain`, `rule_configs.key`), so re-running a seed is safe.

**Migration verification test** (`test/migrations.e2e-spec.ts`, runs in CI on a fresh Testcontainers Postgres):
1. `prisma migrate deploy` from empty, then `prisma migrate diff --from-migrations … --to-schema-datamodel …
   --exit-code` must report **no drift** between migrations and `schema.prisma`.
2. Query `information_schema.table_constraints` and assert **every table has a `PRIMARY KEY`** named `pk_<table>`.
3. Query `pg_constraint` for `contype = 'f'` and assert the **exact set of 9 FKs** above, with their
   `confdeltype` (`c` = cascade, `n` = set null) and `confupdtype`.
4. Assert **every FK column is the leading column of some index** (`pg_index` join).
5. Behavioural checks: inserting a `scan` with a random `original_domain_id` fails with `23503`;
   deleting an `original_domain` cascades to scans, scanned domains and their children; deleting a
   `scan` nulls `scanned_domains.last_scan_id` and `analytics.scan_id`.

**Error mapping**: Prisma `P2003` (FK violation) becomes `400 Bad Request` with a message derived
from the constraint name (`fk_reviews_scanned_domain_id` → "scanned domain does not exist");
`P2002` (unique) becomes `409 Conflict`.

**Volume note**: with 31-day retention (§6a) the history tables stay bounded, so declarative
partitioning is not needed in v1. Batched deletes on the `*_created_at` / `*_computed_at` /
`*_fetched_at` indexes are enough. Bulk DNS upserts use
`INSERT … ON CONFLICT (original_domain_id, domain) DO UPDATE … RETURNING (xmax = 0) AS inserted`.

---

## 4. Transactions & events

### 4.1 Pattern (every write)

```ts
// common/events/transactional-event-bus.ts
async write<T>(spec: {
  before: BaseEvent;                     // emitted with emitAsync — a listener may throw to veto
  work: (tx: Prisma.TransactionClient, after: AfterEvents) => Promise<T>;
  isolationLevel?: Prisma.TransactionIsolationLevel;
}): Promise<T> {
  await this.events.emitAsync(spec.before.name, spec.before);          // 1. before (validation/enrichment, no writes)
  const after = new AfterEvents();
  const result = await this.prisma.$transaction(tx => spec.work(tx, after), {
    isolationLevel: spec.isolationLevel ?? 'ReadCommitted', timeout: 15_000,
  });                                                                  // 2. commit
  for (const e of after.drain()) this.events.emit(e.name, e);         // 3. after — only post-commit
  return result;
}
```

- Before events never write to the database; after events are never emitted inside the transaction.
- Listeners are idempotent (keyed by entity id + version), because retries can re-deliver.
- Event payloads carry ids plus minimal fields, never whole rows, so they stay small and stable.

### 4.2 Event catalogue

| Module | Before | After | Main listeners |
|---|---|---|---|
| original-domains | `original-domain.before-create/update/delete` | `original-domain.created/updated/deleted` | scans (register/remove scheduled scan) |
| scans | `scan.before-create` (dedupe/rate-limit) | `scan.created`, `scan.status-changed`, `scan.completed`, `scan.failed` | queue (enqueue orchestrator), original-domains (`last_scanned_at`) |
| scanned-domains | `scanned-domain.before-upsert/update` | `scanned-domain.discovered`, `.updated`, `.status-changed`, `.deleted` | whois, screenshots, analytics (rescore on DNS change) |
| whois-informations | `whois-information.before-create` | `whois-information.created` | analytics (score with domain age) |
| screenshots | `screenshot.before-create` | `screenshot.captured`, `screenshot.failed` | analytics (visual similarity, phase 3) |
| analytics | `analytics.before-create` | `analytics.computed`, `alert.high-risk` | scanned-domains (risk_score/threat_level), notifications (phase 3) |
| reviews | `review.before-create` (verdict→status transition check) | `review.created` | scanned-domains (status update), threat-feed push (§10a) |
| retention | `retention.before-purge` | `retention.purged` | screenshots (S3 object cleanup), metrics |

Names live in `common/constants/event-names.ts`; payload classes live in each module's `events/` folder.

---

## 5. Queues (BullMQ)

| Queue | Producer | Job data | Concurrency (per worker) | Limits / retry |
|---|---|---|---|---|
| `scan-orchestrator` | `scan.created` listener, scheduler | `{ scanId }` | 2 | jobId `scan:<originalDomainId>` dedupe; 3 attempts, exp backoff |
| `dns-resolve` | orchestrator (Flow children) | `{ scanId, originalDomainId, permutations[500] }` | 8 | 3 attempts; per-lookup timeout 3s |
| `scan-finalize` | Flow parent | `{ scanId }` | 2 | runs when all children finish (`failParentOnFailure: false`) |
| `whois` | scanned-domain listener | `{ scannedDomainId, domain }` | 4 | **limiter** 5/s global + per-TLD group; 5 attempts, backoff 30s → 10m |
| `screenshot` | scanned-domain listener, API recapture | `{ scannedDomainId, url }` | = Grid node slots | 2 attempts; job timeout 60s |
| `analytics` | whois listener, API rescore | `{ scannedDomainId, scanId? }` | 8 | 3 attempts |
| `scheduler` | repeatable (`upsertJobScheduler`) per original domain | `{ originalDomainId }` | 1 | cron from `scan_schedule` |
| `threat-feed-push` | `review.created` listener (MALICIOUS / FALSE_POSITIVE) | `{ scannedDomainId, verdict }` | 2 | 5 attempts, backoff 1m → 30m (§10a) |
| `retention` | daily job scheduler 03:30 UTC + admin trigger | `{ cutoff, tables[] }` | 1 | jobId per day (no overlap); resumable (§6a) |

- `removeOnComplete: { age: 86400, count: 5000 }`, `removeOnFail: { age: 7 * 86400 }`.
- Failed jobs past their final attempt are logged with full context and counted in `scans.failed_count`.
- Graceful shutdown: `worker.close()` on SIGTERM so in-flight jobs finish or return to the queue.
- `WORKER_QUEUES=dns-resolve,whois` (env) picks which processors a worker process runs. This is what lets you scale per queue.
- Optional: Bull Board at `/api/v1/admin/queues` behind the admin API key.

---

## 6. Redis (password required)

- **Env**: `REDIS_HOST`, `REDIS_PORT`, `REDIS_USERNAME` (ACL user, optional), **`REDIS_PASSWORD` (required)**,
  `REDIS_TLS` (bool), `REDIS_QUEUE_DB=0`, `REDIS_CACHE_DB=1`.
- **Validation** (Joi): `REDIS_PASSWORD` required in every environment, minimum 16 characters
  when `NODE_ENV=production`. Startup fails fast with a clear message if it is missing.
- **Single connection factory** (`redis.module.ts`) builds ioredis options `{ host, port, username, password, tls, db,
  maxRetriesPerRequest: null, enableReadyCheck: true }`. BullMQ, cache, health check and rate
  limiter all use it, so no client can connect without authentication.
- **docker-compose**: `redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes`; the health check uses
  `redis-cli -a "$REDIS_PASSWORD" --no-auth-warning ping`. Production: ACL file with a dedicated
  `fuzzer` user limited to `~bull:* ~cache:*` keys and no `FLUSHALL/CONFIG`.
- Passwords and connection strings are **redacted by the Winston formatter** (§8).

---

## 6a. Data retention (31 days)

`RETENTION_DAYS=31` (env, validated 1–365). A `retention` BullMQ job scheduler runs daily at 03:30 UTC
(`RetentionModule`, worker process). The run is idempotent and resumable: it deletes in batches and
can safely be re-run or interrupted.

| Data | Rule | Notes |
|---|---|---|
| `scans` | Delete finished scans (`COMPLETED/FAILED/CANCELLED`) whose `created_at` is older than 31 days | FKs `SET NULL` on `scanned_domains.last_scan_id`, `analytics.scan_id`, `screenshots.scan_id` (§3.3) |
| `analytics` | Delete rows with `computed_at` older than 31 days, **except the latest row per scanned domain** | Keeps the current score visible for domains not rescanned recently |
| `whois_informations` | Delete rows with `fetched_at` older than 31 days, **except the latest per scanned domain** | |
| `screenshots` + S3 objects | Delete rows with `created_at` older than 31 days, **except the latest `CAPTURED` per scanned domain**. The S3 object is deleted first, then the row | If S3 deletion fails the row is kept and retried on the next run, so nothing is orphaned |
| Soft-deleted `original_domains` / `scanned_domains` | Hard-purged 31 days after `deleted_at` | Children go via `ON DELETE CASCADE`; their S3 keys are collected **before** the purge and deleted |
| BullMQ job records | `removeOnComplete.age` 1 day, `removeOnFail.age` 7 days | Well inside 31 days |
| Log files (when `LOG_TO_FILE=true`) | `winston-daily-rotate-file` `maxFiles: '31d'` | |
| **Kept indefinitely** | `original_domains`, `scanned_domains` (current state), `reviews` (audit trail), `rule_configs`, `scoring_thresholds` | Reviews are analyst decisions and the audit trail; tell me if they should expire too |

`RETENTION_KEEP_LATEST=true` (default) controls the "keep the latest row per domain" exception.
Set it to `false` for a strict 31-day cut-off.

**Mechanics**
- Deletes run in batches of 5,000 (`DELETE … WHERE id IN (SELECT id … ORDER BY … LIMIT 5000)`), one
  short transaction per batch, using the `ix_*_created_at / computed_at / fetched_at` indexes (§3.2).
  This avoids long locks and table bloat spikes.
- Events: `retention.before-purge` (per table, carries cutoff and batch size) and `retention.purged`
  (counts per table) after each committed batch. Prometheus counter `retention_rows_purged_total{table}`.
- A weekly orphan sweep lists `screenshots/` in the bucket and removes objects whose key has no row.
  It is a backstop only.
- Admin endpoints: `GET /api/v1/admin/retention` (last run, counts, next run) and
  `POST /api/v1/admin/retention/run` (manual trigger, admin API key).

---

## 6b. Object storage (S3 / MinIO)

- `StorageService` interface with one implementation, `S3StorageService` (`@aws-sdk/client-s3`
  v3 + `@aws-sdk/s3-request-presigner`). MinIO in dev and compose; S3, or any S3-compatible store, in production.
- **Env**: `S3_ENDPOINT` (MinIO only), `S3_REGION`, `S3_BUCKET=fuzzer-screenshots`,
  `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_FORCE_PATH_STYLE=true` (MinIO), `S3_SIGNED_URL_TTL=300`.
- **Key layout**: `screenshots/{originalDomainId}/{scannedDomainId}/{screenshotId}.png`. The key is unique
  (`uq_screenshots_storage_key`) and deterministic, so a retried upload overwrites rather than duplicating.
- **Security**: private bucket (block public access), SSE-S3 encryption, least-privilege credentials
  (`s3:PutObject/GetObject/DeleteObject/ListBucket` on this bucket only). Images are served only via
  `GET /screenshots/:id/image` → 302 to a 5-minute presigned URL.
- **Upload order**: upload the object, then commit the row in a transaction (`screenshot.captured`
  after commit). If the transaction fails, the object is deleted in a compensating step.
- Health: `HeadBucket` in `/health`. Compose: `minio` + a `minio-init` job (`mc mb`, private policy).

---

## 7. API (prefix `api/v1`, Swagger `/api/docs`)

**Auth (v1, confirmed): API key.** All routes require `x-api-key` (global `ApiKeyGuard`; keys are
stored as SHA-256 hashes in the secret store, each with a name and scope `read` / `write` / `admin`)
except `/health`. The key name is recorded as `reviews.reviewer`. JWT/RBAC shared with `threat-feed` is a
phase 5 option. Global `ValidationPipe({ whitelist, forbidNonWhitelisted, transform })`, `@nestjs/throttler`,
uniform errors `{ statusCode, message, error, path, timestamp, requestId }`. Lists use
`?page&limit&sort&order` and return `{ data, total, page, limit }`.

### 7.1 Trigger scans

| Method | Path | Notes |
|---|---|---|
| POST | `/scans` | `{ originalDomainId \| domain, options?: { fuzzers?, includeWhois?, includeScreenshots? } }` → `202 { scanId, status }`. `Idempotency-Key` header supported; returns the existing scan if one is already active for the domain |
| GET | `/scans` | filter `originalDomainId`, `status`, date range |
| GET | `/scans/:id` | progress: status, counts, % (resolved / permutationsTotal) |
| POST | `/scans/:id/cancel` | removes pending children, marks `CANCELLED` |
| POST | `/original-domains/:id/scans` | shortcut trigger |

### 7.2 Original domains

`POST /original-domains` (IDN normalised to punycode, PSL-validated) · `GET /original-domains` ·
`GET /original-domains/:id` (with latest scan + counts per threat level) · `PATCH /original-domains/:id`
(schedule, options, active) · `DELETE /original-domains/:id` (soft).

### 7.3 Manage scanned domains

| Method | Path | Notes |
|---|---|---|
| GET | `/scanned-domains` | filters: `originalDomainId`, `threatLevel[]`, `status[]`, `fuzzer[]`, `minScore`, `hasMx`, `firstSeenFrom/To`, `search` (domain contains) |
| GET | `/scanned-domains/:id` | includes latest whois, latest screenshot, latest analytics, reviews |
| PATCH | `/scanned-domains/:id` | `status`, `tags` (transition rules enforced in the before event) |
| PATCH | `/scanned-domains/bulk` | `{ ids[], status?, tags? }` (one transaction) |
| DELETE | `/scanned-domains/:id` | soft delete |
| POST | `/scanned-domains/:id/rescan` | re-resolve, then WHOIS, screenshot, analytics |
| POST | `/scanned-domains/:id/screenshots` | recapture |
| POST | `/scanned-domains/:id/whois/refresh` | |
| GET | `/scanned-domains/export?format=csv\|json\|stix` | streamed |

### 7.4 Sub-resources

- **Screenshots**: `GET /scanned-domains/:id/screenshots`, `GET /screenshots/:id`, `GET /screenshots/:id/image` (302 to a short-lived signed URL).
- **WHOIS**: `GET /scanned-domains/:id/whois` (history), `GET /whois-informations/:id`.
- **Reviews**: `POST /scanned-domains/:id/reviews` `{ verdict, notes }`, `GET /scanned-domains/:id/reviews`, `GET /reviews` (queue view).
- **Analytics**: `GET /scanned-domains/:id/analytics`, `GET /analytics/summary?originalDomainId` (counts per threat level/status/fuzzer), `GET /analytics/trends?interval=day` (new registrations and high-risk over time).
- **Rules**: `GET /rule-configs`, `PATCH /rule-configs/:key` (admin).
- **Health**: `GET /health` (db, redis, selenium grid `/status`, S3 bucket, threat-feed reachability).
- **Admin**: `GET /admin/retention`, `POST /admin/retention/run`, Bull Board `/admin/queues` (admin scope).

---

## 8. Logging (Winston)

- `nest-winston` replaces the Nest logger (`bufferLogs: true` then `app.useLogger(...)`) in both API and workers.
- **Formats**: production uses JSON (`timestamp`, `level`, `message`, `context`, `requestId`, `jobId`, `scanId`, `durationMs`); development uses colourised `nestLike`.
- **Transports**: Console always; `winston-daily-rotate-file` (`maxFiles: '31d'`, gzip — matches the retention policy) when `LOG_TO_FILE=true`. Production ships stdout to the log stack (Loki/ELK).
- **Correlation**: `AsyncLocalStorage` context set by HTTP middleware (`x-request-id`, generated if absent) and by a `WorkerHost` base class (jobId, queue, scanId). A custom format injects it into every line.
- **Redaction format**: masks `password`, `authorization`, `x-api-key`, `REDIS_PASSWORD`, `DATABASE_URL`, `S3_SECRET_ACCESS_KEY`, `THREAT_FEED_PASSWORD`, `token`/`accessToken` keys at any depth.
- **What is logged**: HTTP access (method, route, status, duration), job lifecycle (active/completed/failed with attempts), scan milestones, external call failures (WHOIS server, Grid) at `warn` with target and latency. Per-permutation DNS logs are kept at `debug` only, so a 50k-permutation scan doesn't flood the logs.

---

## 9. Screenshots (Selenium)

- **Driver**: `selenium-webdriver` → **Selenium Grid 4** (`selenium/hub` + `selenium/node-chrome`, or
  `standalone-chrome` in dev). `SeleniumDriverFactory` builds a fresh session per job with headless
  Chrome, window 1366×768, `--disable-gpu --no-sandbox --disable-dev-shm-usage`, downloads disabled,
  insecure certs accepted (phishing sites often have bad TLS), page-load timeout 20s, script timeout 10s.
- **Flow**: try `https://`, fall back to `http://`. Record final URL, title and status. Status comes
  from the BiDi network events where available; otherwise a `HEAD` probe via axios. Take a
  full-viewport PNG, compute size and pHash with `sharp`, upload to S3/MinIO through `StorageService` (§6b), then
  update the row in a transaction and emit `screenshot.captured`. The session is always quit in `finally`.
- **Safety**: nodes run in an isolated network namespace with egress-only access, no credentials, and an
  ephemeral container filesystem. Never run the browser inside the API process.
- **Why Selenium**: Grid gives horizontal scaling and per-node isolation out of the box, and KEDA has a
  Selenium Grid scaler. The trade-off is that Playwright is lighter and faster per capture. The
  `ScreenshotDriver` interface keeps the engine swappable; Playwright is a drop-in alternative implementation.

---

## 10. Scoring rules (ported)

`RuleEngineService.score(input, ctx)` loads `rule_configs` and `scoring_thresholds` once per batch
(cached in Redis for 60s, invalidated on `rule-config.updated`) and evaluates:

| Key | Signal | Default points |
|---|---|---|
| `levenshtein_distance` | Damerau-Levenshtein to the original | 10 (distance ≤ 4) |
| `suspicious_tld` | TLD in configured list (`.tk`, `.xyz`, `.top`, …) | 15 |
| `ssl_issues` | missing / expired / self-signed / untrusted / invalid | 10 |
| `dmarc_missing` | DMARC missing / `none` / `quarantine` | 15 |
| `domain_age` | created ≤ 30 days ago (WHOIS) | 20 |
| `reputation_check` | domain, or its first IPv4, is an active indicator curated in **manage-feed** (threat-feed API, §10a) | 40 |
| `mx_records_found` | MX present (can send phishing email) | 15 |
| `dns_resolves` | resolves to an IP | 10 |
| `low_ttl` | TTL ≤ 300s (fast-flux) | 15 |
| `spamhaus_blacklist` | listed in Spamhaus DBL/ZEN | 10 |

The total score maps to `LOW/MEDIUM/HIGH_RISK` via `scoring_thresholds`. Each rule is a `BaseRule`
subclass with its own unit tests. Seed data is copied from
`Reporting/.../migrations/20260831010000_seed_rule_configs`. The `reputation_check` row's
`params` changes from the OpenCTI URL to `{ "provider": "threat-feed" }`.

---

## 10a. Integration with manage-feed / threat-feed (confirmed)

**manage-feed** is the Next.js console, and its indicators are stored in the **threat-feed** API.
manage-feed's gateway only accepts browser sessions (httpOnly cookie), so service-to-service calls
go **directly to the threat-feed API**, behind manage-feed, with a dedicated service account. The data
is the same either way.

1. **Reputation lookups (inbound)** — `ThreatFeedClient` (`@nestjs/axios`):
   - Signs in as a **service user** (`THREAT_FEED_URL`, `THREAT_FEED_EMAIL`, `THREAT_FEED_PASSWORD`, from the
     secret store) on a threat-feed role restricted to `GET /feeds` and `POST /feeds`. The JWT is cached in
     memory and refreshed before `exp` (tokens are 15 minutes); a `401` triggers one re-login and a retry.
   - Lookup: `GET /feeds?type=DOMAIN&search=<domain>&isActive=true&limit=100`, then an exact match on
     `value` client-side. **Recommended threat-feed change:** expose its existing cached
     `findByValue` as `GET /feeds/lookup?value=&type=` (one indexed query on the `(value, type)` unique).
   - Results are cached in Redis (`cache:reputation:<domain>`, 1 hour; 10 minutes for misses), so a scan does
     not hammer threat-feed. A circuit breaker (opossum) means a threat-feed outage makes the
     rule return "unknown" (0 points) instead of failing the analytics job.
2. **Confirmed threats (outbound)** — on `review.created` with verdict `MALICIOUS`, a listener enqueues
   `threat-feed-push`. The worker upserts the domain into threat-feed as a `DOMAIN` indicator
   (source `Fuzzer Scanner`, severity mapped from `threat_level`, tags `typosquat`, `fuzzer:<technique>`,
   `brand:<original>`). The indicator then appears in manage-feed's Indicators page. A `FALSE_POSITIVE`
   verdict deactivates it there. Idempotent: lookup first, then `POST` or `PATCH`.
3. **Console (manage-feed UI, phase 3)** — add `fuzzer-scanner` as a **second upstream** in manage-feed's
   gateway policy (`/api/gw/lookalikes/*` → `FUZZER_SCANNER_URL`). The gateway injects the
   `x-api-key` server-side and checks the user's threat-feed permissions before forwarding. New pages
   (Original domains, Look-alikes, Review queue) reuse the manage-feed design system.

---

## 11. Testing

- **Unit (Vitest)**, with Prisma and external clients mocked via `vi.fn` / `vi.spyOn`:
  - every service: happy path, not-found, before-event veto, **after events emitted only after the transaction resolves** (and never on rollback)
  - fuzzer: per-technique fixtures plus **parity snapshots** against Python dnstwist output for 3 reference domains (simple `.com`, multi-label `.co.uk`, IDN TLD `.de`)
  - each of the 10 rules: every tier, the disabled case and missing signals
  - processors: success, retryable failure, final failure updating counts
  - DNS resolver: timeout, NXDOMAIN, SERVFAIL, nameserver rotation
  - WHOIS parser: fixtures for common registrars plus RDAP JSON
  - Selenium: `ScreenshotDriver` mocked; URL fallback and cleanup-on-error
- **Coverage gate**: 80% lines / 75% branches on `src/modules/**` (excluding DTOs/modules), enforced in CI.
- **e2e** (`test/*.e2e-spec.ts`): Testcontainers Postgres + Redis (with password) cover the trigger API, scan status polling with mocked DNS, scanned-domain filtering and paging, review → status change, auth (missing or wrong API key), and validation errors.
- **Migrations** (§3.3): no drift; a PK on every table; the exact FK set with referential actions;
  every FK column indexed; behavioural cascade / set-null checks.
- **Retention**: seeded rows either side of the 31-day cutoff, keep-latest exception, S3 delete-before-row
  ordering, resume after interruption.
- **Integrations**: `ThreatFeedClient` (token refresh on 401, cache hit/miss, breaker open) and
  `S3StorageService` (MinIO via Testcontainers in e2e).
- **Contract**: Swagger JSON snapshot test so API changes are deliberate.

---

## 12. DevOps

- **docker-compose (dev)**: `postgres:16`, `redis:7` with `requirepass`, `selenium/standalone-chrome` (or hub + 2 nodes), `minio` + `minio-init` (bucket + private policy), plus `api` and `worker` services from the same image with different commands.
- **Dockerfile**: multi-stage (`deps` → `build` → `runtime`), non-root, `prisma generate` at build time, `HEALTHCHECK` on `/api/v1/health`; targets `api` and `worker`.
- **Migrations**: `prisma migrate deploy` runs as a one-off release job before rollout, never on app boot. CI also runs the migration verification test (§3.3) against a fresh database.
- **CI (GitHub Actions)**: install → `prisma validate` and `generate` → lint → typecheck → unit tests with coverage → e2e (service containers) → build image → Trivy scan → push.
- **Config**: all env validated by Joi at boot; secrets (DB URL, Redis password, API keys, S3) come from the secret manager. `.env.example` documents every variable.
- **Observability**: Winston JSON to Loki/ELK; `@willsoto/nestjs-prometheus` metrics (queue depth, job duration, DNS lookup latency, capture success rate, scans by status); alerts on failed-job rate and queue lag.

---

## 13. Scale-up recommendations

| Concern | Recommendation |
|---|---|
| Independent scaling | Separate deployments per queue group (`dns`, `whois`, `screenshot`, `analytics`). Use **KEDA** to autoscale on BullMQ queue length, and the Selenium Grid scaler for browser nodes |
| DNS throughput | Self-hosted recursive resolvers (Unbound) close to workers. Rotate a nameserver pool; cache NXDOMAIN in Redis (6–24h TTL) so rescans skip known-dead permutations; on rescan, resolve **previously registered** domains first |
| WHOIS rate limits | BullMQ group rate limiting per TLD/WHOIS server; prefer RDAP; cache per registered domain for 7 days unless forced |
| Database | PgBouncer; batch upserts (500/tx); 31-day retention keeps history tables bounded (partitioning only if a single month exceeds ~50M rows); read replica for list/summary endpoints; materialised view for `/analytics/summary` refreshed on `scan.completed` |
| Reliability | **Transactional outbox** (`outbox_events` + relay) for cross-process events; idempotent listeners; dead-letter queue with replay endpoint |
| Large scans | Stream permutations from a generator instead of materialising 60k strings; let users pick fuzzer subsets per original domain (`scan_options.fuzzers`) |
| Storage | Retention job deletes objects after 31 days (§6a); dedupe identical captures by pHash (skip the upload when the hash equals the previous capture's) |
| Multi-tenancy | Add `organizations` + `organization_id` on `original_domains`, with scoping in a Prisma extension, before onboarding the second customer |

## 14. Feature expansion ideas

1. ✅ **Certificate Transparency monitoring** — consume a CT log stream (certstream / crt.sh) and match
   new certificates against original domains using fuzzy/Levenshtein matching. This catches look-alikes the fuzzer never generates.
2. **Newly-registered-domain feeds** — match daily zone or NRD feeds against brand keywords.
3. ✅ **Visual similarity** — pHash and CLIP embeddings compared against a screenshot of the original
   site, plus favicon-hash and logo matching. Feeds a new `visual_similarity` rule.
4. ◐ **Content analysis** (login forms, brand mentions, third-party form targets; kit fingerprinting open) — detect login forms, brand keywords, credential-harvest kits and redirects to the real site.
5. **Change detection between scans** — DNS, WHOIS and screenshot diffs, with alerts when a parked domain goes live (Reporting already has a `change-detection.util` to port).
6. ✅ **Alerting** — webhooks, Slack and email on `alert.high-risk`, with per-original-domain subscriptions and digest mode.
7. **Threat-intel exports** — STIX 2.1 / TAXII export of confirmed look-alikes; OpenCTI as an additional
   reputation provider behind the same interface as threat-feed. (Push to threat-feed and the manage-feed
   console are now in core scope, §10a.)
8. **Takedown workflow** — abuse contact from WHOIS/RDAP, a templated report and status tracking (`TAKEN_DOWN`).
9. **Allowlist** — customer-owned look-alikes are suppressed automatically (`ALLOWLISTED`).
10. ✅ **Auth upgrade** — JWT/RBAC shared with threat-feed so console users act under their own identity (replaces API-key reviewer names).
11. **Enrichment** — GeoIP/ASN, hosting provider, HTTP/SMTP banners, passive DNS history.

---

## 15. Delivery plan (project management)

| Phase | Scope | Estimate | Done when |
|---|---|---|---|
| **0. Foundation** ✅ | Nest scaffold, config + Joi, Winston, Prisma schema + **reviewed migrations with named PKs/FKs** + seed, migration verification test, Redis (auth) + BullMQ, ApiKeyGuard, Swagger, health, compose (Postgres, Redis, MinIO, Selenium), CI | 4–5 d | `GET /api/v1/health` is green with authenticated Redis and the bucket; migration test passes in CI |
| **1. Fuzzer + scans** ✅ | Port fuzzer + dictionaries + parity tests; `original-domains`, `scans` modules; orchestrator, DNS resolve, finalize; transactional event bus | 5–6 d | `POST /scans` discovers registered permutations for a test domain end to end |
| **2. Enrichment** ✅ | `whois-informations` (RDAP + WHOIS), `screenshots` (Selenium Grid + S3/MinIO), `rules` + `analytics`, `ThreatFeedClient` reputation lookup | 7–9 d | Every discovered domain gets whois, screenshot and a score; reputation hits come from manage-feed indicators |
| **3. Review & manage** ✅ | `scanned-domains` management APIs (filters, bulk, export), `reviews`, status transitions, push of confirmed threats to threat-feed, manage-feed gateway upstream + Look-alikes pages | 6–8 d | A `MALICIOUS` review shows up as an indicator in manage-feed; analyst workflow covered by e2e |
| **4. Hardening** ✅ | 31-day retention job + orphan sweep, coverage ≥ 80%, outbox, rate limits, metrics, load test at the sizing target (§16), runbook | 5–6 d | Retention verified on seeded data; load-test SLOs met; dashboards and alerts live |
| **5. Expansion** ✅ (items 1, 3, 4, 6, 10) | Pick from §14 by priority (suggested: alerting → CT monitoring → visual similarity → JWT/RBAC) | per item | — |
| **6. Console investigation & polish** ✅ | OpenCTI-style investigation in manage-feed (Tailwind kept): infrastructure graph, activity timeline, brand overview; accent presets; style guide + docs | 3–4 d | Analysts pivot from a look-alike to shared infrastructure and its history; every new view is specified in the style guide |

**Phase 0 status (2026-10-02): done.** `GET /api/v1/health` is green against Postgres, password-
protected Redis, the private MinIO bucket and Selenium Grid; the migration verification suite passes;
`npm run check` (typecheck, lint, format, 58 unit tests, coverage 98.8% lines / 89% branches) and
`npm run test:e2e` (19 tests on real containers) pass; `npm audit` reports 0 vulnerabilities.

**Phase 1 status (2026-10-02): done.** `POST /scans` discovers registered look-alikes end to end
(live check: `paypal.com`, 219 permutations from 6 techniques → 136 registered; e2e suite with a
stubbed resolver covers subset/full scans, INACTIVE marking, revival, cancellation, idempotency and
concurrent triggers). Notes on what was built beyond / differently from the outline:
- Fuzzer output is **byte-identical** to Reporting's implementation on 5 reference domains (parity fixture).
- Migration `0006`: `scanned_domains.dns_errors` and the partial unique index
  `uq_scans_active_original_domain` (Prisma `partialIndexes` preview; predicate stored in Postgres's
  canonical form so the drift check stays exact).
- Scheduled scans (per-domain BullMQ job schedulers, reconciled at API start-up) landed here rather than later.
- A read-only `GET /scanned-domains` (filters, sorting) was pulled forward to verify discovery; the
  management writes (PATCH/bulk/export) remain Phase 3.

**Phase 2 status (2026-10-02): done.** Live check against real DNS, RDAP/WHOIS, Selenium Grid,
MinIO and a running threat-feed (`paypal.com`, 108 look-alikes): every look-alike has WHOIS and a
score; resolving ones have screenshots; reputation hits came from manage-feed indicators (one DOMAIN,
one IPV4 — which also flagged three other look-alikes on the same parking IP). Enrichment e2e suite
covers the full chain with stubbed network edges. Notes:
- **Scan status vs enrichment:** `COMPLETED` means discovery finished; enrichment is per domain and
  asynchronous (`ENRICHING` is unused). Periodic re-scoring of unchanged domains (e.g. domain age
  crossing 30 days) is a Phase 4 item.
- **Deliberate deviations from Reporting:** reputation checks the domain *and* its IPv4 in threat-feed;
  Spamhaus `127.255.255.x` (query refused, e.g. via public resolvers) is "unknown", not "listed".
- **Bugs found and fixed:** TLS `authorizationError` is a string at runtime (inherited from Reporting —
  self-signed/expired/untrusted were never detected); MinIO rejected the unconditional SSE header
  (now `S3_SSE`, default bucket encryption); `@OnEvent([a, b])` registers one namespaced event in
  wildcard mode — schedule sync on domain create/update (Phase 1) and rule-cache invalidation never
  fired. Fixed with one decorator per event and a wiring test through the real event subsystem.

**Risks**: DNS and WHOIS rate limiting or blocking (mitigated by own resolvers, RDAP and backoff);
browser exposure to malicious sites (isolated Grid, no secrets on nodes); permutation explosion
(fuzzer subsets, streaming, NXDOMAIN cache); event loss across processes (outbox in phase 4).

---

**Phase 3 status (2026-10-02): done.** Live check with a disposable threat-feed, fuzzer-scanner (API +
worker) and manage-feed in a browser: on the Phase 2 `paypal.com` data, an analyst opened `paysal.com` in
*Look-alikes*, recorded a `MALICIOUS` verdict, and the domain appeared under manage-feed *Indicators*
moments later (source "Fuzzer Scanner", Critical, confidence 95, provenance tags). The review was
attributed to the signed-in user. The new `analyst-workflow` e2e suite covers review → status → push →
retire, bulk/atomic transitions, tags, CSV/STIX export, rescan, soft delete and actor attribution
against a stub threat-feed. `npm run check`: 385 unit tests; `npm run test:e2e`: 37 tests. Notes:
- **Push trigger:** the push runs on `scanned-domain.status-changed` rather than only on `review.created`.
  That way a manual `PATCH` to `CONFIRMED_THREAT` publishes too, and leaving that status retires the
  indicator. A repeated `MALICIOUS` review re-publishes (e.g. after someone deactivated it in manage-feed).
- **Severity:** `high`, or `critical` when the score is HIGH_RISK. An analyst-confirmed threat is never
  below `high`.
- **Service role** now also needs `PATCH /feeds/*` and `GET`/`POST /sources` (or `THREAT_FEED_SOURCE_ID`).
- **Gateway path:** `/api/lookalikes/*` in manage-feed, separate from `/api/gw/*`, so the threat-feed
  allowlist stays untouched. Access maps onto threat-feed roles: reads need `GET /feeds`, writes need `POST /feeds`.
- **Bulk atomicity:** status and tag changes are each all-or-nothing, and a rejected status change aborts
  before any tag is written. They are two transactions, not one.
- **`GET /scanned-domains/:id`** returns the brand name. WHOIS, screenshots, scores and reviews stay
  sub-resources (the console loads them in parallel).
- **Outbox** stays in Phase 4 (§15). After-commit events are still in-process.
- **Bugs found and fixed:** `DnsResolverModule` was imported but missing from the worker's module
  `imports`, so the rescan processor would have failed DI in the worker. manage-feed's route matcher
  didn't protect the new pages, and login cached a session without `integrations`.

**Phase 4 status (2026-10-02): done.**
- **Retention verified on seeded data.** The `retention` e2e seeds rows and MinIO objects on both sides of the
  31-day cutoff and checks exactly what is removed and what is kept: keep-latest, S3 deletes before rows, the
  soft-delete purge, idempotent re-runs and the orphan sweep. It was also run live through the admin API.
- **Load-test SLOs met.** `load/` runs hermetically: stub DNS, stub RDAP modelled per registry, nothing sent
  to the internet. 10 brands × ~42k permutations = **422,917 lookups → 6,361 registered**:

  | | Result | SLO |
  |---|---|---|
  | Discovery (10 concurrent full scans, 1 worker) | slowest scan **46 s** | ≤ 2 h |
  | WHOIS + score for all 6,361 look-alikes | **2 h 28 min** | ≤ 6 h |
  | API p95 while saturated (list / summary / scans, 19.5k samples each) | 25 / 12 / 8 ms | ≤ 500 ms |

  WHOIS is bounded by registry limits, not by our capacity. `.com`/`.net` (73% of look-alikes) is held
  at 8 requests / 11 s per egress IP, about 2,600 per hour (RUNBOOK §3). Results:
  `load/results/load-2026-10-02T11-40-47-275Z.json`.
- **Dashboards and alerts live.** `docker compose --profile observability`: Prometheus scrapes API and worker,
  13 alert rules are loaded, the Grafana dashboard *Fuzzer Scanner* has 29 panels, and Alertmanager is wired.
  It was verified by stopping a worker: `FuzzerTargetDown` (critical) fired after 2 minutes and reached
  Alertmanager.
- **Outbox (§1.2).** `outbox_events` (migration 0007) holds every after-commit event and is written in the
  producing transaction. The producer delivers right after commit; a relay in each process role redelivers
  what a crashed process left behind, using `SKIP LOCKED` leases, exponential backoff and dead letters.
  Crash recovery is covered by e2e.
- **Rate limits.** API budgets are tracked per API key (not per IP), plus a stricter per-route budget for
  expensive endpoints.
- **Coverage.** 91.9% lines / 79.7% branches. The gate is ratcheted to 85 / 77.
- **Runbook.** `docs/RUNBOOK.md` covers every alert, routine operations, scaling and `scripts/queues.mjs`.
- **Found by the load test and fixed.** WHOIS head-of-line blocking: `.com` jobs waiting for the registry
  window held every worker slot, so other registries got **0** lookups (all 268 completed in the first
  6 minutes were `.com`). Waiters now give up their slot: jobs are re-parked as delayed, with no attempt used,
  and spread out. Throughput went from 0.74/s to 2.2/s. The 5-minute spread cap left a slow tail (the last
  ~230 lookups took 45 minutes), so it is now 60 s. The SSL rule now connects to the address the pipeline
  resolved (it used to go through the system resolver), and the RDAP bootstrap URL is configurable.
- **Not done here:** PgBouncer, KEDA autoscaling and a read replica remain deployment choices (§13). Screenshot
  capacity scales with Selenium Grid nodes and was not part of the load test.

**Phase 5 status (2026-10-02): done for the selected items** (alerting → CT monitoring → visual similarity
→ shared JWT/RBAC, §14 #6, #1, #3, #4, #10).
- **Alerting (#6).** Migration 0008 adds `alert_channels`, `alert_subscriptions` and `alert_deliveries`. Slack,
  e-mail and HMAC-signed webhooks are supported. Subscriptions are per brand (or all brands) × events
  (HIGH_RISK, CONFIRMED_THREAT, NEW_LOOKALIKE, WENT_LIVE) × minimum risk × immediate or daily digest.
  Targets and secrets are AES-256-GCM encrypted. The SSRF guard checks targets on save and on every send.
  Deliveries go through the outbox, each subscription alerts once per look-alike, event and day, and 4xx
  answers fail at once. The manage-feed *Alerts* page is included. Verified live: signed webhooks were
  received and verified, and viewers are denied.
- **CT monitoring (#1).** A certstream-compatible stream is consumed by one leader across workers (Redis
  lease, reconnect with backoff, stall watchdog). The matcher detects typos (Damerau–Levenshtein over a
  homoglyph and confusable skeleton, including Cyrillic and Greek), TLD swaps, keyword combos and
  brand-in-subdomain. Matches are de-duplicated for 7 days, resolved, and tracked as `ct:<kind>` look-alikes
  through the normal pipeline. **Full scans also re-resolve CT finds**, so liveness tracking and INACTIVE
  marking work for them as well.
- **Visual similarity and content (#3, #4).** Migration 0009 adds `brand_references` and screenshot
  `favicon_hash` / `page_signals`, and seeds two rules (`visual_similarity`, `phishing_content`). Signals are
  collected inside the browser session (no worker-side fetches of attacker URLs). Look-alikes are rescored
  on new captures and on reference changes.
- **Shared auth (#10).** threat-feed gains `GET /auth/me` (`@SelfService`: any authenticated user, own data
  only). fuzzer-scanner accepts threat-feed user tokens (HS256 verified locally; identity and role from
  `/auth/me`, cached ≤ 60 s). manage-feed forwards the analyst's own token by default (`FUZZER_SCANNER_AUTH=jwt`),
  so no gateway service key or `x-acting-user` is needed. Verified live: review attributed to the user,
  viewer gets 403, tampered token gets 401.
- **Found and fixed along the way:**
  - A manual rescan of a look-alike whose last scan had been purged by retention wrote
    `scan_id = 'rescan'` into UUID FK columns, so enrichment failed. Events now carry `scanId: undefined`.
    Regression test added.
  - The Phase 4 WHOIS fix spread re-parked jobs over up to 5 minutes. The cap is now 60 s.
- **Not done:** #2 NRD feeds, #5 change-detection diffs, #7 TAXII / OpenCTI, #8 takedown workflow, #9
  automatic allowlist, #11 GeoIP / ASN enrichment, and credential-kit fingerprinting (#4).

**Phase 6 status (2026-10-03): done.** The console stays on Tailwind (decided 2026-10-03: a
Bootstrap port would rewrite 87 components with no visible gain).
- **fuzzer-scanner:** migration 0010 adds GIN indexes on `dns_a`, `dns_ns` and `dns_mx`. A read-only
  `insights` module serves two endpoints:
  - `GET /scanned-domains/:id/related` returns the infrastructure graph: brand, IPs, nameservers, mail
    servers, registrar, and up to 12 look-alikes per shared node, plus a `sharedBy` count.
  - `GET /scanned-domains/:id/timeline` merges discovery, WHOIS, captures, risk-band changes, reviews
    and alerts.
- **manage-feed:**
  - The look-alike page gains an **Infrastructure** card: a radial SVG graph with no new dependency,
    keyboard-accessible, hover tracing, a screen-reader table, and a shared-infrastructure list. It also
    gains an **Activity** timeline.
  - New **brand overview** page (`/brands/:id`): KPIs, a 30-day trend, a technique bar list, the
    riskiest undecided look-alikes, the brand reference and recent scans.
  - **Accent presets:** indigo, violet, fuchsia and graphite next to cyan. All are WCAG AA in both
    themes (minimum 6.1:1) and avoid status hues. Users switch under Settings → Appearance, with no flash
    on load.
  - The style guide gains an *Investigation* section and a presets entry; `docs/STYLE_GUIDE.md` §2.6 and
    §8a and `docs/THEMING.md` are updated.
- **Verification:** style guide specimens checked in the browser (layout, hover tracing, timeline, preset
  switching and persistence). The graph, timeline and brand pages haven't been exercised against live data
  yet: the dev `.env` Redis password was changed on 2026-10-03 and no longer matches the local Redis
  container.

## 16. Decisions (resolved 2026-10-02)

| # | Question | Decision | Where |
|---|---|---|---|
| 1 | Meaning of `analytics` | Rule-scoring results per scanned domain per scan (time series) | §0.8, §3.2 |
| 2 | Extra tables | `scans`, `rule_configs`, `scoring_thresholds` approved | §3.2 |
| 3 | Auth | API key for v1; JWT/RBAC shared with threat-feed deferred to phase 5 | §7 |
| 4 | Screenshot storage | S3 / MinIO | §6b |
| 5 | Reputation source | Indicators curated in manage-feed (threat-feed API); confirmed threats pushed back | §10a |
| 6 | Scale target | Plan sizing accepted. **Working target:** up to 10 original domains × ~50k permutations, rescanned daily; one full scan completes within 2 hours; WHOIS within 6 hours | §13, §15 phase 4 |
| 7 | Retention | 31 days for history; latest record per domain kept; reviews kept | §6a |
| — | Migrations | Every table has a named UUID PK; every relationship is a named FK with explicit actions and an index; verified by a CI test | §3.3 |

**Still worth a quick confirmation** (the plan proceeds on these defaults unless you say otherwise):
- Reviews are **kept beyond 31 days** as the audit trail, and the **latest** WHOIS/screenshot/score per domain is
  kept even when older than 31 days (`RETENTION_KEEP_LATEST=true`).
- A small threat-feed addition, `GET /feeds/lookup?value=&type=`, for exact reputation lookups (§10a).
