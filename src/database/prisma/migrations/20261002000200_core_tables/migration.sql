-- 0002 — Core tables, created parent → child so every FK target already exists.
--   original_domains (root)
--   scans            → original_domains
--   scanned_domains  → original_domains, scans (last_scan_id)

CREATE TABLE "original_domains" (
    "id"              UUID           NOT NULL DEFAULT gen_random_uuid(),
    "domain"          TEXT           NOT NULL,
    "unicode_domain"  TEXT           NOT NULL,
    "label"           TEXT,
    "is_active"       BOOLEAN        NOT NULL DEFAULT true,
    "scan_schedule"   TEXT,
    "scan_options"    JSONB          NOT NULL DEFAULT '{}',
    "last_scanned_at" TIMESTAMPTZ(3),
    "deleted_at"      TIMESTAMPTZ(3),
    "created_at"      TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"      TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "pk_original_domains" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "uq_original_domains_domain" ON "original_domains" ("domain");

CREATE TABLE "scans" (
    "id"                 UUID           NOT NULL DEFAULT gen_random_uuid(),
    "original_domain_id" UUID           NOT NULL,
    "status"             "ScanStatus"   NOT NULL DEFAULT 'QUEUED',
    "triggered_by"       "ScanTrigger"  NOT NULL DEFAULT 'API',
    "options"            JSONB          NOT NULL DEFAULT '{}',
    "permutations_total" INTEGER        NOT NULL DEFAULT 0,
    "resolved_count"     INTEGER        NOT NULL DEFAULT 0,
    "registered_count"   INTEGER        NOT NULL DEFAULT 0,
    "new_count"          INTEGER        NOT NULL DEFAULT 0,
    "failed_count"       INTEGER        NOT NULL DEFAULT 0,
    "error_message"      TEXT,
    "idempotency_key"    TEXT,
    "started_at"         TIMESTAMPTZ(3),
    "finished_at"        TIMESTAMPTZ(3),
    "created_at"         TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"         TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "pk_scans" PRIMARY KEY ("id"),
    CONSTRAINT "fk_scans_original_domain_id" FOREIGN KEY ("original_domain_id")
        REFERENCES "original_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "uq_scans_idempotency_key" ON "scans" ("idempotency_key");

CREATE TABLE "scanned_domains" (
    "id"                 UUID           NOT NULL DEFAULT gen_random_uuid(),
    "original_domain_id" UUID           NOT NULL,
    "last_scan_id"       UUID,
    "domain"             TEXT           NOT NULL,
    "unicode_domain"     TEXT           NOT NULL,
    "fuzzer"             TEXT           NOT NULL,
    "dns_a"              TEXT[],
    "dns_aaaa"           TEXT[],
    "dns_mx"             TEXT[],
    "dns_ns"             TEXT[],
    "dns_ttl"            INTEGER,
    "status"             "DomainStatus" NOT NULL DEFAULT 'NEW',
    "risk_score"         INTEGER        NOT NULL DEFAULT 0,
    "threat_level"       "ThreatLevel"  NOT NULL DEFAULT 'UNSCORED',
    "tags"               TEXT[],
    "first_seen_at"      TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at"       TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deleted_at"         TIMESTAMPTZ(3),
    "created_at"         TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"         TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "pk_scanned_domains" PRIMARY KEY ("id"),
    CONSTRAINT "fk_scanned_domains_original_domain_id" FOREIGN KEY ("original_domain_id")
        REFERENCES "original_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    -- Retention may delete old scans; the domain keeps existing with last_scan_id = NULL.
    CONSTRAINT "fk_scanned_domains_last_scan_id" FOREIGN KEY ("last_scan_id")
        REFERENCES "scans" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
-- Also serves as the index for fk_scanned_domains_original_domain_id (leading column).
CREATE UNIQUE INDEX "uq_scanned_domains_original_domain_id_domain" ON "scanned_domains" ("original_domain_id", "domain");
