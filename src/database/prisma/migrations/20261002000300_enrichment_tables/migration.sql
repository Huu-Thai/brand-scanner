-- 0003 — Enrichment / history tables (children of scanned_domains and scans).

CREATE TABLE "whois_informations" (
    "id"                 UUID           NOT NULL DEFAULT gen_random_uuid(),
    "scanned_domain_id"  UUID           NOT NULL,
    "source"             "WhoisSource"  NOT NULL,
    "registrar"          TEXT,
    "registrant_org"     TEXT,
    "registrant_country" TEXT,
    "abuse_email"        TEXT,
    "emails"             TEXT[],
    "name_servers"       TEXT[],
    "statuses"           TEXT[],
    "dnssec"             TEXT,
    "whois_server"       TEXT,
    "created_date"       TIMESTAMPTZ(3),
    "updated_date"       TIMESTAMPTZ(3),
    "expires_date"       TIMESTAMPTZ(3),
    "raw_text"           TEXT,
    "parse_succeeded"    BOOLEAN        NOT NULL DEFAULT true,
    "fetched_at"         TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at"         TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pk_whois_informations" PRIMARY KEY ("id"),
    CONSTRAINT "fk_whois_informations_scanned_domain_id" FOREIGN KEY ("scanned_domain_id")
        REFERENCES "scanned_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "screenshots" (
    "id"                     UUID               NOT NULL DEFAULT gen_random_uuid(),
    "scanned_domain_id"      UUID               NOT NULL,
    "scan_id"                UUID,
    "status"                 "ScreenshotStatus" NOT NULL DEFAULT 'PENDING',
    "storage_bucket"         TEXT,
    "storage_key"            TEXT,
    "mime_type"              TEXT,
    "size_bytes"             INTEGER,
    "width"                  INTEGER,
    "height"                 INTEGER,
    "requested_url"          TEXT               NOT NULL,
    "final_url"              TEXT,
    "http_status"            INTEGER,
    "page_title"             TEXT,
    "perceptual_hash"        TEXT,
    "similarity_to_original" DOUBLE PRECISION,
    "error_message"          TEXT,
    "captured_at"            TIMESTAMPTZ(3),
    "created_at"             TIMESTAMPTZ(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"             TIMESTAMPTZ(3)     NOT NULL,

    CONSTRAINT "pk_screenshots" PRIMARY KEY ("id"),
    CONSTRAINT "fk_screenshots_scanned_domain_id" FOREIGN KEY ("scanned_domain_id")
        REFERENCES "scanned_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "fk_screenshots_scan_id" FOREIGN KEY ("scan_id")
        REFERENCES "scans" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "uq_screenshots_storage_key" ON "screenshots" ("storage_key");

CREATE TABLE "reviews" (
    "id"                UUID            NOT NULL DEFAULT gen_random_uuid(),
    "scanned_domain_id" UUID            NOT NULL,
    "verdict"           "ReviewVerdict" NOT NULL,
    "notes"             TEXT,
    "reviewer"          TEXT            NOT NULL,
    "previous_status"   "DomainStatus"  NOT NULL,
    "new_status"        "DomainStatus"  NOT NULL,
    "created_at"        TIMESTAMPTZ(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pk_reviews" PRIMARY KEY ("id"),
    CONSTRAINT "fk_reviews_scanned_domain_id" FOREIGN KEY ("scanned_domain_id")
        REFERENCES "scanned_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "analytics" (
    "id"                   UUID           NOT NULL DEFAULT gen_random_uuid(),
    "scanned_domain_id"    UUID           NOT NULL,
    "scan_id"              UUID,
    "total_score"          INTEGER        NOT NULL,
    "threat_level"         "ThreatLevel"  NOT NULL,
    "rule_results"         JSONB          NOT NULL,
    "levenshtein_distance" INTEGER,
    "domain_age_days"      INTEGER,
    "ssl_status"           TEXT,
    "dmarc_policy"         TEXT,
    "has_mx"               BOOLEAN,
    "spamhaus_listed"      BOOLEAN,
    "reputation_hit"       BOOLEAN,
    "computed_at"          TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pk_analytics" PRIMARY KEY ("id"),
    CONSTRAINT "fk_analytics_scanned_domain_id" FOREIGN KEY ("scanned_domain_id")
        REFERENCES "scanned_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "fk_analytics_scan_id" FOREIGN KEY ("scan_id")
        REFERENCES "scans" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
