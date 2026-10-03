-- 0005 — Secondary indexes.
-- Postgres does NOT index foreign-key columns automatically. Every FK below gets an
-- index whose leading column is the FK column (checked by test/migrations.e2e-spec.ts):
--   fk_scans_original_domain_id               → ix_scans_original_domain_id_created_at
--   fk_scanned_domains_original_domain_id     → uq_scanned_domains_original_domain_id_domain (0002)
--   fk_scanned_domains_last_scan_id           → ix_scanned_domains_last_scan_id
--   fk_whois_informations_scanned_domain_id   → ix_whois_informations_scanned_domain_id_fetched_at
--   fk_screenshots_scanned_domain_id          → ix_screenshots_scanned_domain_id_created_at
--   fk_screenshots_scan_id                    → ix_screenshots_scan_id
--   fk_reviews_scanned_domain_id              → ix_reviews_scanned_domain_id_created_at
--   fk_analytics_scanned_domain_id            → ix_analytics_scanned_domain_id_computed_at
--   fk_analytics_scan_id                      → ix_analytics_scan_id
-- The *_created_at / *_computed_at / *_fetched_at indexes back the 31-day retention sweep.

-- FK-supporting indexes
CREATE INDEX "ix_scans_original_domain_id_created_at" ON "scans" ("original_domain_id", "created_at" DESC);
CREATE INDEX "ix_scanned_domains_last_scan_id" ON "scanned_domains" ("last_scan_id");
CREATE INDEX "ix_whois_informations_scanned_domain_id_fetched_at" ON "whois_informations" ("scanned_domain_id", "fetched_at" DESC);
CREATE INDEX "ix_screenshots_scanned_domain_id_created_at" ON "screenshots" ("scanned_domain_id", "created_at" DESC);
CREATE INDEX "ix_screenshots_scan_id" ON "screenshots" ("scan_id");
CREATE INDEX "ix_reviews_scanned_domain_id_created_at" ON "reviews" ("scanned_domain_id", "created_at" DESC);
CREATE INDEX "ix_analytics_scanned_domain_id_computed_at" ON "analytics" ("scanned_domain_id", "computed_at" DESC);
CREATE INDEX "ix_analytics_scan_id" ON "analytics" ("scan_id");

-- Query indexes
CREATE INDEX "ix_scans_status" ON "scans" ("status");
CREATE INDEX "ix_scanned_domains_threat_level_risk_score" ON "scanned_domains" ("threat_level", "risk_score" DESC);
CREATE INDEX "ix_scanned_domains_status" ON "scanned_domains" ("status");
CREATE INDEX "ix_scanned_domains_last_seen_at" ON "scanned_domains" ("last_seen_at");
CREATE INDEX "ix_analytics_threat_level_computed_at" ON "analytics" ("threat_level", "computed_at");

-- Retention sweep indexes (31 days)
CREATE INDEX "ix_scans_created_at" ON "scans" ("created_at");
CREATE INDEX "ix_scanned_domains_deleted_at" ON "scanned_domains" ("deleted_at");
CREATE INDEX "ix_whois_informations_fetched_at" ON "whois_informations" ("fetched_at");
CREATE INDEX "ix_screenshots_created_at" ON "screenshots" ("created_at");
CREATE INDEX "ix_analytics_computed_at" ON "analytics" ("computed_at");
