-- Documented rollback for migrations 0001–0006 (drops child → parent).
-- Destroys ALL fuzzer-scanner data. Run manually only; never part of `migrate deploy`.
DROP TABLE IF EXISTS "analytics", "reviews", "screenshots", "whois_informations" CASCADE;
DROP TABLE IF EXISTS "scanned_domains", "scans", "original_domains" CASCADE;
DROP TABLE IF EXISTS "rule_configs", "scoring_thresholds" CASCADE;
DROP TYPE IF EXISTS "ReviewVerdict", "WhoisSource", "ScreenshotStatus", "ThreatLevel", "DomainStatus", "ScanTrigger", "ScanStatus";
DELETE FROM "_prisma_migrations" WHERE "migration_name" IN (
  '20261002000100_init_enums', '20261002000200_core_tables', '20261002000300_enrichment_tables',
  '20261002000400_scoring_config', '20261002000500_indexes', '20261002000600_scan_guards_and_dns_errors'
);
