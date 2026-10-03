-- 0006 — Phase 1 scan pipeline guards.

-- DNS failure outcomes (SERVFAIL / TIMEOUT / DNS_EXCEPTION) from the last resolution.
-- Nullable array, no default: adding it is a metadata-only change (no table rewrite).
ALTER TABLE "scanned_domains" ADD COLUMN "dns_errors" TEXT[];

-- At most ONE in-flight scan per original domain, enforced by Postgres so two concurrent
-- POST /scans requests can never both start a scan (the loser gets 23505 and the API returns
-- the scan that won). Finished scans (COMPLETED / FAILED / CANCELLED) are not constrained.
-- Leading column = original_domain_id, so it also serves fk_scans_original_domain_id lookups
-- for active scans.
-- Predicate written in Postgres's canonical form (what pg_get_indexdef returns) so Prisma's
-- drift check compares equal; semantically: status IN ('QUEUED','FUZZING','RESOLVING','ENRICHING').
CREATE UNIQUE INDEX "uq_scans_active_original_domain" ON "scans" ("original_domain_id")
  WHERE (status = ANY (ARRAY['QUEUED'::"ScanStatus", 'FUZZING'::"ScanStatus", 'RESOLVING'::"ScanStatus", 'ENRICHING'::"ScanStatus"]));
