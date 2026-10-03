-- 0010 — Phase 6 infrastructure pivots (look-alikes sharing an IP, nameserver or mail server).
-- GIN indexes serve the array-overlap (&&) lookups behind GET /scanned-domains/:id/related.
CREATE INDEX "ix_scanned_domains_dns_a" ON "scanned_domains" USING GIN ("dns_a");
CREATE INDEX "ix_scanned_domains_dns_ns" ON "scanned_domains" USING GIN ("dns_ns");
CREATE INDEX "ix_scanned_domains_dns_mx" ON "scanned_domains" USING GIN ("dns_mx");
