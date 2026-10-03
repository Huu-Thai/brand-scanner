-- 0004 — Scoring configuration + reference data.
-- Rule tiers are ported from Reporting (wsd 20260831010000_seed_rule_configs).
-- reputation_check now looks up indicators curated in manage-feed (threat-feed API).

CREATE TABLE "rule_configs" (
    "id"         UUID           NOT NULL DEFAULT gen_random_uuid(),
    "key"        TEXT           NOT NULL,
    "name"       TEXT           NOT NULL,
    "enabled"    BOOLEAN        NOT NULL DEFAULT true,
    "points"     JSONB          NOT NULL,
    "params"     JSONB          NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "pk_rule_configs" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "uq_rule_configs_key" ON "rule_configs" ("key");

CREATE TABLE "scoring_thresholds" (
    "id"                    UUID           NOT NULL DEFAULT gen_random_uuid(),
    "key"                   TEXT           NOT NULL,
    "threshold_medium_risk" INTEGER        NOT NULL DEFAULT 80,
    "threshold_low_risk"    INTEGER        NOT NULL DEFAULT 40,
    "created_at"            TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at"            TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "pk_scoring_thresholds" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "uq_scoring_thresholds_key" ON "scoring_thresholds" ("key");

INSERT INTO "scoring_thresholds" ("key", "updated_at")
VALUES ('global_score', CURRENT_TIMESTAMP)
ON CONFLICT ("key") DO NOTHING;

INSERT INTO "rule_configs" ("key", "name", "enabled", "points", "params", "updated_at") VALUES
  ('levenshtein_distance', 'Levenshtein Distance', true,
   '[{"condition": "4", "points": 10}, {"condition": "default", "points": 0}]', '{}', CURRENT_TIMESTAMP),
  ('suspicious_tld', 'Suspicious TLD', true,
   '[{"condition": "matched", "points": 15}, {"condition": "default", "points": 0}]',
   '{"tlds": [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".country", ".stream", ".download", ".loan", ".win", ".bid", ".racing", ".date", ".review", ".faith", ".science"]}',
   CURRENT_TIMESTAMP),
  ('ssl_issues', 'SSL Issues', true,
   '[{"condition": "missing", "points": 10}, {"condition": "expired", "points": 10}, {"condition": "self-signed", "points": 10}, {"condition": "untrusted", "points": 10}, {"condition": "invalid", "points": 10}, {"condition": "default", "points": 0}]',
   '{"ca_issuers": []}', CURRENT_TIMESTAMP),
  ('dmarc_missing', 'DMARC Missing', true,
   '[{"condition": "missing", "points": 15}, {"condition": "none", "points": 15}, {"condition": "quarantine", "points": 15}, {"condition": "reject", "points": 0}, {"condition": "default", "points": 0}]',
   '{}', CURRENT_TIMESTAMP),
  ('domain_age', 'Domain Age (Days)', true,
   '[{"condition": "30", "points": 20}, {"condition": "default", "points": 0}]', '{}', CURRENT_TIMESTAMP),
  ('reputation_check', 'Reputation Check', true,
   '[{"condition": "found", "points": 40}, {"condition": "default", "points": 0}]',
   '{"provider": "threat-feed"}', CURRENT_TIMESTAMP),
  ('mx_records_found', 'MX Records Found', true,
   '[{"condition": "exist", "points": 15}, {"condition": "default", "points": 0}]', '{}', CURRENT_TIMESTAMP),
  ('dns_resolves', 'DNS Resolves', true,
   '[{"condition": "resolved_ip", "points": 10}, {"condition": "default", "points": 0}]', '{}', CURRENT_TIMESTAMP),
  ('low_ttl', 'Low TTL (Seconds)', true,
   '[{"condition": "300", "points": 15}, {"condition": "default", "points": 0}]', '{}', CURRENT_TIMESTAMP),
  ('spamhaus_blacklist', 'Blacklisted (Spamhaus)', true,
   '[{"condition": "listed", "points": 10}, {"condition": "default", "points": 0}]', '{}', CURRENT_TIMESTAMP)
ON CONFLICT ("key") DO NOTHING;
