-- 0009 — Phase 5 visual similarity & content analysis (PLAN.md §14 #3, #4).

-- What the look-alike's page contains (collected inside the browser session, never fetched by the
-- worker): password field, form targets, a text sample, and the favicon's SHA-256.
ALTER TABLE "screenshots" ADD COLUMN "favicon_hash" VARCHAR(64);
ALTER TABLE "screenshots" ADD COLUMN "page_signals" JSONB;

-- The brand's own landing page — what look-alikes are compared against. One row per brand,
-- refreshed in place (the storage key is deterministic, so the object is overwritten too).
CREATE TABLE "brand_references" (
    "id"                 UUID NOT NULL DEFAULT gen_random_uuid(),
    "original_domain_id" UUID NOT NULL,
    "status"             "ScreenshotStatus" NOT NULL,
    "storage_key"        VARCHAR(255),
    "perceptual_hash"    VARCHAR(16),
    "favicon_hash"       VARCHAR(64),
    "page_title"         TEXT,
    "final_url"          TEXT,
    "error_message"      TEXT,
    "captured_at"        TIMESTAMPTZ(3),
    "created_at"         TIMESTAMPTZ(3) NOT NULL DEFAULT now(),
    "updated_at"         TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "pk_brand_references" PRIMARY KEY ("id"),
    CONSTRAINT "fk_brand_references_original_domain_id" FOREIGN KEY ("original_domain_id")
        REFERENCES "original_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
-- Also the FK index (one reference per brand).
CREATE UNIQUE INDEX "uq_brand_references_original_domain_id" ON "brand_references" ("original_domain_id");

INSERT INTO "rule_configs" ("key", "name", "enabled", "points", "params", "updated_at") VALUES
  ('visual_similarity', 'Visual Similarity to Brand Site', true,
   '[{"condition": "identical", "points": 40}, {"condition": "similar", "points": 20}, {"condition": "default", "points": 0}]',
   '{"identicalMaxDistance": 6, "similarMaxDistance": 12}', CURRENT_TIMESTAMP),
  ('phishing_content', 'Phishing Content', true,
   '[{"condition": "credential_form", "points": 35}, {"condition": "favicon_clone", "points": 30}, {"condition": "brand_mentions", "points": 10}, {"condition": "default", "points": 0}]',
   '{}', CURRENT_TIMESTAMP);
