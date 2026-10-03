-- 0008 — Phase 5 alerting (PLAN.md §14 #6).

CREATE TYPE "AlertChannelType" AS ENUM ('WEBHOOK', 'SLACK', 'EMAIL');
CREATE TYPE "AlertEventType" AS ENUM ('HIGH_RISK', 'NEW_LOOKALIKE', 'WENT_LIVE', 'CONFIRMED_THREAT');
CREATE TYPE "AlertMode" AS ENUM ('IMMEDIATE', 'DIGEST');
CREATE TYPE "AlertDeliveryStatus" AS ENUM ('PENDING', 'SENT', 'FAILED');

-- Where alerts go. The target (webhook / Slack URL, e-mail recipients) and the webhook signing
-- secret are stored AES-256-GCM encrypted; `target_hint` is the masked form the API shows.
CREATE TABLE "alert_channels" (
    "id"                       UUID NOT NULL DEFAULT gen_random_uuid(),
    "name"                     VARCHAR(100) NOT NULL,
    "type"                     "AlertChannelType" NOT NULL,
    "target_encrypted"         TEXT NOT NULL,
    "target_hint"              VARCHAR(200) NOT NULL,
    "signing_secret_encrypted" TEXT,
    "is_active"                BOOLEAN NOT NULL DEFAULT true,
    "created_by"               VARCHAR(254) NOT NULL,
    "created_at"               TIMESTAMPTZ(3) NOT NULL DEFAULT now(),
    "updated_at"               TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "pk_alert_channels" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "uq_alert_channels_name" ON "alert_channels" ("name");

-- Which events of which brand (NULL = every brand) reach a channel, and how.
CREATE TABLE "alert_subscriptions" (
    "id"                 UUID NOT NULL DEFAULT gen_random_uuid(),
    "channel_id"         UUID NOT NULL,
    "original_domain_id" UUID,
    "event_types"        "AlertEventType"[] NOT NULL,
    "min_risk_score"     INTEGER NOT NULL DEFAULT 0,
    "mode"               "AlertMode" NOT NULL DEFAULT 'IMMEDIATE',
    "is_active"          BOOLEAN NOT NULL DEFAULT true,
    "created_at"         TIMESTAMPTZ(3) NOT NULL DEFAULT now(),
    "updated_at"         TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "pk_alert_subscriptions" PRIMARY KEY ("id"),
    CONSTRAINT "fk_alert_subscriptions_channel_id" FOREIGN KEY ("channel_id")
        REFERENCES "alert_channels" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "fk_alert_subscriptions_original_domain_id" FOREIGN KEY ("original_domain_id")
        REFERENCES "original_domains" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "ck_alert_subscriptions_event_types" CHECK (cardinality("event_types") > 0),
    CONSTRAINT "ck_alert_subscriptions_min_risk_score" CHECK ("min_risk_score" >= 0)
);
CREATE INDEX "ix_alert_subscriptions_channel_id" ON "alert_subscriptions" ("channel_id");
CREATE INDEX "ix_alert_subscriptions_original_domain_id" ON "alert_subscriptions" ("original_domain_id");

-- One row per alert per subscription. `dedupe_key` makes raising idempotent (redelivered events,
-- repeated scans): subscription + event + look-alike + UTC day.
CREATE TABLE "alert_deliveries" (
    "id"                UUID NOT NULL DEFAULT gen_random_uuid(),
    "subscription_id"   UUID NOT NULL,
    "channel_id"        UUID NOT NULL,
    "scanned_domain_id" UUID,
    "event_type"        "AlertEventType" NOT NULL,
    "mode"              "AlertMode" NOT NULL,
    "dedupe_key"        VARCHAR(200) NOT NULL,
    "payload"           JSONB NOT NULL,
    "status"            "AlertDeliveryStatus" NOT NULL DEFAULT 'PENDING',
    "attempts"          INTEGER NOT NULL DEFAULT 0,
    "last_error"        TEXT,
    "created_at"        TIMESTAMPTZ(3) NOT NULL DEFAULT now(),
    "sent_at"           TIMESTAMPTZ(3),
    CONSTRAINT "pk_alert_deliveries" PRIMARY KEY ("id"),
    CONSTRAINT "fk_alert_deliveries_subscription_id" FOREIGN KEY ("subscription_id")
        REFERENCES "alert_subscriptions" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "fk_alert_deliveries_channel_id" FOREIGN KEY ("channel_id")
        REFERENCES "alert_channels" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "fk_alert_deliveries_scanned_domain_id" FOREIGN KEY ("scanned_domain_id")
        REFERENCES "scanned_domains" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "uq_alert_deliveries_dedupe_key" ON "alert_deliveries" ("dedupe_key");
CREATE INDEX "ix_alert_deliveries_subscription_id" ON "alert_deliveries" ("subscription_id");
CREATE INDEX "ix_alert_deliveries_channel_id_status" ON "alert_deliveries" ("channel_id", "status");
CREATE INDEX "ix_alert_deliveries_scanned_domain_id" ON "alert_deliveries" ("scanned_domain_id");
CREATE INDEX "ix_alert_deliveries_created_at" ON "alert_deliveries" ("created_at");
