-- 0007 — Phase 4 transactional outbox (PLAN.md §1.2, §13).
--
-- Every after-commit domain event is written here in the SAME transaction as the change that
-- produced it. The writing process dispatches it right after commit and deletes the row; if the
-- process dies first, the outbox relay of a process with the same role re-dispatches it.
-- No foreign keys: the payload references rows by id and must outlive them (e.g. delete events).
CREATE TABLE "outbox_events" (
    "id"           UUID         NOT NULL DEFAULT gen_random_uuid(),
    "event_name"   VARCHAR(120) NOT NULL,
    "payload"      JSONB        NOT NULL,
    -- Process role that emitted it ('api' | 'worker'): only that role has every listener for it.
    "origin"       VARCHAR(16)  NOT NULL,
    "attempts"     INTEGER      NOT NULL DEFAULT 0,
    -- The relay ignores a row until this time (grace period for the in-process dispatch / backoff).
    "available_at" TIMESTAMPTZ(3) NOT NULL DEFAULT now(),
    "last_error"   TEXT,
    -- Set after the last allowed attempt: parked for an operator (dead letter), never retried.
    "failed_at"    TIMESTAMPTZ(3),
    "created_at"   TIMESTAMPTZ(3) NOT NULL DEFAULT now(),

    CONSTRAINT "pk_outbox_events" PRIMARY KEY ("id")
);

-- Relay scan: pending rows of one role whose grace period / backoff has elapsed.
CREATE INDEX "ix_outbox_events_origin_available_at" ON "outbox_events" ("origin", "available_at");
-- Dead-letter listing and retention.
CREATE INDEX "ix_outbox_events_failed_at" ON "outbox_events" ("failed_at");
