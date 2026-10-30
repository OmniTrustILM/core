-- Who started the run, so agenda-driven work can act as them. Nullable: existing runs and unauthenticated
-- callers have none.
ALTER TABLE "discovery" ADD COLUMN "started_by_user_uuid" UUID;

-- The connector's per-occurrence dedupe key for a staged certificate. Nullable: v1 rows have none.
ALTER TABLE "discovery_certificate" ADD COLUMN "unique_ref" VARCHAR;

-- One reference may be staged once per run. Partial so v1's null rows sit outside the constraint.
CREATE UNIQUE INDEX "uq_discovery_certificate_ref"
    ON "discovery_certificate" ("discovery_uuid", "unique_ref")
    WHERE "unique_ref" IS NOT NULL;

-- Supports the v2 processing claim. Partial so it shrinks as a run drains instead of growing with it.
CREATE INDEX "idx_discovery_certificate_pending"
    ON "discovery_certificate" ("discovery_uuid", "certificate_content_id", "i_cre")
    WHERE "newly_discovered" = true AND "processed" = false AND "processed_error" IS NULL;

-- Supports the end-of-run WARNING check. Partial, so it stays tiny on a healthy run.
CREATE INDEX "idx_discovery_certificate_failed"
    ON "discovery_certificate" ("discovery_uuid")
    WHERE "processed_error" IS NOT NULL;
