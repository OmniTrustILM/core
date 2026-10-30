-- Discovery v2 schema groundwork: run-level v2 columns on discovery, the work agenda table that
-- drives the status/drain/process ticks, and the resource-agnostic staging table for discovered
-- items. Column-comment parity notes refer to discovery_certificate, whose v1 rows keep living
-- beside discovery_item until the evidence-gated unification (core#2027).

ALTER TABLE "discovery"
    ADD COLUMN "connector_interface_uuid" UUID,          -- NULL = v1 legacy run
    ADD COLUMN "run_meta" JSONB,
    ADD COLUMN "resources" JSONB,
    ADD COLUMN "last_applied_sequence" BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN "progress_processed" BIGINT,
    ADD COLUMN "progress_total_estimate" BIGINT,
    ADD COLUMN "progress_by_resource" JSONB,
    ADD COLUMN "progress_phase" VARCHAR,
    ADD COLUMN "run_messages" JSONB,
    ADD COLUMN "stopped_at" TIMESTAMPTZ,
    ADD COLUMN "connector_state" VARCHAR,                -- last authoritative DiscoveryRunState;
                                                         -- 'completed' = drain-to-completion mode
    -- The two legacy run timestamps join the timestamptz columns above. The naive values are interpreted
    -- in the session's TimeZone, which pgJDBC pins to the JVM's zone — the same zone the java.util.Date
    -- values were written in, so the implicit conversion is exact wherever the JVM zone did not change
    -- over the data's lifetime.
    ALTER COLUMN "start_time" TYPE TIMESTAMPTZ,
    ALTER COLUMN "end_time" TYPE TIMESTAMPTZ;

CREATE TABLE "discovery_work" (
    "uuid" UUID PRIMARY KEY,
    "discovery_uuid" UUID NOT NULL,
    "work_type" VARCHAR NOT NULL,
    "attempt" INT NOT NULL DEFAULT 0,
    "next_due_at" TIMESTAMPTZ NOT NULL,
    "i_cre" TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT "discovery_work_to_discovery_key" FOREIGN KEY ("discovery_uuid")
        REFERENCES "discovery" ("uuid") ON DELETE CASCADE,
    CONSTRAINT "uq_discovery_work" UNIQUE ("discovery_uuid", "work_type")
);
CREATE INDEX "idx_discovery_work_next_due_at" ON "discovery_work" ("next_due_at");

CREATE TABLE "discovery_item" (
    "uuid" UUID PRIMARY KEY,
    "discovery_uuid" UUID NOT NULL,
    "resource" VARCHAR NOT NULL,
    "sequence" BIGINT NOT NULL,
    "unique_ref" VARCHAR NOT NULL,
    "payload" JSONB NOT NULL,
    "discovered_at" TIMESTAMPTZ,
    "processed_at" TIMESTAMPTZ,
    "processed_error" VARCHAR,           -- per-item processing failure (parity: discovery_certificate.processed_error)
    "inventory_uuid" UUID,               -- object this item became (parity: discovery_certificate.inventory_uuid);
                                         -- null until processed, permanently null if processing failed
    "newly_discovered" BOOLEAN NOT NULL, -- not already in inventory when staged, matched by fingerprint
                                         -- (parity: discovery_certificate.newly_discovered)
    "meta" JSONB,                        -- provider-reported location context (DiscoveredItemDto.meta);
                                         -- unrecoverable if dropped at staging; key location lives here
    CONSTRAINT "discovery_item_to_discovery_key" FOREIGN KEY ("discovery_uuid")
        REFERENCES "discovery" ("uuid") ON DELETE CASCADE,
    CONSTRAINT "uq_discovery_item_ref" UNIQUE ("discovery_uuid", "resource", "unique_ref")
);
CREATE INDEX "idx_discovery_item_unprocessed" ON "discovery_item" ("discovery_uuid") WHERE "processed_at" IS NULL;
