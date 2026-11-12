-- delivery_mode: see Discovery.deliveryMode; NULL on a v1 run and on a v2 run whose connector has not answered.
-- checkpoint_revision: see Discovery.checkpointRevision; existing runs start at 0.
ALTER TABLE "discovery"
    ADD COLUMN "delivery_mode" VARCHAR,
    ADD COLUMN "checkpoint_revision" BIGINT NOT NULL DEFAULT 0;

-- When a checkpointed drain row began receiving nothing but "busy" answers; empty otherwise.
ALTER TABLE "discovery_work"
    ADD COLUMN "busy_since" TIMESTAMPTZ;
