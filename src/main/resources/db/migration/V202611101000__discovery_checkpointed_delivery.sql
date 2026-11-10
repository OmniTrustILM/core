-- How a run's results travel from its connector, chosen by the connector at initiate and resume; empty on a v1 run
-- and on a v2 run whose connector has not answered yet.
-- The checkpoint revision rises with every applied checkpointed page and every stop and resume, so a tick can apply
-- its page only from the position it was asked from. Existing runs start at 0.
ALTER TABLE "discovery"
    ADD COLUMN "delivery_mode" VARCHAR,
    ADD COLUMN "checkpoint_revision" BIGINT NOT NULL DEFAULT 0;

-- When a checkpointed drain row began receiving nothing but "busy" answers; empty otherwise.
ALTER TABLE "discovery_work"
    ADD COLUMN "busy_since" TIMESTAMPTZ;
