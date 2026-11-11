-- The lease a tick holds on its agenda row; an empty or expired lease leaves the row claimable.
-- Both columns start empty: no row is leased before this migration.
ALTER TABLE "discovery_work"
    ADD COLUMN "lease_token" UUID,
    ADD COLUMN "lease_expires_at" TIMESTAMPTZ;
