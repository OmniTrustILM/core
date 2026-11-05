-- A tick holds its agenda row through a lease: the sweep writes a fresh token when it claims the row, the tick message
-- carries it, and a tick runs and writes the row only while the token is still the row's own. An empty or expired
-- lease leaves the row claimable. Both columns start empty: no row is being worked when this migration runs.
ALTER TABLE "discovery_work"
    ADD COLUMN "lease_token" UUID,
    ADD COLUMN "lease_expires_at" TIMESTAMPTZ;
