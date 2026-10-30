-- Backs the discovery run reaper's recurring selections (every discovery work sweep). Partial
-- indexes: actively driven and stopped v2 runs are tiny subsets of the discovery history, so the
-- indexes stay small and the sweep does index range scans instead of sequential scans of the
-- (potentially very large) discovery table.
CREATE INDEX "idx_discovery_work_lost_reaper"
    ON "discovery" ("i_cre")
    WHERE "connector_interface_uuid" IS NOT NULL AND "status" IN ('IN_PROGRESS', 'PROCESSING');

CREATE INDEX "idx_discovery_stop_expiry_reaper"
    ON "discovery" ("stopped_at")
    WHERE "connector_interface_uuid" IS NOT NULL AND "status" = 'STOPPED';
