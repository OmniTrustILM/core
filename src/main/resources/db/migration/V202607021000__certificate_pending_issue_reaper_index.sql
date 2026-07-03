-- Backs the orphaned-PENDING_ISSUE reaper's recurring selection (state + i_upd, oldest-first),
-- which runs on every status-poll sweep. Partial index: PENDING_ISSUE is a small subset, so the
-- index stays tiny and the sweep does an index range scan instead of a sequential scan of the
-- (potentially very large) certificate table.
CREATE INDEX "idx_certificate_pending_issue_reaper"
    ON "certificate" ("i_upd")
    WHERE "state" = 'PENDING_ISSUE';
