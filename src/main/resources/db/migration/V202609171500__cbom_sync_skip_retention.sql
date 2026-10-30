-- The documents the CBOM sync gave up on (cbom_sync_skip, V202609081800) gain an operator's view and a retention:
-- POST /v1/cboms/syncSkips lists the rows newest failure first with a state filter, POST .../{uuid}/retry puts a
-- written-off row back to retrying, and the daily CbomSyncSkipRetentionTask removes written-off rows whose last
-- attempt is older than the platform setting cbomSyncSkipRetentionDays (90 by default). Age is the last attempt, not
-- the first failure: a document the repository keeps offering is failed on again each run and stays listed; one it no
-- longer lists expires. This index serves the sweep's cutoff scan (state, then age) and, under a state filter, the
-- list's default order; an unfiltered page sorts the table, which the retention keeps small.
CREATE INDEX "idx_cbom_sync_skip_state_last_attempt" ON "cbom_sync_skip" ("state", "last_attempt_at");
