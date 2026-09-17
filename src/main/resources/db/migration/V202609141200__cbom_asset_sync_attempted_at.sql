-- When the cryptographic-asset ingest last touched this CBOM, success or not.
--
-- `assets_synced_at` records the last success, so it cannot answer the question a run actually asks: has this row been
-- untouched long enough that retrying it is not stealing work from a live ingest, or re-reading a document that just
-- failed? The `cbom` table is not audited (it carries no `i_upd`), so there is no existing column that moves on every
-- attempt.
--
-- Null means never attempted, which is what every row holds today: nothing has ever ingested assets.
ALTER TABLE "cbom"
    ADD COLUMN "asset_sync_attempted_at" TIMESTAMPTZ;

-- Both ingest work lists select on `asset_sync_state` and the retry list reads `asset_sync_attempted_at` out of the
-- same row, so the timestamp is carried in the index to keep the retry list's filter off the heap.
--
-- It does not supply the retry list's ordering, and no index can while that query is shaped as it is: the
-- `attempted_at IS NULL OR attempted_at < :retryBefore` disjunction is not a range condition, `NULLS FIRST` is the
-- opposite of a btree's default, and `uuid` is the second sort key. The rows sorted are the ones the state predicate
-- admits, which is what the work list is bounded by anyway.
--
-- `idx_cbom_asset_sync_state` goes, because this index has it as a strict prefix and serves every lookup it served.
DROP INDEX IF EXISTS "idx_cbom_asset_sync_state";

CREATE INDEX "idx_cbom_asset_sync_attempt" ON "cbom" ("asset_sync_state", "asset_sync_attempted_at");
