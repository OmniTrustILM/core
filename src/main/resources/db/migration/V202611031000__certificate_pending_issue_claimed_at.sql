-- When a synchronous issue/renew/rekey call to the authority started; cleared once the authority's
-- answer is recorded. The pending-issue reaper fails only certificates whose stamp went stale, so a
-- certificate the authority accepted asynchronously or parked after a local failure is never failed.
--
-- No index of its own: the reaper narrows to PENDING_ISSUE through the existing partial index
-- idx_certificate_pending_issue_reaper and filters the stamp on that small set. Adding a nullable
-- column changes only the catalog, so this migration takes a brief lock and never scans the table.
ALTER TABLE "certificate" ADD COLUMN "pending_issue_claimed_at" TIMESTAMPTZ NULL;
