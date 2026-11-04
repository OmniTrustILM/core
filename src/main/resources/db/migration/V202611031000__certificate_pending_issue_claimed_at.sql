-- When a synchronous issue/renew/rekey call to the authority started; cleared once the authority's
-- answer is recorded. The pending-issue reaper fails only certificates whose stamp went stale, so a
-- certificate the authority accepted asynchronously or parked after a local failure is not failed,
-- unless clearing its stamp failed.
--
-- Adding a nullable column changes only the catalog, so this migration takes a brief lock and never
-- scans the table. The index that serves the reaper is built by the next migration.
ALTER TABLE "certificate" ADD COLUMN "pending_issue_claimed_at" TIMESTAMPTZ NULL;
