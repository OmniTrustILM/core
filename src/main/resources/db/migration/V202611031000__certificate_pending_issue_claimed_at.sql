-- When a synchronous issue/renew/rekey call to the authority started; cleared once the authority's
-- answer is recorded. The pending-issue reaper fails only certificates whose stamp went stale, so a
-- certificate the authority accepted asynchronously or parked after a local failure is never failed.
ALTER TABLE "certificate" ADD COLUMN "pending_issue_claimed_at" TIMESTAMPTZ NULL;

-- Backs the reaper's recurring selection (stale stamps, oldest first). Partial index: stamped
-- PENDING_ISSUE rows are a handful at any time, so the sweep does an index range scan.
CREATE INDEX "idx_certificate_pending_issue_claimed_at"
    ON "certificate" ("pending_issue_claimed_at")
    WHERE "state" = 'PENDING_ISSUE' AND "pending_issue_claimed_at" IS NOT NULL;
