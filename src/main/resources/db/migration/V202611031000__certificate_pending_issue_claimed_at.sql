-- When a synchronous issue/renew/rekey call to the authority started; cleared once the authority's
-- answer is recorded. The pending-issue reaper fails only certificates whose stamp went stale, so a
-- certificate the authority accepted asynchronously or parked after a local failure is not failed,
-- unless clearing its stamp failed.
ALTER TABLE "certificate" ADD COLUMN "pending_issue_claimed_at" TIMESTAMPTZ NULL;

-- Backs the reaper's selection: stamps are set only while a synchronous call is unanswered, so this
-- index stays tiny however many certificates wait in PENDING_ISSUE for manual completion.
-- Building it holds the ALTER TABLE's lock, so certificate reads and writes wait while it scans the
-- table; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_certificate_pending_issue_claimed_at"
    ON "certificate" ("pending_issue_claimed_at")
    WHERE "state" = 'PENDING_ISSUE' AND "pending_issue_claimed_at" IS NOT NULL;
