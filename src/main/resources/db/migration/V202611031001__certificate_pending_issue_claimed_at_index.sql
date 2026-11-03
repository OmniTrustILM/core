-- Backs the pending-issue reaper's selection: a claim is stamped only while a synchronous call to the
-- authority is unanswered, so this index stays tiny however many certificates wait in PENDING_ISSUE
-- for manual completion.
--
-- CREATE INDEX blocks writes to certificate while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_certificate_pending_issue_claimed_at"
    ON "certificate" ("pending_issue_claimed_at")
    WHERE "state" = 'PENDING_ISSUE' AND "pending_issue_claimed_at" IS NOT NULL;
