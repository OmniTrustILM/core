-- Concurrent notification consumers (the queue runs multiple consumers) can create duplicate
-- suppression rows through the read-then-insert flow. Collapse duplicates deterministically --
-- keep the row with the greatest last_sent_at, then repetitions, then uuid -- and add the unique
-- constraint the atomic upsert relies on. Legacy rows may carry a NULL event, so the duplicate
-- match treats NULL as a value; new rows always carry an event (only monitoring events are tracked).
LOCK TABLE "pending_notification" IN SHARE ROW EXCLUSIVE MODE;

DELETE FROM "pending_notification" p
USING "pending_notification" d
WHERE p."notification_profile_uuid" = d."notification_profile_uuid"
  AND p."resource" = d."resource"
  AND p."object_uuid" = d."object_uuid"
  AND p."event" IS NOT DISTINCT FROM d."event"
  AND p."uuid" <> d."uuid"
  AND (p."last_sent_at", p."repetitions", p."uuid") < (d."last_sent_at", d."repetitions", d."uuid");

ALTER TABLE "pending_notification"
    ADD CONSTRAINT "uq_pending_notification_suppression_row"
    UNIQUE ("notification_profile_uuid", "resource", "object_uuid", "event");
