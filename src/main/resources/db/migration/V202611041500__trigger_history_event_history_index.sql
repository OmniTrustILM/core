-- The "Certificate uploaded" event looks up the trigger histories of its own event history, to see whether a trigger
-- sets the owner. TriggerHistoryEventHistoryIndexMigrationITest pins the index to that lookup.
--
-- CREATE INDEX blocks writes to its table while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_trigger_history_event_history" ON "trigger_history" ("event_history_uuid");
