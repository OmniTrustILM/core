-- Deleting the suppression rows of an object (when a certificate becomes not compliant again or is deleted) filters on
-- the object and the event; the unique constraint leads with the notification profile and cannot serve those deletes.
CREATE INDEX IF NOT EXISTS "idx_pending_notification_object_event"
    ON "pending_notification" ("object_uuid", "event");
