ALTER TABLE inventory_event_outbox ADD COLUMN last_attempt_at TIMESTAMPTZ;

DROP INDEX idx_inventory_event_outbox_ready;
CREATE INDEX idx_inventory_event_outbox_ready
    ON inventory_event_outbox (COALESCE(last_attempt_at, created_at), cbom_uuid);
