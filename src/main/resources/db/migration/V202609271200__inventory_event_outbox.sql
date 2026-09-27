CREATE TABLE inventory_event_outbox (
    cbom_uuid UUID PRIMARY KEY,
    asset_uuids UUID[] NOT NULL DEFAULT '{}',
    cbom_synced BOOLEAN NOT NULL DEFAULT FALSE,
    assets_ready BOOLEAN NOT NULL DEFAULT FALSE,
    cbom_user_uuid UUID,
    claimed_until TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_inventory_event_outbox_ready
    ON inventory_event_outbox (created_at)
    WHERE claimed_until IS NULL;
