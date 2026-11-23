-- The index builds in a migration of its own, after the backfill. Its SHARE lock lets plain reads through.
-- Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX cryptographic_key_item_parameter_set
    ON cryptographic_key_item (parameter_set);
