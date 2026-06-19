ALTER TABLE custom_oid_entry
    ADD COLUMN IF NOT EXISTS default_critical  BOOLEAN,
    ADD COLUMN IF NOT EXISTS value_encoding    VARCHAR(255);
