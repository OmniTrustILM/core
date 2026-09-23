ALTER TABLE cryptographic_key_item
    ADD COLUMN exportable BOOLEAN NOT NULL DEFAULT FALSE;
