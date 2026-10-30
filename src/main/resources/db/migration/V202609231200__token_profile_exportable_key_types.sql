ALTER TABLE token_profile
    ADD COLUMN exportable_key_types JSONB,
    ADD COLUMN exportable_key_types_revision INTEGER NOT NULL DEFAULT 0;
