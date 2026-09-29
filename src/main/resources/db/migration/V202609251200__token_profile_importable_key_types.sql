ALTER TABLE token_profile
    ADD COLUMN importable_key_types JSONB;

ALTER TABLE token_profile
    RENAME COLUMN exportable_key_types_revision TO key_types_revision;
