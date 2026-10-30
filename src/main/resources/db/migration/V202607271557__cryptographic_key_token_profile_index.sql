-- Backs the FK cryptographic_key -> token_profile, which Postgres does not index automatically:
-- the dependent-key count and FK check on token profile deletion, and the key inventory filter
-- by token profile (FilterField.CK_TOKEN_PROFILE), all scan this column. Mirrors
-- idx_spv_token_profile_uuid on signing_profile_version.
CREATE INDEX IF NOT EXISTS "idx_cryptographic_key_token_profile_uuid"
    ON "cryptographic_key" ("token_profile_uuid");
