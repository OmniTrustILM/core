-- In PostgreSQL, a UNIQUE constraint is backed by its own unique index which is created automatically.
ALTER TABLE "tsp_profile_basic_credential"
    ADD CONSTRAINT "tsp_profile_basic_credential_secret_uuid" UNIQUE ("secret_uuid");
