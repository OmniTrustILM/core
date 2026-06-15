ALTER TABLE "tsp_profile"
    ADD COLUMN "allowed_authentication_methods" TEXT[] NOT NULL DEFAULT '{}';

-- Backfill existing profiles with CLIENT_CERTIFICATE only.
UPDATE "tsp_profile"
SET "allowed_authentication_methods" = ARRAY['CLIENT_CERTIFICATE']
WHERE cardinality("allowed_authentication_methods") = 0;

CREATE TABLE "tsp_profile_basic_credential"
(
    "uuid"             UUID    NOT NULL,
    "tsp_profile_uuid" UUID    NOT NULL,
    "username"         VARCHAR NOT NULL,
    "secret_uuid"      UUID    NOT NULL,
    "mapped_user_uuid" UUID    NOT NULL,
    PRIMARY KEY ("uuid"),
    FOREIGN KEY ("tsp_profile_uuid") REFERENCES "tsp_profile" ("uuid"),
    CONSTRAINT "tsp_profile_basic_credential_username" UNIQUE ("tsp_profile_uuid", "username")
);

ALTER TABLE "tsp_profile" ADD COLUMN "vault_profile_uuid" UUID;
ALTER TABLE "tsp_profile" ADD CONSTRAINT "fk_tsp_profile_vault_profile" FOREIGN KEY ("vault_profile_uuid") REFERENCES "vault_profile" ("uuid");

CREATE INDEX "idx_tsp_profile_vault_profile_uuid" ON "tsp_profile" ("vault_profile_uuid");
