CREATE TABLE "est_profile" (
    "uuid"                            UUID        NOT NULL,
    "name"                            VARCHAR     NOT NULL,
    "description"                     TEXT,
    "enabled"                         BOOLEAN     NOT NULL DEFAULT FALSE,
    "system_default"                  BOOLEAN     NOT NULL DEFAULT FALSE,
    "ra_profile_uuid"                 UUID,
    "authentication_policy"           VARCHAR     NOT NULL,
    "basic_credential_secret_uuids"   UUID[]      NOT NULL DEFAULT '{}',
    "trusted_ca_certificate_uuids"    UUID[]      NOT NULL DEFAULT '{}',
    "allow_renewal"                   BOOLEAN     NOT NULL DEFAULT TRUE,
    "allow_rekey"                     BOOLEAN     NOT NULL DEFAULT TRUE,
    "renewal_threshold"               INTEGER,
    "server_key_generation"           BOOLEAN     NOT NULL DEFAULT FALSE,
    "issue_wait_timeout"              INTEGER     NOT NULL DEFAULT 10,
    "retry_after"                     INTEGER     NOT NULL DEFAULT 30,
    "server_key_generation_timeout"   INTEGER     NOT NULL DEFAULT 30,
    "key_recovery"                    BOOLEAN     NOT NULL DEFAULT FALSE,
    "key_recovery_token_profile_uuid" UUID,
    "key_recovery_key_attributes"     TEXT,
    "certificate_associations_uuid"   UUID,
    "i_author"                        VARCHAR,
    "i_cre"                           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "i_upd"                           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY ("uuid"),
    UNIQUE ("name"),
    CONSTRAINT "fk_est_profile_ra_profile" FOREIGN KEY ("ra_profile_uuid")
        REFERENCES "ra_profile" ("uuid") ON DELETE RESTRICT,
    CONSTRAINT "fk_est_profile_key_recovery_token_profile" FOREIGN KEY ("key_recovery_token_profile_uuid")
        REFERENCES "token_profile" ("uuid") ON DELETE RESTRICT,
    CONSTRAINT "fk_est_profile_certificate_associations" FOREIGN KEY ("certificate_associations_uuid")
        REFERENCES "protocol_certificate_associations" ("uuid") ON DELETE NO ACTION
);

-- At most one profile serves requests sent without a label. A partial unique index is the only shape that expresses
-- "unique among the rows where the flag is set", so it has no counterpart on the entity and is absent from the
-- entity-generated test schema.
CREATE UNIQUE INDEX "uk_est_profile_single_system_default" ON "est_profile" ("system_default") WHERE "system_default";

ALTER TABLE "ra_profile" ADD COLUMN "est_profile_uuid" UUID NULL;

ALTER TABLE "ra_profile"
    ADD CONSTRAINT "ra_profile_to_est_profile_key" FOREIGN KEY ("est_profile_uuid")
        REFERENCES "est_profile" ("uuid") ON DELETE RESTRICT;

CREATE INDEX "idx_ra_profile_est_profile_uuid" ON "ra_profile" ("est_profile_uuid");

ALTER TABLE "ra_profile_protocol_attribute" ADD COLUMN "est_issue_certificate_attributes" TEXT;

-- An EST retry finds the certificate of its request by the fingerprint of the request. The protocol that requested it
-- is read through the index of the unique constraint on certificate_protocol_association.certificate_uuid.
CREATE INDEX IF NOT EXISTS "idx_certificate_request_fingerprint"
    ON "certificate_request" ("fingerprint");

-- Destroying a key asks whether a certificate uses it, also through the request it carries, which looks certificate
-- requests up by their key and alternative key; neither column has an index.
--
-- CREATE INDEX blocks writes to its table while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX IF NOT EXISTS "idx_certificate_request_key_uuid" ON "certificate_request" ("key_uuid");
CREATE INDEX IF NOT EXISTS "idx_certificate_request_alt_key_uuid" ON "certificate_request" ("alt_key_uuid");

-- Serialises identical concurrent EST requests: the node that inserts (or takes over) a claim submits to the authority,
-- the others wait for the certificate that the claim links once it is stored. No foreign keys to the profiles, so a
-- claim never blocks deleting a profile; a linked claim goes with its certificate.
CREATE TABLE "est_request_claim" (
    "uuid"             UUID        NOT NULL,
    "est_profile_uuid" UUID        NOT NULL,
    "ra_profile_uuid"  UUID        NOT NULL,
    "operation"        VARCHAR     NOT NULL,
    "request_key"      TEXT        NOT NULL,
    "claimed_at"       TIMESTAMPTZ NOT NULL,
    "certificate_uuid" UUID        NULL,
    PRIMARY KEY ("uuid"),
    CONSTRAINT "uq_est_request_claim" UNIQUE ("est_profile_uuid", "ra_profile_uuid", "operation", "request_key"),
    CONSTRAINT "fk_est_request_claim_certificate" FOREIGN KEY ("certificate_uuid") REFERENCES "certificate" ("uuid")
        ON DELETE CASCADE
);

CREATE INDEX "idx_est_request_claim_certificate_uuid" ON "est_request_claim" ("certificate_uuid");
