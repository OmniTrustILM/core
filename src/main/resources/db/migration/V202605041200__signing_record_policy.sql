-- Versioned content-policy fields on signing_profile_version
ALTER TABLE "signing_profile_version"
    ADD COLUMN "record_metadata" BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_request_metadata"  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_signature"         BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_signed_document"   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_dtbs"              BOOLEAN NOT NULL DEFAULT FALSE;

-- Non-versioned operational policy + denormalized cache fields on signing_profile
ALTER TABLE "signing_profile"
    ADD COLUMN "retention_days" INTEGER NULL,
    ADD COLUMN "delete_after_retrieval"   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "persistence_mode"         VARCHAR NOT NULL DEFAULT 'DEFERRED_DURABLE',
    ADD COLUMN "record_metadata"          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_request_metadata"  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_signature"         BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_signed_document"   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_dtbs"              BOOLEAN NOT NULL DEFAULT FALSE;

-- Optional payload columns + retrieval timestamp on signing_record
ALTER TABLE "signing_record"
    ADD COLUMN "request_metadata_json" JSONB NULL,
    ADD COLUMN "signed_document"                 BYTEA        NULL,
    ADD COLUMN "dtbs"                            BYTEA        NULL,
    ADD COLUMN "signed_document_retrieved_at"    TIMESTAMPTZ  NULL;

-- Sweeper index
CREATE INDEX idx_sr_profile_created
    ON "signing_record" ("signing_profile_uuid", "created_at");

-- Outbox staging table for DEFERRED_DURABLE
CREATE TABLE "signing_record_outbox"
(
    "uuid"                    UUID        NOT NULL PRIMARY KEY,
    "name"                    VARCHAR NULL,
    "signing_profile_uuid"    UUID NULL,
    "signing_profile_version" INTEGER     NOT NULL,
    "signing_time"            TIMESTAMPTZ NOT NULL,
    "signature_value"         BYTEA NULL,
    "signed_document"         BYTEA NULL,
    "dtbs"                    BYTEA NULL,
    "request_metadata_json"   JSONB NULL,
    "created_at"              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "attempts"                INTEGER     NOT NULL DEFAULT 0,
    "last_error"              TEXT NULL
);

CREATE INDEX idx_sro_created_at ON "signing_record_outbox" ("created_at");
