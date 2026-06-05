-- Versioned record-policy fields on signing_profile_version: each SigningRecord carries the version it was
-- created under, so its retention / delete-after-retrieval / persistence behaviour is fixed at signing time and
-- a later policy change applies only to records created afterwards.
ALTER TABLE "signing_profile_version"
    ADD COLUMN "record_metadata" BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_request_metadata"  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_signature"         BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_signed_document"   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "record_dtbs"      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "retention_days"   INTEGER NULL,
    ADD COLUMN "delete_after_retrieval"   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "persistence_mode" VARCHAR NOT NULL DEFAULT 'DEFERRED_DURABLE';

-- Signing record (maps SigningRecord extends UniquelyIdentifiedAndAudited)
CREATE TABLE "signing_record"
(
    "uuid"                         UUID        NOT NULL,
    "name"                         VARCHAR,
    "signing_profile_uuid"         UUID,
    "signing_profile_version"      INTEGER     NOT NULL,
    "signing_time"                 TIMESTAMPTZ NOT NULL,
    "signature_value"              BYTEA,
    "request_metadata_json"        JSONB,
    "signed_document"              BYTEA,
    "dtbs"                         BYTEA,
    "signed_document_retrieved_at" TIMESTAMPTZ,
    "i_author"                     VARCHAR,
    "i_cre"                        TIMESTAMP DEFAULT NOW(),
    "i_upd"                        TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY ("uuid"),
    FOREIGN KEY ("signing_profile_uuid") REFERENCES "signing_profile" ("uuid") ON DELETE RESTRICT
);

-- Sweeper index: retention deletes filter by profile + signing_time (see SigningRecordRepository.deleteExpiredByRetention)
CREATE INDEX idx_sr_profile_signing_time
    ON "signing_record" ("signing_profile_uuid", "signing_time");

-- Fallback sweep index: delete-after-retrieval deletes filter on retrieved-but-not-yet-deleted
-- records (see SigningRecordRepository.deleteRetrievedAndFlagged). Partial so it only indexes the
-- small set of retrieved rows still pending deletion, not the full table.
CREATE INDEX idx_sr_retrieved_at
    ON "signing_record" ("signed_document_retrieved_at")
    WHERE "signed_document_retrieved_at" IS NOT NULL;

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
    "attempts"                INTEGER     NOT NULL DEFAULT 0,
    "last_error"              TEXT NULL
);

CREATE INDEX idx_sro_signing_time ON "signing_record_outbox" ("signing_time");
-- Backs the outbox.poisoned gauge (COUNT WHERE attempts >= threshold) and the
-- attempts filter on the lag_seconds gauge; plain btree so it stays valid if the
-- runtime poison-threshold is overridden away from its default.
CREATE INDEX idx_sro_attempts ON "signing_record_outbox" ("attempts");
