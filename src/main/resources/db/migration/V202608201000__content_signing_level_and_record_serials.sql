-- Level-ladder configuration for CONTENT_SIGNING profiles.
--
ALTER TABLE "signing_profile_version"
    ADD COLUMN "signature_family"              VARCHAR NULL,
    ADD COLUMN "max_signature_level"           VARCHAR NULL,
    ADD COLUMN "timestamp_source_profile_uuid" UUID    NULL,
    ADD COLUMN "document_size_cap"             BIGINT  NULL;

-- The referenced profile must outlive the reference; RESTRICT makes deleting a referenced TSA profile an error.
ALTER TABLE "signing_profile_version"
    ADD CONSTRAINT "fk_spv_timestamp_source_profile"
        FOREIGN KEY ("timestamp_source_profile_uuid") REFERENCES "signing_profile" ("uuid") ON DELETE RESTRICT;

CREATE INDEX idx_spv_timestamp_source_profile_uuid
    ON "signing_profile_version" ("timestamp_source_profile_uuid");

ALTER TABLE "signing_record" ADD COLUMN "timestamp_token_serial_numbers" TEXT[];
ALTER TABLE "signing_record_outbox" ADD COLUMN "timestamp_token_serial_numbers" TEXT[];

CREATE INDEX idx_sr_timestamp_token_serial_numbers
    ON "signing_record" USING GIN ("timestamp_token_serial_numbers");
