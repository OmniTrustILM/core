-- Level-ladder configuration for CONTENT_SIGNING profiles. All four are nullable. Profile save is what makes the
-- first three mandatory for ILM-managed signing; a delegated profile carries none of them. document_size_cap is
-- never mandatory and is legal under either signing scheme.
--
-- No data step accompanies these columns. Content signing has never been used in the field, so no deployed
-- database holds a CONTENT_SIGNING version row that would need one.
ALTER TABLE "signing_profile_version"
    ADD COLUMN "signature_family"              VARCHAR NULL,
    ADD COLUMN "max_signature_level"           VARCHAR NULL,
    ADD COLUMN "timestamp_source_profile_uuid" UUID    NULL,
    ADD COLUMN "document_size_cap"             BIGINT  NULL;

-- The referenced profile must outlive the reference; RESTRICT makes deleting a referenced TSA profile an error
-- rather than a silently broken content-signing profile.
ALTER TABLE "signing_profile_version"
    ADD CONSTRAINT "fk_spv_timestamp_source_profile"
        FOREIGN KEY ("timestamp_source_profile_uuid") REFERENCES "signing_profile" ("uuid") ON DELETE RESTRICT;

-- Backs the new FK: without it every signing_profile delete sequential-scans signing_profile_version to
-- enforce the constraint. Mirrors the FK-column indexes the table already carries.
CREATE INDEX idx_spv_timestamp_source_profile_uuid
    ON "signing_profile_version" ("timestamp_source_profile_uuid");
