-- Immutable signing history. A signing_record row proves what a signing contained; this table preserves that the
-- signing happened, which has to survive the record being deleted by an operator, by retention, or by
-- delete-after-retrieval. Rows are written only by the roll-up-then-delete statements on SigningRecordRepository:
-- a bucket is created or incremented in the same statement that removes the records it accounts for.
CREATE TABLE "signing_record_volume"
(
    "uuid"                 UUID        NOT NULL,
    -- No FK to signing_profile: a profile becomes deletable once its records are gone and these counts outlive it,
    -- so the reference would be unsatisfiable. The column stays the access-control anchor -- signing history is
    -- scoped by signing-profile access, exactly as the records were.
    "signing_profile_uuid" UUID        NOT NULL,
    -- Start of the UTC hour the signings fall in. Hourly is the finest granularity the dashboard renders, and daily
    -- series are summed from it.
    "bucket_start"         TIMESTAMPTZ NOT NULL,
    "signing_count"        BIGINT      NOT NULL,
    PRIMARY KEY ("uuid"),
    -- Target of the ON CONFLICT that increments an existing bucket.
    CONSTRAINT "uq_signing_record_volume_bucket" UNIQUE ("signing_profile_uuid", "bucket_start")
);

-- The dashboard series scans a window across every profile the caller may see; the unique constraint's index leads
-- with the profile, so it cannot serve a bare window scan.
CREATE INDEX "idx_srv_bucket_start" ON "signing_record_volume" ("bucket_start");
