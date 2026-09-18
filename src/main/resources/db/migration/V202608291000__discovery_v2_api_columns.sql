-- Columns the discovery v2 API surface needs. All nullable and written by the v2 path only, so a v1 run keeps the
-- shape it has today and nothing is backfilled.

-- The connector's opaque, resumable run state, replayed to it on every call. Not metadata, hence the name.
ALTER TABLE "discovery"
    RENAME COLUMN "run_meta" TO "checkpoint";

-- stoppable: see Discovery.stoppable; NULL for a v1 run, which the detail publishes as false.
-- scheduled_job_history_uuid: the scheduled job execution that started the run, replayed when it ends; see
--   Discovery.scheduledJobHistoryUuid for why it is stored and why the execution alone.
-- connector_highest_sequence: the highest item number the connector had assigned as of the last status answer
--   applied, which is what orders two answers to one run; see DiscoveryStatusTickWorker.apply.
ALTER TABLE "discovery"
    ADD COLUMN "stoppable" BOOLEAN,
    ADD COLUMN "scheduled_job_history_uuid" UUID,
    ADD COLUMN "connector_highest_sequence" BIGINT;

-- Numbered and timestamped as every other resource is, so one run's certificates and keys can be ordered against
-- each other. NULL on a v1 row; see DiscoveryCertificate.sequence for what the listing does with that. Metadata-only.
ALTER TABLE "discovery_certificate"
    ADD COLUMN "sequence" BIGINT,
    ADD COLUMN "discovered_at" TIMESTAMPTZ;

-- These audit columns are declared VARCHAR, though the entity has always mapped them as OffsetDateTime. The
-- items listing is the first query to compare them against a timestamp and fails at plan time as they stand.
-- Existing values are ISO-8601 written by Hibernate and read in the server's zone, where they were written, so the
-- cast is total. Rewrites the table under ACCESS EXCLUSIVE: brief, but one of the larger tables in a mature
-- deployment, so it wants a maintenance window.
ALTER TABLE "discovery_certificate"
    ALTER COLUMN "i_cre" TYPE TIMESTAMPTZ USING "i_cre"::timestamptz,
    ALTER COLUMN "i_upd" TYPE TIMESTAMPTZ USING "i_upd"::timestamptz;

-- Serves the items listing and its count. Every existing discovery_certificate index is partial and a v1 run's rows
-- satisfy none of them, so without this both sequentially scan the table; i_cre is included because the listing
-- orders the certificate branch by it. Built after the conversion above, which would otherwise rebuild it.
CREATE INDEX "idx_discovery_certificate_run"
    ON "discovery_certificate" ("discovery_uuid", "i_cre", "uuid");

-- References already dangling are cleared first: the column carried no constraint until now, so a connector deleted
-- earlier left runs pointing at interfaces that went with it, and the constraint cannot be added while they exist.
UPDATE "discovery"
SET "connector_interface_uuid" = NULL
WHERE "connector_interface_uuid" IS NOT NULL
  AND NOT EXISTS (SELECT 1
                  FROM "connector_interface" ci
                  WHERE ci."uuid" = "discovery"."connector_interface_uuid");

-- A real foreign key, as vault_instance and authority_instance_reference declare theirs. RESTRICT rather than SET
-- NULL: this column is also what says a run was v2 -- NULL means a legacy v1 run -- so nulling it for a cascade
-- would reclassify finished v2 runs. A connector's delete releases the ended runs first, so the interfaces still
-- cascade away; a live run keeps its reference and the delete is refused on it.
ALTER TABLE "discovery"
    ADD CONSTRAINT "fk_discovery_connector_interface"
        FOREIGN KEY ("connector_interface_uuid") REFERENCES "connector_interface" ("uuid")
        ON UPDATE CASCADE ON DELETE RESTRICT;

-- A connector's delete asks which runs still hold one of its interfaces and releases the ended ones, and the
-- constraint check above scans by the same column. Partial: a v1 run holds no interface and is never asked about.
CREATE INDEX "idx_discovery_connector_interface"
    ON "discovery" ("connector_interface_uuid")
    WHERE "connector_interface_uuid" IS NOT NULL;
