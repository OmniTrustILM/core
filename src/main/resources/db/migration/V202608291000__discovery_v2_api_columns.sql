-- Columns the discovery v2 API surface needs. All nullable and written by the v2 path only, so a v1 run keeps the
-- shape it has today and nothing is backfilled.

-- stoppable: what the connector declared at initiate and refreshes on each resume. NULL for a v1 run, which cannot
--   be stopped; the detail publishes that as false.
-- scheduled_job_history_uuid: the execution that started the run. A v1 run carries it through one synchronous call
--   chain, but a v2 run ends later in a tick worker with no memory of who asked for it, so without this the
--   scheduler is never told and the job hangs open. The execution alone -- the history row points at its job.
ALTER TABLE "discovery"
    ADD COLUMN "stoppable" BOOLEAN,
    ADD COLUMN "scheduled_job_history_uuid" UUID;

-- Numbered and timestamped as every other resource is, so one run's certificates and keys can be ordered against
-- each other. NULL on a v1 row, whose provider numbered nothing: the listing synthesizes both at read time rather
-- than backfilling values that never existed. Metadata-only.
ALTER TABLE "discovery_certificate"
    ADD COLUMN "sequence" BIGINT,
    ADD COLUMN "discovered_at" TIMESTAMPTZ;

-- The only audit columns still declared VARCHAR, though the entity has always mapped them as OffsetDateTime. The
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
-- would reclassify finished v2 runs. ConnectorServiceImpl.removeConnectorAssociations releases the runs first, so
-- the interfaces still cascade away. No index, as on the two tables above: the association loads by
-- connector_interface's own primary key, so only this constraint check ever scans discovery by the column.
ALTER TABLE "discovery"
    ADD CONSTRAINT "fk_discovery_connector_interface"
        FOREIGN KEY ("connector_interface_uuid") REFERENCES "connector_interface" ("uuid")
        ON UPDATE CASCADE ON DELETE RESTRICT;
