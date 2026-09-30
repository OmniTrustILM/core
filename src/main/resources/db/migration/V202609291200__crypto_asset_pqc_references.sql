-- The PQC rule set carries no version: there is one, unreleased, and a verdict is re-evaluated when the row it
-- describes changes. A later rule change re-offers every row by advancing input_revision in its own migration.
DROP INDEX IF EXISTS "idx_crypto_asset_pqc_ruleset_version";
ALTER TABLE "crypto_asset" DROP COLUMN "pqc_ruleset_version";

-- The asset whose own verdict a certificate's or a protocol's was carried over from, recorded with the stamp so the
-- detail can name it. No FK: the verdict outlives its target, which the detail then serves as no longer visible.
ALTER TABLE "crypto_asset" ADD COLUMN "pqc_referenced_asset_uuid" UUID;
-- Every target a certificate's or a protocol's verdict was read from, with the verdict it held then. The sweep
-- rebuilds the same string from the rows as they stand and re-offers the referrer when the two differ.
ALTER TABLE "crypto_asset" ADD COLUMN "pqc_reference_basis" TEXT;

-- A certificate's verdict is its key's and signature algorithm's, a protocol's the weakest algorithm its cipher suites
-- name. A bom-ref names a component only within its document, so the ingest resolves each reference while the document
-- is in hand and records the asset it resolved to. Per source: only the source whose payload the merge elected speaks
-- for a row. A NULL target is a reference recorded and resolved to nothing.
CREATE TABLE "crypto_asset_reference" (
    "uuid"              UUID PRIMARY KEY,
    "source_uuid"       UUID NOT NULL,
    "kind"              TEXT NOT NULL,
    "ordinal"           INT  NOT NULL,
    -- The bom-ref as the document spelt it, served as evidence for an unresolved reference.
    "ref"               TEXT NOT NULL,
    -- The cipher suite that named the algorithm; NULL on a certificate's references.
    "suite"             TEXT,
    "target_asset_uuid" UUID,
    CONSTRAINT "uq_crypto_asset_reference" UNIQUE ("source_uuid", "kind", "ordinal"),
    CONSTRAINT "ck_crypto_asset_reference_kind" CHECK ("kind" IN
        ('SUBJECT_PUBLIC_KEY', 'SIGNATURE_ALGORITHM', 'CIPHER_SUITE_ALGORITHM')),
    CONSTRAINT "ck_crypto_asset_reference_ordinal" CHECK ("ordinal" >= 0),
    CONSTRAINT "crypto_asset_reference_to_source_key" FOREIGN KEY ("source_uuid")
        REFERENCES "crypto_asset_source" ("uuid") ON DELETE CASCADE,
    -- SET NULL, not CASCADE: a reference whose target left the inventory still says the certificate named a key.
    CONSTRAINT "crypto_asset_reference_to_target_key" FOREIGN KEY ("target_asset_uuid")
        REFERENCES "crypto_asset" ("uuid") ON DELETE SET NULL
);

-- uq_crypto_asset_reference leads with source_uuid, which serves the per-source read, the cascade and the sweep's
-- staleness test, which is driven from the referrer. The target index serves the SET NULL check.
CREATE INDEX "idx_crypto_asset_reference_target" ON "crypto_asset_reference" ("target_asset_uuid");

-- Freshness is a revision, not a time. Every write that changes what the rules read advances input_revision under the
-- row lock, and a stamp records the revision it evaluated; comparing transaction timestamps let a writer that began
-- before a sweep and committed after it leave a verdict on inputs the row no longer has.
ALTER TABLE "crypto_asset" ADD COLUMN "input_revision" BIGINT NOT NULL DEFAULT 0;
ALTER TABLE "crypto_asset" ADD COLUMN "pqc_evaluated_revision" BIGINT;
-- No verdict carries over as current. The old test cannot vouch for one -- a row still awaiting the previous rule
-- generation, or one a concurrent write left looking fresh, would be blessed for good -- so every row starts with no
-- evaluated revision and the first sweep after the upgrade re-evaluates the inventory once. That also moves every
-- certificate and protocol off the two removed rules, whether or not its document is ever re-ingested.

-- Documents ingested before this migration recorded no references, so their certificates and protocols would read as
-- naming nothing. Only a revision that still contributes one is re-offered: a superseded revision's links were
-- withdrawn, so it has no source rows and stays SYNCED, and the backlog never re-ingests it ahead of its successor.
-- Re-ingesting a contributing revision is an idempotent upsert.
-- The content-refusal count restarts with it: a document at the limit would otherwise get this one attempt and, if it
-- failed, never be offered again, leaving its certificates and protocols without references.
UPDATE "cbom" c SET "asset_sync_state" = 'PENDING', "asset_sync_content_refusals" = 0
WHERE c."asset_sync_state" = 'SYNCED'
  AND EXISTS (SELECT 1 FROM "crypto_asset_source" s JOIN "crypto_asset" a ON a."uuid" = s."asset_uuid"
              WHERE s."cbom_uuid" = c."uuid" AND a."asset_type" IN ('CERTIFICATE', 'PROTOCOL'));
