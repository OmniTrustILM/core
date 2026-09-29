-- The PQC rule set carries no version: there is one, unreleased, and a verdict is re-evaluated when the row it
-- describes changes. A later rule change re-offers every row by advancing i_upd in its own migration.
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

-- uq_crypto_asset_reference leads with source_uuid, which serves the per-source read and the cascade. The target
-- index serves the SET NULL check and the sweep's test for a target that moved since its referrer was evaluated.
CREATE INDEX "idx_crypto_asset_reference_target" ON "crypto_asset_reference" ("target_asset_uuid");

-- The two rules that returned notApplicable for every certificate and protocol are gone. Re-offering the rows they
-- decided moves them to an honest deferral within the hour, whether or not their document is ever re-ingested.
UPDATE "crypto_asset" SET "i_upd" = CURRENT_TIMESTAMP WHERE "asset_type" IN ('CERTIFICATE', 'PROTOCOL');

-- Documents ingested before this migration recorded no references, so their certificates and protocols would read as
-- naming nothing. Only a revision that still contributes one is re-offered: a superseded revision's links were
-- withdrawn, so it has no source rows and stays SYNCED, and the backlog never re-ingests it ahead of its successor.
-- Re-ingesting a contributing revision is an idempotent upsert.
UPDATE "cbom" c SET "asset_sync_state" = 'PENDING'
WHERE c."asset_sync_state" = 'SYNCED'
  AND EXISTS (SELECT 1 FROM "crypto_asset_source" s JOIN "crypto_asset" a ON a."uuid" = s."asset_uuid"
              WHERE s."cbom_uuid" = c."uuid" AND a."asset_type" IN ('CERTIFICATE', 'PROTOCOL'));
