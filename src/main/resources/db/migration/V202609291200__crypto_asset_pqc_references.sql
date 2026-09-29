-- The PQC rule set carries no version: there is one, unreleased, and a verdict is re-evaluated when the row it
-- describes changes. A later rule change re-offers every row by advancing i_upd in its own migration.
DROP INDEX IF EXISTS "idx_crypto_asset_pqc_ruleset_version";
ALTER TABLE "crypto_asset" DROP COLUMN "pqc_ruleset_version";

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

-- Documents ingested before this migration recorded no references, so their certificates and protocols would read as
-- naming nothing. Re-ingesting them is an idempotent upsert; a superseded revision settles as superseded again.
UPDATE "cbom" SET "asset_sync_state" = 'PENDING' WHERE "asset_sync_state" = 'SYNCED';
