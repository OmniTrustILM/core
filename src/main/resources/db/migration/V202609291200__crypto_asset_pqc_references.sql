-- The PQC rule set carries no version: there is one, unreleased, and a verdict is re-evaluated when the row it
-- describes changes. A later rule change re-offers every row by advancing i_upd in its own migration.
DROP INDEX IF EXISTS "idx_crypto_asset_pqc_ruleset_version";
ALTER TABLE "crypto_asset" DROP COLUMN "pqc_ruleset_version";
