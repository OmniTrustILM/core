-- A hybrid scheme (X25519/X448, and every transitional pairing after it) reports one curve value holding both
-- members joined on '+'. Held as scalar TEXT, "show me every asset that touches curve25519" -- the sweep this
-- inventory exists to serve -- silently skipped exactly those rows. The column becomes an array so a curve can be
-- matched by membership; a single-curve asset is a one-element array and an absent curve stays NULL.
--
-- The identity preimage is unaffected: it keeps the '+'-joined spelling, so no row is re-keyed and the identity
-- rule-set version does not move. This is a projection change, not an identity change.
ALTER TABLE "crypto_asset"
    ALTER COLUMN "curve" TYPE TEXT[] USING CASE WHEN "curve" IS NULL THEN NULL ELSE string_to_array("curve", '+') END;

-- The btree answered equality on the scalar and cannot answer membership in an array. GIN can, but only for a
-- containment predicate: PostgreSQL has no index path for 'scalar = ANY(column)' at all, which is why the membership
-- filter is emitted as containment (PostgresFunctionContributor.ARRAY_CONTAINS_PATTERN). The pairing is pinned by
-- CryptoAssetCurveMembershipMigrationITest, which plans the shipped predicate against this index.
DROP INDEX "idx_crypto_asset_curve";

CREATE INDEX "idx_crypto_asset_curve" ON "crypto_asset" USING GIN ("curve");
