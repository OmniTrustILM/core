-- A hybrid scheme (X25519/X448, and every transitional pairing after it) reports one curve value holding both
-- members joined on '+'. Held as scalar TEXT, "show me every asset that touches curve25519" -- the sweep this
-- inventory exists to serve -- silently skipped exactly those rows. The column becomes an array so a curve can be
-- matched by membership; a single-curve asset is a one-element array and an absent curve stays NULL.
--
-- The identity preimage is unaffected: it keeps the '+'-joined spelling, so no row is re-keyed and the identity
-- rule-set version does not move. This is a projection change, not an identity change.
--
-- MERGE ORDER. Both statements below are free only while crypto_asset is empty, which it is in every environment
-- today: CryptoAssetWriter has no production caller (IdentityRuleset records this, and it is what makes the whole
-- inventory unpopulated). ALTER COLUMN ... TYPE takes ACCESS EXCLUSIVE and rewrites the table, and CREATE INDEX
-- blocks writes again. Behind ingest (core#2073) the same two statements are an outage-class migration on a
-- populated inventory, and CREATE INDEX CONCURRENTLY is not a remedy here -- Flyway runs the script in a
-- transaction, which that statement cannot join, and no migration in this repo sets executeInTransaction=false.
-- This must land before ingest does.

-- Dropped before the type change, not after: leaving it in place makes ALTER COLUMN TYPE rebuild a btree over the
-- new array type, which this migration then discards -- a full index build for nothing, inside the exclusive-lock
-- window.
DROP INDEX "idx_crypto_asset_curve";

-- NULLIF keeps an empty-string curve arriving as absent rather than as an empty array. string_to_array('', '+')
-- returns {}, which nothing downstream expects: CompositeCurve.join reports it as null while array_to_string
-- reports it as '', so one row would answer differently to the detail endpoint and to the PQC sweep, and
-- CryptographicAssetServiceImpl's all-fields-absent test would not fire for it. Unreachable for rows this codebase
-- wrote (CryptoAssetIdentityFields.fold maps blank to null), which is exactly why it belongs here: converting data
-- this codebase did not write is the statement's whole job. It also makes the NULL arm earn its place -- on its own
-- that arm is redundant, since string_to_array(NULL, '+') is already NULL.
ALTER TABLE "crypto_asset"
    ALTER COLUMN "curve" TYPE TEXT[]
        USING CASE WHEN NULLIF("curve", '') IS NULL THEN NULL ELSE string_to_array("curve", '+') END;

-- The btree answered equality on the scalar and cannot answer membership in an array. GIN can, but only for a
-- containment predicate: PostgreSQL has no index path for 'scalar = ANY(column)' at all, which is why the membership
-- filter is emitted as containment (PostgresFunctionContributor.ARRAY_CONTAINS_PATTERN). The pairing is pinned by
-- CryptoAssetCurveMembershipMigrationITest, which plans the shipped predicate against this index.
--
-- The trade this makes, measured on the pinned postgres:15-alpine with enable_seqscan = off: of the six conditions
-- the field now advertises, EQUALS gains an index path it never had, and EMPTY/NOT_EMPTY lose the one the btree
-- gave them -- array_ops GIN indexes elements, so it answers neither 'curve IS NULL' nor 'cardinality(curve) = 0',
-- and both plan a sequential scan. NOT_EQUALS and NOT_CONTAINS are negations OR'd with IS NULL and were never
-- index-answerable; CONTAINS goes through unnest + LIKE, which no index serves. EQUALS is the query this inventory
-- exists to answer and EMPTY is not, so the trade is taken deliberately. A partial index on (curve) WHERE curve IS
-- NULL would restore EMPTY if it ever earns one.
CREATE INDEX "idx_crypto_asset_curve" ON "crypto_asset" USING GIN ("curve");
