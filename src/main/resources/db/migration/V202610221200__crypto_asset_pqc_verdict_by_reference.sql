-- A key takes the verdict of the algorithm its CBOM references, and a protocol evaluates the groups, signature
-- schemes, protocol-level algorithms and IKEv2 key exchange methods it offers. The ingest records three more kinds of
-- reference for that.
ALTER TABLE "crypto_asset_reference" DROP CONSTRAINT "ck_crypto_asset_reference_kind";
ALTER TABLE "crypto_asset_reference" ADD CONSTRAINT "ck_crypto_asset_reference_kind" CHECK ("kind" IN
    ('SUBJECT_PUBLIC_KEY', 'SIGNATURE_ALGORITHM', 'CIPHER_SUITE_ALGORITHM', 'ALGORITHM', 'PROTOCOL_ALGORITHM',
     'KEY_EXCHANGE_TRANSFORM'));

-- The rules for keys and protocols changed, and a certificate's verdict is its key's. Advancing input_revision
-- re-offers the rows to the sweep, which restamps them; an algorithm's rules did not move.
UPDATE "crypto_asset" SET "input_revision" = "input_revision" + 1
WHERE "asset_type" IN ('RELATED_CRYPTO_MATERIAL', 'CERTIFICATE', 'PROTOCOL');

-- References are recorded at ingest only, and a document ingested before this migration recorded none for its keys
-- and protocols, so every key would read as naming no algorithm. Only a revision that still contributes a key or a
-- protocol is re-offered: a superseded revision has no source rows left and stays SYNCED. Re-ingesting a contributing
-- revision is an idempotent upsert. The content-refusal count restarts with it, so a document at the limit gets its
-- attempts back rather than one chance.
UPDATE "cbom" c SET "asset_sync_state" = 'PENDING', "asset_sync_content_refusals" = 0
WHERE c."asset_sync_state" = 'SYNCED'
  AND EXISTS (SELECT 1 FROM "crypto_asset_source" s JOIN "crypto_asset" a ON a."uuid" = s."asset_uuid"
              WHERE s."cbom_uuid" = c."uuid" AND a."asset_type" IN ('RELATED_CRYPTO_MATERIAL', 'PROTOCOL'));
