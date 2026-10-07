-- Store each plaintext attribute value once per definition (core#1899). The lookup by value expects one row, and two
-- writers storing the same new value at once used to insert it twice, after which every write of that value failed.
-- Turning a definition's encryption off did the same, one row per object that held the value.
--
-- Fold what is already duplicated, then let a unique constraint keep it that way. json_hash follows jsonb equality, as
-- the lookup by value does. It is NULL for an encrypted row: the value lives in salted ciphertext, so equal values never
-- share a json and stay one row per object, outside the rule, since NULLs never collide in a unique constraint. A hash
-- rather than the jsonb itself, because a btree entry cannot hold a value over ~2.7 kB; jsonb_hash_extended rather than
-- a cryptographic digest, which a FIPS-mode server may refuse to compute. Adding the stored column rewrites the table.

CREATE TEMP TABLE "attribute_content_item_merge" ON COMMIT DROP AS
SELECT "uuid" AS "duplicate_uuid", "keep_uuid"
  FROM (SELECT "uuid",
               first_value("uuid") OVER (PARTITION BY "attribute_definition_uuid", "json" ORDER BY "uuid")
                   AS "keep_uuid"
          FROM "attribute_content_item"
         WHERE "encrypted_data" IS NULL) AS "ranked"
 WHERE "uuid" <> "keep_uuid";

UPDATE "attribute_content_2_object" AS "mapping"
   SET "attribute_content_item_uuid" = "merge"."keep_uuid"
  FROM "attribute_content_item_merge" AS "merge"
 WHERE "mapping"."attribute_content_item_uuid" = "merge"."duplicate_uuid";

-- An object mapped to more than one of the folded rows now holds the same mapping twice: keep one.
DELETE FROM "attribute_content_2_object" AS "mapping"
 USING "attribute_content_2_object" AS "kept"
 WHERE "mapping"."attribute_content_item_uuid" IN (SELECT "keep_uuid" FROM "attribute_content_item_merge")
   AND "kept"."attribute_content_item_uuid" = "mapping"."attribute_content_item_uuid"
   AND "kept"."uuid" < "mapping"."uuid"
   AND "kept"."object_type" = "mapping"."object_type"
   AND "kept"."object_uuid" = "mapping"."object_uuid"
   AND "kept"."connector_uuid" IS NOT DISTINCT FROM "mapping"."connector_uuid"
   AND "kept"."source_object_type" IS NOT DISTINCT FROM "mapping"."source_object_type"
   AND "kept"."source_object_uuid" IS NOT DISTINCT FROM "mapping"."source_object_uuid"
   AND "kept"."purpose" IS NOT DISTINCT FROM "mapping"."purpose"
   AND "kept"."object_version" IS NOT DISTINCT FROM "mapping"."object_version";

DELETE FROM "attribute_content_item" AS "item"
 USING "attribute_content_item_merge" AS "merge"
 WHERE "item"."uuid" = "merge"."duplicate_uuid";

ALTER TABLE "attribute_content_item"
    ADD COLUMN "json_hash" BIGINT
        GENERATED ALWAYS AS (CASE WHEN "encrypted_data" IS NULL THEN jsonb_hash_extended("json", 0) END) STORED;

ALTER TABLE "attribute_content_item"
    ADD CONSTRAINT "uq_attribute_content_item_value" UNIQUE ("attribute_definition_uuid", "json_hash");

-- The constraint's index leads with the definition, so it answers every lookup by definition that the index from
-- V202609251800 was added for; keeping both would only double the upkeep on each write.
DROP INDEX IF EXISTS "idx_attribute_content_item_definition";
