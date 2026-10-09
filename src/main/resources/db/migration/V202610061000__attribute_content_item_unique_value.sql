-- Store each plaintext attribute value once per definition. Concurrent first writes, and turning a definition's
-- encryption off, could store a value twice, and every later write of it then failed. Fold existing duplicates, then
-- let a unique constraint keep it that way.
--
-- json_digest is the SHA-256 of the value's jsonb text, as the lookup by value computes it: key order and spacing
-- normalize away, a number's written precision does not, so 1.0 and 1.00 are two values. It is NULL for an encrypted
-- row, whose json is a placeholder shared by every value, so encrypted rows stay one per object, outside the rule.
--
-- A digest because a btree entry cannot hold a value over ~2.7 kB; SHA-256 because jsonb_hash_extended gives [{},{}]
-- and [[],[]] one hash and md5() fails on a FIPS-mode server. convert_to() is not immutable, so the text reaches
-- sha256() through decode(..., 'escape'), each backslash doubled because that format reads it as an escape. Adding the
-- stored column rewrites the table.

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
    ADD COLUMN "json_digest" BYTEA
        GENERATED ALWAYS AS (CASE WHEN "encrypted_data" IS NULL
                                  THEN sha256(decode(replace("json"::TEXT, chr(92), chr(92) || chr(92)), 'escape'))
                             END) STORED;

ALTER TABLE "attribute_content_item"
    ADD CONSTRAINT "uq_attribute_content_item_value" UNIQUE ("attribute_definition_uuid", "json_digest");

-- The constraint's index leads with the definition, so it answers every lookup by definition that the index from
-- V202609251800 was added for; keeping both would only double the upkeep on each write.
DROP INDEX IF EXISTS "idx_attribute_content_item_definition";
