-- Discovery registered every metadata value ahead of import in plaintext, those of definitions that keep their values
-- encrypted included. The import stores such values encrypted, one row per object, and never maps those
-- plaintext rows, so nothing reads them.
DELETE FROM "attribute_content_item" AS "item"
 USING "attribute_definition" AS "definition"
 WHERE "definition"."uuid" = "item"."attribute_definition_uuid"
   AND "definition"."protection_level" = 'ENCRYPTED'
   AND "item"."encrypted_data" IS NULL
   AND NOT EXISTS (SELECT 1
                     FROM "attribute_content_2_object" AS "mapping"
                    WHERE "mapping"."attribute_content_item_uuid" = "item"."uuid");
