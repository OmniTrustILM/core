-- Discovery no longer stores metadata values ahead of import (core#1899). Storing them up front only made the race a
-- unique constraint now closes less likely. Rows it stored that no object took up are read by nothing: every reader
-- reaches a content item through a mapping.
DELETE FROM "attribute_content_item" AS "item"
 WHERE NOT EXISTS (SELECT 1
                     FROM "attribute_content_2_object" AS "mapping"
                    WHERE "mapping"."attribute_content_item_uuid" = "item"."uuid");
