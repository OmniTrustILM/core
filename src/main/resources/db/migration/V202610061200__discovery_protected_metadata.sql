-- Discovery keeps the metadata attributes a connector declares encrypted out of the staged metadata, encrypted
-- (core#2462). A row staged before this has no protected_meta, and its metadata reads as stored.
ALTER TABLE "discovery_certificate" ADD COLUMN "protected_meta" VARCHAR;
ALTER TABLE "discovery_item" ADD COLUMN "protected_meta" VARCHAR;

-- Rows of finished discoveries are never imported again, so their copies of encrypted attributes go; the objects
-- they were imported into keep those values, encrypted. Rows of a discovery still running keep theirs for the import.
UPDATE "discovery_certificate" AS "staged"
   SET "meta" = (SELECT COALESCE(jsonb_agg("element"."attribute" ORDER BY "element"."position"), '[]'::jsonb)
                   FROM jsonb_array_elements("staged"."meta") WITH ORDINALITY AS "element"("attribute", "position")
                  WHERE "element"."attribute" #>> '{properties,protectionLevel}' IS DISTINCT FROM 'encrypted')
 WHERE jsonb_typeof("staged"."meta") = 'array'
   AND jsonb_path_exists("staged"."meta", '$[*] ? (@.properties.protectionLevel == "encrypted")')
   AND "staged"."discovery_uuid" IN (SELECT "uuid" FROM "discovery"
                                      WHERE "status" IN ('COMPLETED', 'WARNING', 'FAILED', 'STOPPED', 'CANCELLED'));

UPDATE "discovery_item" AS "staged"
   SET "meta" = (SELECT COALESCE(jsonb_agg("element"."attribute" ORDER BY "element"."position"), '[]'::jsonb)
                   FROM jsonb_array_elements("staged"."meta") WITH ORDINALITY AS "element"("attribute", "position")
                  WHERE "element"."attribute" #>> '{properties,protectionLevel}' IS DISTINCT FROM 'encrypted')
 WHERE jsonb_typeof("staged"."meta") = 'array'
   AND jsonb_path_exists("staged"."meta", '$[*] ? (@.properties.protectionLevel == "encrypted")')
   AND "staged"."discovery_uuid" IN (SELECT "uuid" FROM "discovery"
                                      WHERE "status" IN ('COMPLETED', 'WARNING', 'FAILED', 'STOPPED', 'CANCELLED'));
