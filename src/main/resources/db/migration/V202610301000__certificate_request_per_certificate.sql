-- Gives every certificate its own certificate request and drops requests no certificate refers to.

-- Certificates are looked up by their request on delete and when a request's compliance result is authorized; the
-- index skips uploaded and discovered certificates, which have no request.
--
-- CREATE INDEX blocks writes to certificate; Flyway's transaction rules out CONCURRENTLY. The lock lasts until
-- commit, so the previous release cannot repoint a certificate during the split below.
CREATE INDEX IF NOT EXISTS "idx_certificate_certificate_request_uuid" ON "certificate" ("certificate_request_uuid")
    WHERE "certificate_request_uuid" IS NOT NULL;

-- The oldest certificate keeps a shared row; each other one gets a copy of all its columns (read from the catalog) and
-- attribute values, compliance result included, as the row does not record whose it is. Associations stay on the row.
CREATE TEMP TABLE "certificate_request_split" ON COMMIT DROP AS
SELECT "ranked"."uuid" AS "certificate_uuid", "ranked"."certificate_request_uuid" AS "request_uuid",
       gen_random_uuid() AS "copy_uuid"
  FROM (SELECT "uuid", "certificate_request_uuid",
               row_number() OVER (PARTITION BY "certificate_request_uuid" ORDER BY "i_cre", "uuid") AS "position"
          FROM "certificate"
         WHERE "certificate_request_uuid" IS NOT NULL) AS "ranked"
 WHERE "ranked"."position" > 1;

DO $$
DECLARE
    request_columns TEXT;
    copied_request_columns TEXT;
    mapping_columns TEXT;
    copied_mapping_columns TEXT;
BEGIN
    SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position),
           string_agg('"request".' || quote_ident(column_name), ', ' ORDER BY ordinal_position)
      INTO request_columns, copied_request_columns
      FROM information_schema.columns
     WHERE table_schema = current_schema() AND table_name = 'certificate_request' AND column_name <> 'uuid';
    EXECUTE format('INSERT INTO "certificate_request" ("uuid", %s)'
                   ' SELECT "split"."copy_uuid", %s'
                   '   FROM "certificate_request_split" AS "split"'
                   '   JOIN "certificate_request" AS "request" ON "request"."uuid" = "split"."request_uuid"',
                   request_columns, copied_request_columns);

    SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position),
           string_agg('"mapping".' || quote_ident(column_name), ', ' ORDER BY ordinal_position)
      INTO mapping_columns, copied_mapping_columns
      FROM information_schema.columns
     WHERE table_schema = current_schema() AND table_name = 'attribute_content_2_object'
       AND column_name NOT IN ('uuid', 'object_uuid');
    EXECUTE format('INSERT INTO "attribute_content_2_object" ("uuid", "object_uuid", %s)'
                   ' SELECT gen_random_uuid(), "split"."copy_uuid", %s'
                   '   FROM "certificate_request_split" AS "split"'
                   '   JOIN "attribute_content_2_object" AS "mapping"'
                   '     ON "mapping"."object_type" = ''CERTIFICATE_REQUEST'''
                   '    AND "mapping"."object_uuid" = "split"."request_uuid"',
                   mapping_columns, copied_mapping_columns);
END
$$;

UPDATE "certificate"
   SET "certificate_request_uuid" = "split"."copy_uuid"
  FROM "certificate_request_split" AS "split"
 WHERE "certificate"."uuid" = "split"."certificate_uuid"
   AND "certificate"."certificate_request_uuid" = "split"."request_uuid";

DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'CERTIFICATE_REQUEST'
   AND NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "association"."object_uuid");

DELETE FROM "attribute_content_2_object" AS "mapping"
 WHERE "mapping"."object_type" = 'CERTIFICATE_REQUEST'
   AND NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "mapping"."object_uuid");

DELETE FROM "certificate_request" AS "request"
 WHERE NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "request"."uuid");
