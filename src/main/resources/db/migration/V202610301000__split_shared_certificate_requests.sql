-- Gives every certificate a request of its own. Earlier releases shared one row among all certificates submitted with
-- an identical CSR, so its compliance result, written by whichever RA profile checked it last, gated all of them.
--
-- The oldest certificate keeps the row; every other one gets a copy with all its columns (read from the catalog) and
-- attribute values. Copies keep the stored compliance result, as the row does not record whose it is; it gates
-- nothing now, since a request is checked only when it is submitted. Compliance profile associations stay on the row.
--
-- The previous release keeps running during a rolling update. A certificate it repoints while this runs is left as it
-- is, and the copy made for it is dropped by the sweep that follows. One it points at a stored request afterwards
-- keeps sharing that request.

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
