-- Gives every certificate a certificate request of its own. Earlier releases stored an identical CSR once and pointed
-- every certificate submitted with it at that row, so the compliance result kept on the row was overwritten by
-- whichever RA profile checked it last, and that result gated the issuance of all of them.
--
-- The oldest certificate keeps the row, and every other certificate gets a copy of it. A copy keeps every column of the
-- row, the stored compliance result included: the row does not record which certificate that result was computed for,
-- so each certificate shows what it showed before until it is checked again. The result gates nothing any more: a
-- request is checked for issuance only when it is submitted. The attribute values submitted with the request are mapped
-- to each copy as well. Compliance profile associations name the request itself, so they stay with the row the oldest
-- certificate keeps.
--
-- The columns are read from the catalog, so a copy carries every column the table has when this runs.
--
-- The previous release keeps running during a rolling update. A certificate it detaches from the shared request, or
-- points elsewhere, while this runs is left as it is; the copy made for it is then unreferenced, and the sweep that
-- follows drops it. A certificate it points at a stored request after this runs shares that request from then on.

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
