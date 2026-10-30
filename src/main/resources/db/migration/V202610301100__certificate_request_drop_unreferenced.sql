-- Certificates are looked up by their request when one is deleted and when a request's compliance result is
-- authorized. Uploaded and discovered certificates have no request, so the index holds the others; it is built first
-- so the deletes below use it.
--
-- CREATE INDEX blocks writes to certificate while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX IF NOT EXISTS "idx_certificate_certificate_request_uuid" ON "certificate" ("certificate_request_uuid")
    WHERE "certificate_request_uuid" IS NOT NULL;

-- Earlier releases deleted neither a deleted certificate's request nor one a rejected approval detached, so drop
-- every request no certificate refers to, with its attribute values and compliance profile associations.
DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'CERTIFICATE_REQUEST'
   AND NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "association"."object_uuid");

DELETE FROM "attribute_content_2_object" AS "mapping"
 WHERE "mapping"."object_type" = 'CERTIFICATE_REQUEST'
   AND NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "mapping"."object_uuid");

DELETE FROM "certificate_request" AS "request"
 WHERE NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "request"."uuid");
