-- A certificate request belongs to the certificate it was submitted for. Earlier releases deleted neither the request
-- of a deleted certificate nor the one a rejected approval detached from its placeholder, so drop every request no
-- certificate refers to, with its attribute values and compliance profile associations.
DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'CERTIFICATE_REQUEST'
   AND NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "association"."object_uuid");

DELETE FROM "attribute_content_2_object" AS "mapping"
 WHERE "mapping"."object_type" = 'CERTIFICATE_REQUEST'
   AND NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "mapping"."object_uuid");

DELETE FROM "certificate_request" AS "request"
 WHERE NOT EXISTS (SELECT 1 FROM "certificate" WHERE "certificate"."certificate_request_uuid" = "request"."uuid");
