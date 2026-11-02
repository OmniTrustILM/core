-- Deleting an object kept its compliance profile associations.
-- The compliance profile then counted them and could only be deleted with force.
DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'RA_PROFILE'
   AND NOT EXISTS (SELECT 1 FROM "ra_profile" AS "object" WHERE "object"."uuid" = "association"."object_uuid");

DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'TOKEN_PROFILE'
   AND NOT EXISTS (SELECT 1 FROM "token_profile" AS "object" WHERE "object"."uuid" = "association"."object_uuid");

DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'VAULT_PROFILE'
   AND NOT EXISTS (SELECT 1 FROM "vault_profile" AS "object" WHERE "object"."uuid" = "association"."object_uuid");

DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'CERTIFICATE'
   AND NOT EXISTS (SELECT 1 FROM "certificate" AS "object" WHERE "object"."uuid" = "association"."object_uuid");

-- A certificate request counts as existing while a certificate refers to it.
DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'CERTIFICATE_REQUEST'
   AND NOT EXISTS (SELECT 1
                     FROM "certificate" AS "object"
                    WHERE "object"."certificate_request_uuid" = "association"."object_uuid");

DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'CRYPTOGRAPHIC_KEY'
   AND NOT EXISTS (SELECT 1
                     FROM "cryptographic_key" AS "object"
                    WHERE "object"."uuid" = "association"."object_uuid");

DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'CRYPTOGRAPHIC_KEY_ITEM'
   AND NOT EXISTS (SELECT 1
                     FROM "cryptographic_key_item" AS "object"
                    WHERE "object"."uuid" = "association"."object_uuid");

DELETE FROM "compliance_profile_association" AS "association"
 WHERE "association"."resource" = 'SECRET'
   AND NOT EXISTS (SELECT 1 FROM "secret" AS "object" WHERE "object"."uuid" = "association"."object_uuid");
