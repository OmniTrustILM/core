-- Rename the CONTENT_SIGNING signing workflow type to DOCUMENT_SIGNING.
UPDATE "signing_profile_version"
   SET "workflow_type" = 'DOCUMENT_SIGNING'
 WHERE "workflow_type" = 'CONTENT_SIGNING';

-- Denormalized cache of the latest signing_profile_version row.
UPDATE "signing_profile"
   SET "workflow_type" = 'DOCUMENT_SIGNING'
 WHERE "workflow_type" = 'CONTENT_SIGNING';

-- connector_interface.features stores enum names in a text array, so the persisted
-- feature value requires the same replacement.
UPDATE "connector_interface"
   SET "features" = array_replace("features", 'CONTENT_SIGNING', 'DOCUMENT_SIGNING')
 WHERE 'CONTENT_SIGNING' = ANY ("features");
