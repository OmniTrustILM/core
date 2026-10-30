-- Revert the DOCUMENT_SIGNING signing workflow type back to CONTENT_SIGNING.
-- Compensates V202608121000__rename_content_signing_to_document_signing.sql, which is kept
-- in place because it may already have been applied in existing environments.
UPDATE "signing_profile_version"
   SET "workflow_type" = 'CONTENT_SIGNING'
 WHERE "workflow_type" = 'DOCUMENT_SIGNING';

-- Denormalized cache of the latest signing_profile_version row.
UPDATE "signing_profile"
   SET "workflow_type" = 'CONTENT_SIGNING'
 WHERE "workflow_type" = 'DOCUMENT_SIGNING';

-- connector_interface.features stores enum names in a text array, so the persisted
-- feature value requires the same replacement.
UPDATE "connector_interface"
   SET "features" = array_replace("features", 'DOCUMENT_SIGNING', 'CONTENT_SIGNING')
 WHERE 'DOCUMENT_SIGNING' = ANY ("features");
