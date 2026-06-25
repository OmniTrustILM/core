-- Rename the signing_profile_version formatter-connector reference from the old
-- "Signature Formatter" naming to the canonical "Signature Formatting Provider"
-- (OmniTrustILM/ilm#258). The column and its index are renamed in place; the FK
-- to "connector"("uuid") is preserved by RENAME COLUMN.
ALTER TABLE "signing_profile_version"
    RENAME COLUMN "signature_formatter_connector_uuid" TO "signature_formatting_connector_uuid";

ALTER INDEX idx_spv_signature_formatter_connector_uuid
    RENAME TO idx_spv_signature_formatting_connector_uuid;

-- Rename the attribute-engine operation scope for signing-profile workflow
-- formatting attributes ("workflowFormatter" -> "workflowFormatting"). The value
-- is persisted in attribute_definition.operation and all attribute-content reads
-- join on it, so existing rows must be updated in place to avoid orphaning the
-- formatting attribute data of existing signing profiles.
UPDATE "attribute_definition"
   SET operation = 'workflowFormatting'
 WHERE operation = 'workflowFormatter';
