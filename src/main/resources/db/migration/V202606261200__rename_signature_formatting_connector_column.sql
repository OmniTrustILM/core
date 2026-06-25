-- Rename the signing_profile_version formatter-connector reference from the old
-- "Signature Formatter" naming to the canonical "Signature Formatting Provider"
-- (OmniTrustILM/ilm#258). The column and its index are renamed in place; the FK
-- to "connector"("uuid") is preserved by RENAME COLUMN.
ALTER TABLE "signing_profile_version"
    RENAME COLUMN "signature_formatter_connector_uuid" TO "signature_formatting_connector_uuid";

ALTER INDEX idx_spv_signature_formatter_connector_uuid
    RENAME TO idx_spv_signature_formatting_connector_uuid;
