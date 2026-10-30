ALTER TABLE token_instance_reference
    ALTER COLUMN kind DROP NOT NULL,
    ALTER COLUMN token_instance_uuid DROP NOT NULL;

ALTER TABLE token_instance_reference
    ADD COLUMN connector_interface_uuid UUID
        REFERENCES connector_interface (uuid) ON UPDATE CASCADE ON DELETE RESTRICT;

-- Existing token instances use the legacy v1 provider flow and deliberately retain a NULL association.
CREATE INDEX idx_token_instance_reference_connector_interface_uuid
    ON token_instance_reference (connector_interface_uuid);
