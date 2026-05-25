ALTER TABLE authority_instance_reference
    ADD COLUMN connector_interface_uuid UUID
    REFERENCES connector_interface(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;

-- Backfill: link each authority instance to its connector's AUTHORITY interface row.
UPDATE authority_instance_reference air
SET connector_interface_uuid = (
    SELECT ci.uuid
    FROM connector_interface ci
    WHERE ci.connector_uuid = air.connector_uuid
      AND ci.interface = 'AUTHORITY'
)
WHERE connector_interface_uuid IS NULL;
