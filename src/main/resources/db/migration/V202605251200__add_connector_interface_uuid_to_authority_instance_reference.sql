ALTER TABLE authority_instance_reference
    ADD COLUMN connector_interface_uuid UUID
    REFERENCES connector_interface(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;

-- Backfill: link each authority instance to its connector's AUTHORITY interface row.
--
-- A connector may expose multiple AUTHORITY interface rows when it advertises both v2
-- and v3 side-by-side during migration. Pick the highest version deterministically so
-- the UPDATE never aborts with "more than one row returned by a subquery". Existing
-- authorities are pre-v3 so this resolves to v2 on coexisting connectors. v3 authorities
-- created via the service from M2 onward set the FK explicitly and bypass this backfill.
--
-- The FK stays NULL for authorities whose connector declares no connector_interface row.
-- That happens in two unrelated cases:
--   * connector framework v1 implementing the v2 authority wire protocol (e.g. ejbca-ng)
--   * legacy v1-authority connectors (AUTHORITY function group = LEGACY_AUTHORITY_PROVIDER)
-- Disambiguating these at the DB level is not possible from the schema; the factory
-- (AuthorityProviderAdapterFactory) handles NULL by routing to the v2 adapter, which is
-- correct for the framework-v1 + authority-v2 case. Legacy v1-authority connectors flow
-- through a separate service path that never consults this column.
UPDATE authority_instance_reference air
SET connector_interface_uuid = (
    SELECT ci.uuid
    FROM connector_interface ci
    WHERE ci.connector_uuid = air.connector_uuid
      AND ci.interface = 'AUTHORITY'
    ORDER BY ci.version DESC
    LIMIT 1
)
WHERE connector_interface_uuid IS NULL;
