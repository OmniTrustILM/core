ALTER TABLE authority_instance_reference
    ADD COLUMN connector_interface_uuid UUID
    REFERENCES connector_interface(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;

-- Backfill: link each existing authority instance to its connector's AUTHORITY interface row.
--
-- Every authority touched by this backfill predates v3 (v3 authorities created via the service
-- set the FK explicitly and are excluded by the WHERE clause below). They must therefore resolve
-- to the v2 AUTHORITY interface. A connector may expose multiple AUTHORITY rows when it advertises
-- v2 and v3 side-by-side, so the subquery prefers v2 explicitly (then orders by version for
-- determinism) — this both avoids "more than one row returned by a subquery" and guarantees the
-- v2 resolution regardless of which connector versions happen to be registered at migration time.
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
    ORDER BY CASE WHEN ci.version = 'v2' THEN 0 ELSE 1 END, ci.version
    LIMIT 1
)
WHERE connector_interface_uuid IS NULL;
