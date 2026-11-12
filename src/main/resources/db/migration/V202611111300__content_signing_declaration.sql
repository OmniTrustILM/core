-- Core keeps the content-signing declaration it read from a formatting connector on the last connect or reconnect,
-- one row per connector.
CREATE TABLE connector_content_signing_declaration (
    connector_uuid UUID NOT NULL PRIMARY KEY,
    declaration JSONB NOT NULL,
    CONSTRAINT fk_connector_content_signing_declaration_connector
        FOREIGN KEY (connector_uuid) REFERENCES connector (uuid) ON DELETE CASCADE
);

-- One interface code serves every family. Each formatting connector image serves a single family. No connector
-- therefore carries two of the old codes at one version.
UPDATE connector_interface
SET interface = 'CONTENT_SIGNING_FORMATTING'
WHERE interface IN ('PADES_FORMATTING', 'XADES_FORMATTING', 'CADES_FORMATTING', 'JADES_FORMATTING');

-- The interface code says the connector serves content signing. Its declaration names the levels each family reaches.
-- These flags therefore carry nothing.
UPDATE connector_interface
SET features = array_remove(array_remove(array_remove(array_remove(features,
        'CONTENT_SIGNING'), 'LEVEL_TIMESTAMPED'), 'LEVEL_LONG_TERM'), 'LEVEL_ARCHIVAL')
WHERE features && ARRAY ['CONTENT_SIGNING', 'LEVEL_TIMESTAMPED', 'LEVEL_LONG_TERM', 'LEVEL_ARCHIVAL']::TEXT[];

-- The family column held enum names such as PADES and now holds the family code.
UPDATE signing_profile_version
SET signature_family = lower(signature_family)
WHERE signature_family IS NOT NULL;
