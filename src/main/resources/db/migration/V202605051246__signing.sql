-- ── 1. signing_profile header
-- signing_scheme and workflow_type are denormalized cache columns that mirror the latest signing_profile_version row. Updated on every create/update.
CREATE TABLE "signing_profile"
(
    "uuid"                     UUID    NOT NULL,
    "name"                     VARCHAR NOT NULL,
    "description"              TEXT,
    "enabled"                  BOOLEAN NOT NULL DEFAULT FALSE,
    "signing_scheme"           VARCHAR NOT NULL, -- cache: MANAGED | DELEGATED
    "workflow_type"            VARCHAR NOT NULL, -- cache: CONTENT_SIGNING | RAW_SIGNING | TIMESTAMPING
    "latest_version"           INTEGER NOT NULL DEFAULT 1,
    "time_quality_config_uuid" UUID REFERENCES "time_quality_configuration" ("uuid") ON DELETE RESTRICT,
    "tsp_profile_uuid"         UUID,
    "i_author"                 VARCHAR,
    "i_cre"                    TIMESTAMP        DEFAULT NOW(),
    "i_upd"                    TIMESTAMP        DEFAULT NOW(),
    PRIMARY KEY ("uuid"),
    UNIQUE ("name")
);

-- ── 2. signing_profile_version
CREATE TABLE "signing_profile_version"
(
    "uuid"                               UUID    NOT NULL,
    "signing_profile_uuid"               UUID    NOT NULL,
    "version"                            INTEGER NOT NULL,
    -- scheme (authoritative)
    "signing_scheme"                     VARCHAR NOT NULL,
    "managed_signing_type"               VARCHAR,
    "token_profile_uuid"                 UUID    REFERENCES "token_profile" ("uuid") ON DELETE SET NULL,
    "certificate_uuid"                   UUID    REFERENCES "certificate" ("uuid") ON DELETE SET NULL,
    "ra_profile_uuid"                    UUID    REFERENCES "ra_profile" ("uuid") ON DELETE SET NULL,
    "csr_template_uuid"                  UUID,
    "delegated_signer_connector_uuid"    UUID    REFERENCES "connector" ("uuid") ON DELETE SET NULL,
    -- workflow (authoritative)
    "workflow_type"                      VARCHAR NOT NULL,
    "signature_formatter_connector_uuid" UUID    REFERENCES "connector" ("uuid") ON DELETE SET NULL,
    "qualified_timestamp"                BOOLEAN,
    "default_policy_id"                  VARCHAR,
    "allowed_policy_ids"                 TEXT[],
    "allowed_digest_algorithms"          TEXT[],
    "validate_token_signature"           BOOLEAN,
    "i_author"                           VARCHAR,
    "i_cre"                              TIMESTAMP DEFAULT NOW(),
    "i_upd"                              TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY ("uuid"),
    UNIQUE ("signing_profile_uuid", "version"),
    FOREIGN KEY ("signing_profile_uuid") REFERENCES "signing_profile" ("uuid") ON DELETE CASCADE
);

-- ── 3. Circular FK resolution: signing_profile ↔ tsp_profile ──────────────────────
ALTER TABLE "tsp_profile"
    ADD COLUMN "default_signing_profile_uuid" UUID;

ALTER TABLE "signing_profile"
    ADD CONSTRAINT fk_signing_profile_tsp_profile
        FOREIGN KEY ("tsp_profile_uuid")
            REFERENCES "tsp_profile" ("uuid") ON DELETE SET NULL;

ALTER TABLE "tsp_profile"
    ADD CONSTRAINT fk_tsp_default_signing_profile
        FOREIGN KEY ("default_signing_profile_uuid")
            REFERENCES "signing_profile" ("uuid") ON DELETE RESTRICT;
