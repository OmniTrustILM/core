CREATE TABLE ai_runtime_control
(
    id                       SMALLINT     NOT NULL PRIMARY KEY CHECK (id = 1),
    generation               BIGINT       NOT NULL CHECK (generation >= 1),
    enabled                  BOOLEAN      NOT NULL DEFAULT FALSE,
    image_digest             VARCHAR(71)  CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    profile_revision         BIGINT       CHECK (profile_revision >= 1),
    security_revision        BIGINT       CHECK (security_revision >= 1),
    trust_revision           BIGINT       CHECK (trust_revision >= 1),
    protocol                 VARCHAR(16)  CHECK (protocol = 'v1'),
    cluster                  VARCHAR(128) CHECK (btrim(cluster) <> ''),
    namespace_name           VARCHAR(63)  CHECK (btrim(namespace_name) <> ''),
    namespace_uid            VARCHAR(128) CHECK (btrim(namespace_uid) <> ''),
    service_account_name     VARCHAR(253) CHECK (btrim(service_account_name) <> ''),
    service_account_uid      VARCHAR(128) CHECK (btrim(service_account_uid) <> ''),
    template_digest          VARCHAR(71)  CHECK (template_digest ~ '^sha256:[0-9a-f]{64}$'),
    runtime_class            VARCHAR(253) CHECK (btrim(runtime_class) <> ''),
    observation_sequence     BIGINT       NOT NULL DEFAULT 0 CHECK (observation_sequence >= 0),
    evidence_id              UUID,
    observed_at              TIMESTAMPTZ,
    valid_until              TIMESTAMPTZ,
    created_at               TIMESTAMPTZ  NOT NULL,
    updated_at               TIMESTAMPTZ  NOT NULL,
    CONSTRAINT ck_ai_runtime_control_pins CHECK (
        (image_digest IS NULL AND profile_revision IS NULL AND security_revision IS NULL AND trust_revision IS NULL
            AND protocol IS NULL AND cluster IS NULL AND namespace_name IS NULL AND namespace_uid IS NULL
            AND service_account_name IS NULL AND service_account_uid IS NULL AND template_digest IS NULL
            AND runtime_class IS NULL AND enabled = FALSE)
        OR (image_digest IS NOT NULL AND profile_revision IS NOT NULL AND security_revision IS NOT NULL
            AND trust_revision IS NOT NULL AND protocol IS NOT NULL AND cluster IS NOT NULL
            AND namespace_name IS NOT NULL AND namespace_uid IS NOT NULL AND service_account_name IS NOT NULL
            AND service_account_uid IS NOT NULL AND template_digest IS NOT NULL AND runtime_class IS NOT NULL)),
    CONSTRAINT ck_ai_runtime_control_evidence CHECK (
        (observation_sequence = 0 AND evidence_id IS NULL AND observed_at IS NULL AND valid_until IS NULL)
        OR (observation_sequence > 0 AND evidence_id IS NOT NULL AND observed_at IS NOT NULL
            AND valid_until IS NOT NULL AND observed_at < valid_until AND image_digest IS NOT NULL))
);

INSERT INTO ai_runtime_control (id, generation, enabled, observation_sequence, created_at, updated_at)
SELECT 1, 1, FALSE, 0, at, at FROM (SELECT clock_timestamp() AS at) initial;

ALTER TABLE ai_runtime_run
    ADD COLUMN control_generation BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT ck_ai_runtime_run_control_generation CHECK (control_generation >= 0),
    ADD CONSTRAINT uq_ai_runtime_run_control_generation UNIQUE (uuid, control_generation);

ALTER TABLE ai_runtime_attempt
    ADD COLUMN control_generation BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT ck_ai_runtime_attempt_control_generation CHECK (control_generation >= 0),
    ADD CONSTRAINT fk_ai_runtime_attempt_control_generation FOREIGN KEY (run_uuid, control_generation)
        REFERENCES ai_runtime_run (uuid, control_generation) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ai_runtime_run ALTER COLUMN control_generation DROP DEFAULT;
ALTER TABLE ai_runtime_attempt ALTER COLUMN control_generation DROP DEFAULT;
