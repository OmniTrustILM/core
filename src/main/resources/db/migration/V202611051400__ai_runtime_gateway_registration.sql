CREATE TABLE ai_runtime_gateway_deployment (
    role VARCHAR(32) PRIMARY KEY CHECK (role IN ('GATEWAY_RUN', 'GATEWAY_MANAGEMENT')),
    control_generation BIGINT NOT NULL CHECK (control_generation > 0),
    image_digest VARCHAR(71) NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    cluster VARCHAR(253) NOT NULL,
    namespace_name VARCHAR(253) NOT NULL,
    namespace_uid VARCHAR(253) NOT NULL,
    service_account_name VARCHAR(253) NOT NULL,
    service_account_uid VARCHAR(253) NOT NULL,
    template_digest VARCHAR(71) NOT NULL CHECK (template_digest ~ '^sha256:[0-9a-f]{64}$'),
    runtime_class VARCHAR(253) NOT NULL
);

CREATE TABLE ai_runtime_gateway_registration (
    role VARCHAR(32) NOT NULL REFERENCES ai_runtime_gateway_deployment(role),
    control_generation BIGINT NOT NULL CHECK (control_generation > 0),
    pod_name VARCHAR(253) NOT NULL,
    pod_uid UUID NOT NULL,
    observation_sequence BIGINT NOT NULL CHECK (observation_sequence > 0),
    evidence_id UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (role, pod_uid),
    CHECK (observed_at < valid_until AND valid_until <= observed_at + interval '30 seconds')
);
