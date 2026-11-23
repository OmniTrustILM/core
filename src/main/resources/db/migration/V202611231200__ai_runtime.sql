-- Runtime kernel
CREATE TABLE ai_runtime_run
(
    uuid                 UUID        NOT NULL PRIMARY KEY,
    conversation_ref     UUID,
    actor_uuid           UUID        NOT NULL,
    scope_marker         VARCHAR(64) NOT NULL CHECK (btrim(scope_marker) <> ''),
    state                VARCHAR(24) NOT NULL CHECK (state IN ('QUEUED', 'RUNNING', 'FAILED', 'CANCELLED', 'LIMIT_REACHED')),
    revision             BIGINT      NOT NULL CHECK (revision >= 1),
    fence                BIGINT      NOT NULL CHECK (fence >= 1),
    attempts_used        INTEGER     NOT NULL CHECK (attempts_used >= 1),
    attempt_limit        INTEGER     NOT NULL CHECK (attempt_limit BETWEEN 1 AND 10 AND attempts_used <= attempt_limit),
    current_attempt_uuid UUID        NOT NULL,
    run_deadline         TIMESTAMPTZ NOT NULL,
    lease_seconds        INTEGER     NOT NULL CHECK (lease_seconds BETWEEN 1 AND 60),
    pod_limit            INTEGER     NOT NULL CHECK (pod_limit BETWEEN 2 AND 16),
    created_at           TIMESTAMPTZ NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX uq_ai_runtime_live_conversation ON ai_runtime_run (conversation_ref)
    WHERE conversation_ref IS NOT NULL AND state IN ('QUEUED', 'RUNNING');

CREATE TABLE ai_runtime_attempt
(
    uuid                    UUID         NOT NULL PRIMARY KEY,
    run_uuid                UUID         NOT NULL REFERENCES ai_runtime_run (uuid),
    attempt_no              INTEGER      NOT NULL CHECK (attempt_no BETWEEN 1 AND 10),
    state                   VARCHAR(24)  NOT NULL CHECK (state IN ('LAUNCHING', 'CLAIMED', 'FENCED')),
    failure_reason          VARCHAR(32)  CHECK (failure_reason IN ('LAUNCH_EXPIRED', 'LEASE_EXPIRED', 'PENDING_EXHAUSTED',
                                            'OBSERVATION_EXPIRED', 'JOB_CONFLICT', 'CANCELLED', 'INVALIDATED')),
    fence                   BIGINT       NOT NULL CHECK (fence >= 1),
    image_digest            VARCHAR(71)  NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    profile_revision        BIGINT       NOT NULL CHECK (profile_revision >= 1),
    security_revision       BIGINT       NOT NULL CHECK (security_revision >= 1),
    trust_revision          BIGINT       NOT NULL CHECK (trust_revision >= 1),
    protocol                VARCHAR(16)  NOT NULL CHECK (protocol = 'v1'),
    launch_deadline         TIMESTAMPTZ  NOT NULL,
    max_deadline            TIMESTAMPTZ  NOT NULL CHECK (launch_deadline <= max_deadline),
    winner_cluster          VARCHAR(128),
    winner_pod_uid          VARCHAR(128),
    claim_uuid              UUID         UNIQUE,
    lease_until             TIMESTAMPTZ,
    last_heartbeat_sequence BIGINT       CHECK (last_heartbeat_sequence >= 0),
    last_heartbeat_lease    TIMESTAMPTZ,
    created_at              TIMESTAMPTZ  NOT NULL,
    updated_at              TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uq_ai_runtime_attempt_number UNIQUE (run_uuid, attempt_no),
    CONSTRAINT uq_ai_runtime_attempt_run_uuid UNIQUE (run_uuid, uuid),
    CONSTRAINT ck_ai_runtime_claim_fields CHECK (
        (winner_cluster IS NULL AND winner_pod_uid IS NULL AND claim_uuid IS NULL AND lease_until IS NULL
            AND last_heartbeat_sequence IS NULL AND last_heartbeat_lease IS NULL)
        OR (winner_cluster IS NOT NULL AND btrim(winner_cluster) <> ''
            AND winner_pod_uid IS NOT NULL AND btrim(winner_pod_uid) <> '' AND claim_uuid IS NOT NULL
            AND lease_until IS NOT NULL AND last_heartbeat_sequence IS NOT NULL AND last_heartbeat_lease IS NOT NULL
            AND lease_until = last_heartbeat_lease AND lease_until <= max_deadline)),
    CONSTRAINT ck_ai_runtime_attempt_claim_state CHECK (
        (state = 'LAUNCHING' AND claim_uuid IS NULL AND failure_reason IS NULL)
        OR (state = 'CLAIMED' AND claim_uuid IS NOT NULL AND failure_reason IS NULL)
        OR (state = 'FENCED' AND failure_reason IS NOT NULL))
);

CREATE UNIQUE INDEX uq_ai_runtime_live_attempt ON ai_runtime_attempt (run_uuid)
    WHERE state IN ('LAUNCHING', 'CLAIMED');

ALTER TABLE ai_runtime_run
    ADD CONSTRAINT fk_ai_runtime_current_attempt FOREIGN KEY (uuid, current_attempt_uuid)
        REFERENCES ai_runtime_attempt (run_uuid, uuid) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ai_runtime_launch
(
    attempt_uuid         UUID         NOT NULL PRIMARY KEY REFERENCES ai_runtime_attempt (uuid),
    cluster              VARCHAR(128) NOT NULL CHECK (btrim(cluster) <> ''),
    namespace_name       VARCHAR(63)  NOT NULL CHECK (btrim(namespace_name) <> ''),
    namespace_uid        VARCHAR(128) NOT NULL CHECK (btrim(namespace_uid) <> ''),
    service_account_name VARCHAR(253) NOT NULL CHECK (btrim(service_account_name) <> ''),
    service_account_uid  VARCHAR(128) NOT NULL CHECK (btrim(service_account_uid) <> ''),
    job_name             VARCHAR(63)  NOT NULL CHECK (job_name = 'ilm-ai-' || replace(attempt_uuid::text, '-', '')),
    template_digest      VARCHAR(71)  NOT NULL CHECK (template_digest ~ '^sha256:[0-9a-f]{64}$'),
    runtime_class        VARCHAR(253) NOT NULL CHECK (btrim(runtime_class) <> ''),
    job_uid              VARCHAR(128) CHECK (btrim(job_uid) <> ''),
    observation_sequence BIGINT       NOT NULL CHECK (observation_sequence >= 0),
    cleanup_state        VARCHAR(16)  NOT NULL CHECK (cleanup_state IN ('NONE', 'DUE', 'DONE')),
    created_at           TIMESTAMPTZ  NOT NULL,
    updated_at           TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uq_ai_runtime_launch_name UNIQUE (cluster, namespace_uid, job_name),
    CONSTRAINT uq_ai_runtime_launch_cluster UNIQUE (attempt_uuid, cluster)
);

CREATE TABLE ai_runtime_workload
(
    cluster                 VARCHAR(128) NOT NULL CHECK (btrim(cluster) <> ''),
    pod_uid                 VARCHAR(128) NOT NULL CHECK (btrim(pod_uid) <> ''),
    attempt_uuid            UUID         NOT NULL,
    pod_name                VARCHAR(253) NOT NULL CHECK (btrim(pod_name) <> ''),
    job_uid                 VARCHAR(128) NOT NULL CHECK (btrim(job_uid) <> ''),
    state                   VARCHAR(16)  NOT NULL CHECK (state IN ('ELIGIBLE', 'REGISTERED', 'CLOSED')),
    observation_sequence    BIGINT       NOT NULL CHECK (observation_sequence > 0),
    observation_valid_until TIMESTAMPTZ  NOT NULL,
    first_pending_at        TIMESTAMPTZ,
    pending_deadline        TIMESTAMPTZ,
    pending_returns         INTEGER      NOT NULL DEFAULT 0 CHECK (pending_returns BETWEEN 0 AND 11),
    bootstrap_consumed_at   TIMESTAMPTZ,
    created_at              TIMESTAMPTZ  NOT NULL,
    updated_at              TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (cluster, pod_uid),
    CONSTRAINT uq_ai_runtime_workload_attempt UNIQUE (attempt_uuid, cluster, pod_uid),
    CONSTRAINT fk_ai_runtime_workload_launch FOREIGN KEY (attempt_uuid, cluster)
        REFERENCES ai_runtime_launch (attempt_uuid, cluster),
    CONSTRAINT ck_ai_runtime_pending CHECK (
        (pending_returns = 0 AND first_pending_at IS NULL AND pending_deadline IS NULL)
        OR (pending_returns > 0 AND first_pending_at IS NOT NULL AND pending_deadline IS NOT NULL
            AND first_pending_at <= pending_deadline))
);

ALTER TABLE ai_runtime_attempt
    ADD CONSTRAINT fk_ai_runtime_winner FOREIGN KEY (uuid, winner_cluster, winner_pod_uid)
        REFERENCES ai_runtime_workload (attempt_uuid, cluster, pod_uid) DEFERRABLE INITIALLY DEFERRED;

-- Runtime control
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

-- Model dispatch
-- Local persisted facts and conservative allowance only; no permission/native identity/send grant.
CREATE TABLE ai_model_connection (
    uuid UUID PRIMARY KEY,
    model_identifier VARCHAR(255) NOT NULL CHECK (length(btrim(model_identifier)) > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    destination_revision BIGINT NOT NULL CHECK (destination_revision > 0),
    authentication_revision BIGINT NOT NULL CHECK (authentication_revision > 0),
    approved_revision BIGINT,
    approved_destination_revision BIGINT,
    approved_authentication_revision BIGINT,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    origin VARCHAR(2048) NOT NULL CHECK (
        origin ~ '^https://([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?/?$'
        AND COALESCE(substring(origin FROM ':([0-9]{1,5})/?$')::INTEGER BETWEEN 1 AND 65535, TRUE)),
    credential_reference VARCHAR(64) NOT NULL CHECK (credential_reference ~ '^[a-z][a-z0-9-]{0,63}$'),
    CHECK ((approved_revision IS NULL AND approved_destination_revision IS NULL AND approved_authentication_revision IS NULL)
        OR (approved_revision IS NOT NULL AND approved_destination_revision IS NOT NULL
            AND approved_authentication_revision IS NOT NULL
            AND approved_revision > 0 AND approved_revision <= revision
            AND approved_destination_revision > 0 AND approved_destination_revision <= destination_revision
            AND approved_authentication_revision > 0 AND approved_authentication_revision <= authentication_revision))
);

CREATE TABLE ai_model_run_budget (
    run_uuid UUID PRIMARY KEY REFERENCES ai_runtime_run(uuid),
    connection_uuid UUID NOT NULL REFERENCES ai_model_connection(uuid),
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision > 0),
    destination_revision BIGINT NOT NULL CHECK (destination_revision > 0),
    authentication_revision BIGINT NOT NULL CHECK (authentication_revision > 0),
    max_calls BIGINT NOT NULL CHECK (max_calls > 0),
    max_tokens BIGINT NOT NULL CHECK (max_tokens > 0),
    reserved_calls BIGINT NOT NULL DEFAULT 0 CHECK (reserved_calls >= 0),
    reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    CHECK (reserved_calls <= max_calls AND reserved_tokens <= max_tokens)
);

CREATE TABLE ai_model_run_intent (
    uuid UUID PRIMARY KEY,
    request_key UUID NOT NULL,
    run_uuid UUID NOT NULL REFERENCES ai_runtime_run(uuid),
    attempt_uuid UUID NOT NULL REFERENCES ai_runtime_attempt(uuid),
    actor_uuid UUID NOT NULL,
    claim_uuid UUID NOT NULL,
    cluster VARCHAR(253) NOT NULL,
    pod_uid VARCHAR(253) NOT NULL,
    fence BIGINT NOT NULL CHECK (fence > 0),
    connection_uuid UUID NOT NULL REFERENCES ai_model_connection(uuid),
    model_identifier VARCHAR(255) NOT NULL CHECK (length(btrim(model_identifier)) > 0),
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision > 0),
    destination_revision BIGINT NOT NULL CHECK (destination_revision > 0),
    authentication_revision BIGINT NOT NULL CHECK (authentication_revision > 0),
    payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    output_tokens INTEGER NOT NULL CHECK (output_tokens > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'PREPARED' CHECK (state IN ('PREPARED', 'CONSUMED')),
    consumed_at TIMESTAMPTZ,
    gateway_correlation UUID,
    UNIQUE (run_uuid, request_key),
    CHECK ((state = 'PREPARED' AND consumed_at IS NULL AND gateway_correlation IS NULL)
        OR (state = 'CONSUMED' AND consumed_at IS NOT NULL AND gateway_correlation IS NOT NULL))
);

CREATE TABLE ai_model_management_session (
    session_uuid UUID PRIMARY KEY,
    actor_uuid UUID NOT NULL,
    connection_uuid UUID NOT NULL REFERENCES ai_model_connection(uuid),
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision > 0),
    destination_revision BIGINT NOT NULL CHECK (destination_revision > 0),
    authentication_revision BIGINT NOT NULL CHECK (authentication_revision > 0),
    action VARCHAR(32) NOT NULL CHECK (action IN ('CONNECTION_CHECK', 'CAPABILITY_CHECK')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    max_calls BIGINT NOT NULL CHECK (max_calls > 0),
    max_tokens BIGINT NOT NULL CHECK (max_tokens > 0),
    reserved_calls BIGINT NOT NULL DEFAULT 0 CHECK (reserved_calls >= 0),
    reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    CHECK (reserved_calls <= max_calls AND reserved_tokens <= max_tokens)
);

-- Management intentionally has no run/attempt/Pod/claim/image fields or foreign keys.
CREATE TABLE ai_model_management_intent (
    uuid UUID PRIMARY KEY,
    request_key UUID NOT NULL,
    actor_uuid UUID NOT NULL,
    session_uuid UUID NOT NULL REFERENCES ai_model_management_session(session_uuid),
    action VARCHAR(32) NOT NULL CHECK (action IN ('CONNECTION_CHECK', 'CAPABILITY_CHECK')),
    connection_uuid UUID NOT NULL REFERENCES ai_model_connection(uuid),
    model_identifier VARCHAR(255) NOT NULL CHECK (length(btrim(model_identifier)) > 0),
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision > 0),
    destination_revision BIGINT NOT NULL CHECK (destination_revision > 0),
    authentication_revision BIGINT NOT NULL CHECK (authentication_revision > 0),
    payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_sha256 CHAR(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    output_tokens INTEGER NOT NULL CHECK (output_tokens > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'PREPARED' CHECK (state IN ('PREPARED', 'CONSUMED')),
    consumed_at TIMESTAMPTZ,
    gateway_correlation UUID,
    UNIQUE (session_uuid, request_key),
    CHECK ((state = 'PREPARED' AND consumed_at IS NULL AND gateway_correlation IS NULL)
        OR (state = 'CONSUMED' AND consumed_at IS NOT NULL AND gateway_correlation IS NOT NULL))
);

-- No configuration writer can silently reuse or roll back approved destination/authentication revisions.
CREATE FUNCTION ai_model_connection_revision_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revision < OLD.revision OR NEW.destination_revision < OLD.destination_revision
            OR NEW.authentication_revision < OLD.authentication_revision
            OR (NEW.model_identifier IS DISTINCT FROM OLD.model_identifier AND NEW.revision <= OLD.revision)
            OR (NEW.origin IS DISTINCT FROM OLD.origin
                AND (NEW.revision <= OLD.revision OR NEW.destination_revision <= OLD.destination_revision))
            OR (NEW.credential_reference IS DISTINCT FROM OLD.credential_reference
                AND (NEW.revision <= OLD.revision OR NEW.authentication_revision <= OLD.authentication_revision))
            OR ((NEW.destination_revision > OLD.destination_revision
                    OR NEW.authentication_revision > OLD.authentication_revision
                    OR NEW.enabled IS DISTINCT FROM OLD.enabled) AND NEW.revision <= OLD.revision) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', CONSTRAINT = 'ai_model_connection_revision_guard',
            MESSAGE = 'Model revision transition rejected';
    END IF;
    IF NEW.revision > OLD.revision OR NEW.destination_revision > OLD.destination_revision
            OR NEW.authentication_revision > OLD.authentication_revision OR NEW.enabled IS DISTINCT FROM OLD.enabled THEN
        NEW.approved_revision := NULL;
        NEW.approved_destination_revision := NULL;
        NEW.approved_authentication_revision := NULL;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER ai_model_connection_revision_guard BEFORE UPDATE ON ai_model_connection
    FOR EACH ROW EXECUTE FUNCTION ai_model_connection_revision_guard();

-- Model run input
-- Core-authored immutable execution input. Actor and model/version remain in their existing run/budget tables.
CREATE TABLE ai_model_run_input (
    run_uuid UUID PRIMARY KEY REFERENCES ai_runtime_run(uuid) ON DELETE CASCADE,
    actor_uuid UUID NOT NULL,
    ra_profile_uuid UUID NOT NULL,
    certificate_uuids UUID[] NOT NULL CHECK (COALESCE(array_ndims(certificate_uuids), 1) = 1
        AND cardinality(certificate_uuids) <= 100 AND array_position(certificate_uuids, NULL) IS NULL),
    instructions TEXT NOT NULL CHECK (length(instructions) BETWEEN 1 AND 65536),
    prompt TEXT NOT NULL CHECK (length(prompt) BETWEEN 1 AND 65536),
    output_tokens INTEGER NOT NULL CHECK (output_tokens > 0)
);

CREATE FUNCTION ai_model_run_input_immutable_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    parent_exists BOOLEAN;
BEGIN
    IF TG_OP IN ('UPDATE', 'TRUNCATE') THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Stored model run input is immutable';
    END IF;
    -- Use this table's schema even if a caller changes search_path or creates a temporary shadow table.
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.ai_runtime_run WHERE uuid = $1)', TG_TABLE_SCHEMA)
        INTO parent_exists USING OLD.run_uuid;
    IF parent_exists THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Stored model run input is retained';
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER ai_model_run_input_immutable_guard BEFORE UPDATE OR DELETE ON ai_model_run_input
    FOR EACH ROW EXECUTE FUNCTION ai_model_run_input_immutable_guard();
CREATE TRIGGER ai_model_run_input_truncate_guard BEFORE TRUNCATE ON ai_model_run_input
    FOR EACH STATEMENT EXECUTE FUNCTION ai_model_run_input_immutable_guard();

-- Runtime gateway registration
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

-- Model run outcome
-- Immutable Core-selected delegation and protected evidence. Neither row authorizes a read or work revival.
CREATE TABLE ai_model_run_gateway_assignment (
    intent_uuid UUID PRIMARY KEY REFERENCES ai_model_run_intent(uuid) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL CHECK (role = 'GATEWAY_RUN'),
    cluster VARCHAR(253) NOT NULL,
    namespace_name VARCHAR(253) NOT NULL,
    service_account_name VARCHAR(253) NOT NULL,
    pod_name VARCHAR(253) NOT NULL,
    pod_uid UUID NOT NULL,
    control_generation BIGINT NOT NULL CHECK (control_generation > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ai_model_run_outcome (
    intent_uuid UUID PRIMARY KEY REFERENCES ai_model_run_gateway_assignment(intent_uuid) ON DELETE CASCADE,
    result_version BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE CHECK (result_version > 0),
    gateway_correlation UUID NOT NULL,
    outcome_sha256 CHAR(64) NOT NULL CHECK (outcome_sha256 ~ '^[0-9a-f]{64}$'),
    request_bytes BYTEA NOT NULL CHECK (octet_length(request_bytes) BETWEEN 1 AND 1500000),
    transport_code VARCHAR(16) NOT NULL CHECK (transport_code IN ('HTTP_200', 'UNKNOWN')),
    response_bytes BYTEA,
    response_sha256 CHAR(64),
    response_byte_count INTEGER NOT NULL CHECK (response_byte_count BETWEEN 0 AND 1048576),
    result_code VARCHAR(16) NOT NULL CHECK (result_code IN ('TEXT', 'INVALID')),
    result_text TEXT,
    finish VARCHAR(16),
    prompt_tokens BIGINT,
    completion_tokens BIGINT,
    total_tokens BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (outcome_sha256 = encode(sha256(request_bytes), 'hex')),
    CHECK ((transport_code = 'UNKNOWN' AND response_bytes IS NULL AND response_sha256 IS NULL AND response_byte_count = 0)
        OR (transport_code = 'HTTP_200' AND response_bytes IS NOT NULL
            AND octet_length(response_bytes) BETWEEN 1 AND 1048576
            AND response_byte_count = octet_length(response_bytes) AND response_sha256 IS NOT NULL
            AND response_sha256 ~ '^[0-9a-f]{64}$' AND response_sha256 = encode(sha256(response_bytes), 'hex'))),
    CHECK ((result_code = 'INVALID' AND result_text IS NULL AND finish IS NULL
            AND prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL)
        OR (result_code = 'TEXT' AND result_text IS NOT NULL AND finish IS NOT NULL AND finish IN ('STOP', 'LENGTH'))),
    CHECK ((prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL)
        OR (prompt_tokens IS NOT NULL AND completion_tokens IS NOT NULL AND total_tokens IS NOT NULL
            AND prompt_tokens >= 0 AND completion_tokens >= 0 AND total_tokens >= 0
            AND total_tokens::NUMERIC = prompt_tokens::NUMERIC + completion_tokens::NUMERIC))
);

CREATE FUNCTION ai_model_run_gateway_immutable_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    parent_present BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.ai_model_run_intent WHERE uuid = $1)', TG_TABLE_SCHEMA)
            INTO parent_present USING OLD.intent_uuid;
        IF NOT parent_present THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Model gateway evidence is immutable';
END;
$$;
CREATE TRIGGER ai_model_run_gateway_assignment_immutable BEFORE UPDATE OR DELETE ON ai_model_run_gateway_assignment
    FOR EACH ROW EXECUTE FUNCTION ai_model_run_gateway_immutable_guard();
CREATE TRIGGER ai_model_run_gateway_assignment_truncate BEFORE TRUNCATE ON ai_model_run_gateway_assignment
    FOR EACH STATEMENT EXECUTE FUNCTION ai_model_run_gateway_immutable_guard();
CREATE TRIGGER ai_model_run_outcome_immutable BEFORE UPDATE OR DELETE ON ai_model_run_outcome
    FOR EACH ROW EXECUTE FUNCTION ai_model_run_gateway_immutable_guard();
CREATE TRIGGER ai_model_run_outcome_truncate BEFORE TRUNCATE ON ai_model_run_outcome
    FOR EACH STATEMENT EXECUTE FUNCTION ai_model_run_gateway_immutable_guard();

-- Model management session
-- Add guards to the existing finite management-session table; no run activation or readiness is created.
CREATE OR REPLACE FUNCTION ai_model_management_session_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'Immutable management session' USING ERRCODE = '55000';
    END IF;
    IF ROW(NEW.session_uuid, NEW.actor_uuid, NEW.connection_uuid, NEW.configuration_revision,
            NEW.destination_revision, NEW.authentication_revision, NEW.action, NEW.expires_at,
            NEW.max_calls, NEW.max_tokens)
        IS DISTINCT FROM ROW(OLD.session_uuid, OLD.actor_uuid, OLD.connection_uuid, OLD.configuration_revision,
            OLD.destination_revision, OLD.authentication_revision, OLD.action, OLD.expires_at,
            OLD.max_calls, OLD.max_tokens)
        OR (NOT OLD.enabled AND NEW.enabled)
        OR NEW.reserved_calls < OLD.reserved_calls OR NEW.reserved_tokens < OLD.reserved_tokens THEN
        RAISE EXCEPTION 'Immutable management session' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER ai_model_management_session_immutable
    BEFORE UPDATE OR DELETE ON ai_model_management_session
    FOR EACH ROW EXECUTE FUNCTION ai_model_management_session_immutable_guard();
CREATE TRIGGER ai_model_management_session_no_truncate
    BEFORE TRUNCATE ON ai_model_management_session
    FOR EACH STATEMENT EXECUTE FUNCTION ai_model_management_session_immutable_guard();

-- Management gateway
-- Independent management transport membership; no run or global activation authority.
CREATE TABLE ai_management_gateway_deployment (
 id integer PRIMARY KEY CHECK (id=1), revision bigint NOT NULL CHECK(revision>=0), configured boolean NOT NULL,
 image_digest text, cluster text, namespace_name text, namespace_uid text,
 service_account_name text, service_account_uid text, template_digest text, runtime_class text,
 CHECK (NOT configured OR (revision>0 AND image_digest IS NOT NULL AND template_digest IS NOT NULL AND image_digest ~ '^sha256:[0-9a-f]{64}$' AND cluster IS NOT NULL
 AND namespace_name IS NOT NULL AND namespace_uid IS NOT NULL AND service_account_name IS NOT NULL
 AND service_account_uid IS NOT NULL AND template_digest ~ '^sha256:[0-9a-f]{64}$' AND runtime_class IS NOT NULL))
);
INSERT INTO ai_management_gateway_deployment(id,revision,configured) VALUES(1,0,false);
CREATE TABLE ai_management_gateway_registration (
 pod_uid uuid PRIMARY KEY, deployment_revision bigint NOT NULL CHECK(deployment_revision>0),
 pod_name text NOT NULL, observation_sequence bigint NOT NULL CHECK(observation_sequence>0),
 evidence_id uuid NOT NULL, observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 CHECK(observed_at<valid_until AND valid_until<=observed_at+interval '30 seconds')
);

-- Model management outcome
-- Core-only immutable delegation. It grants neither CONNECT nor automatic approval.
CREATE TABLE ai_model_management_gateway_assignment (
 intent_uuid UUID PRIMARY KEY REFERENCES ai_model_management_intent(uuid) ON DELETE CASCADE,
 deployment_revision BIGINT NOT NULL CHECK(deployment_revision>0),
 cluster TEXT NOT NULL,namespace_name TEXT NOT NULL,service_account_name TEXT NOT NULL,
 pod_name TEXT NOT NULL,pod_uid UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION ai_model_management_gateway_immutable_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE parent_present BOOLEAN;
BEGIN
 IF TG_OP='DELETE' THEN
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.ai_model_management_intent WHERE uuid=$1)',TG_TABLE_SCHEMA)
   INTO parent_present USING OLD.intent_uuid;
  IF NOT parent_present THEN RETURN OLD; END IF;
 END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Management gateway evidence is immutable';
END;
$$;
CREATE TRIGGER ai_model_management_assignment_immutable BEFORE UPDATE OR DELETE ON ai_model_management_gateway_assignment
 FOR EACH ROW EXECUTE FUNCTION ai_model_management_gateway_immutable_guard();
CREATE TRIGGER ai_model_management_assignment_truncate BEFORE TRUNCATE ON ai_model_management_gateway_assignment
 FOR EACH STATEMENT EXECUTE FUNCTION ai_model_management_gateway_immutable_guard();

CREATE TABLE ai_model_management_outcome (
    intent_uuid UUID PRIMARY KEY REFERENCES ai_model_management_gateway_assignment(intent_uuid) ON DELETE CASCADE,
    result_version BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE CHECK (result_version > 0),
    gateway_correlation UUID NOT NULL,
    outcome_sha256 CHAR(64) NOT NULL CHECK (outcome_sha256 ~ '^[0-9a-f]{64}$'),
    request_bytes BYTEA NOT NULL CHECK (octet_length(request_bytes) BETWEEN 1 AND 1500000),
    transport_code VARCHAR(16) NOT NULL CHECK (transport_code IN ('HTTP_200', 'UNKNOWN')),
    response_bytes BYTEA,
    response_sha256 CHAR(64),
    response_byte_count INTEGER NOT NULL CHECK (response_byte_count BETWEEN 0 AND 1048576),
    result_code VARCHAR(16) NOT NULL CHECK (result_code IN ('TEXT', 'INVALID')),
    result_text TEXT,
    finish VARCHAR(16),
    prompt_tokens BIGINT,
    completion_tokens BIGINT,
    total_tokens BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (outcome_sha256 = encode(sha256(request_bytes), 'hex')),
    CHECK ((transport_code = 'UNKNOWN' AND response_bytes IS NULL AND response_sha256 IS NULL AND response_byte_count = 0)
        OR (transport_code = 'HTTP_200' AND response_bytes IS NOT NULL
            AND octet_length(response_bytes) BETWEEN 1 AND 1048576
            AND response_byte_count = octet_length(response_bytes) AND response_sha256 IS NOT NULL
            AND response_sha256 ~ '^[0-9a-f]{64}$' AND response_sha256 = encode(sha256(response_bytes), 'hex'))),
    CHECK ((result_code = 'INVALID' AND result_text IS NULL AND finish IS NULL
            AND prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL)
        OR (result_code = 'TEXT' AND result_text IS NOT NULL AND finish IS NOT NULL AND finish IN ('STOP', 'LENGTH'))),
    CHECK ((prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL)
        OR (prompt_tokens IS NOT NULL AND completion_tokens IS NOT NULL AND total_tokens IS NOT NULL
            AND prompt_tokens >= 0 AND completion_tokens >= 0 AND total_tokens >= 0
            AND total_tokens::NUMERIC = prompt_tokens::NUMERIC + completion_tokens::NUMERIC))
);


CREATE TRIGGER ai_model_management_outcome_immutable BEFORE UPDATE OR DELETE ON ai_model_management_outcome
 FOR EACH ROW EXECUTE FUNCTION ai_model_management_gateway_immutable_guard();
CREATE TRIGGER ai_model_management_outcome_truncate BEFORE TRUNCATE ON ai_model_management_outcome
 FOR EACH STATEMENT EXECUTE FUNCTION ai_model_management_gateway_immutable_guard();
