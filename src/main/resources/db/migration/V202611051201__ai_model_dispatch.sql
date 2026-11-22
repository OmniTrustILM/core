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
