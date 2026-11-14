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
