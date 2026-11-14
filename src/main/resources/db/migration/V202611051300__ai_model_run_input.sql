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
