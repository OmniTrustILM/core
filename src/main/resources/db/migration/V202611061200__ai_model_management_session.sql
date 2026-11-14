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
