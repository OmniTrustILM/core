package com.otilm.core.dao.repository.ai;

/** Current finite session metadata and final local writes only; no run activation or remote permission grant. */
final class AiModelManagementSessionSql {
    static final String APPROVED = """
            m.enabled AND m.approved_revision = m.revision
            AND m.approved_destination_revision = m.destination_revision
            AND m.approved_authentication_revision = m.authentication_revision
            """;
    static final String COLUMNS = """
            SELECT s.session_uuid AS "sessionId", s.actor_uuid AS "actorId", s.connection_uuid AS "connectionId",
                m.model_identifier AS "modelIdentifier", s.configuration_revision AS configuration,
                s.destination_revision AS destination, s.authentication_revision AS authentication,
                s.action AS action, s.enabled AS enabled, s.expires_at AS "expiresAt", s.max_calls AS "maxCalls",
                s.max_tokens AS "maxTokens", s.reserved_calls AS "reservedCalls", s.reserved_tokens AS "reservedTokens"
            FROM {h-schema}ai_model_management_session s JOIN {h-schema}ai_model_connection m ON m.uuid = s.connection_uuid
            WHERE s.session_uuid = :id
            """;
    static final String METADATA = COLUMNS + """
            AND s.enabled AND s.configuration_revision = m.revision AND s.destination_revision = m.destination_revision
                AND s.authentication_revision = m.authentication_revision AND clock_timestamp() < s.expires_at
                AND clock_timestamp() < :operationDeadline AND
            """ + APPROVED;
    static final String MODEL_CURRENT = "SELECT EXISTS(SELECT 1 FROM {h-schema}ai_model_connection m WHERE "
            + AiModelDispatchSql.MODEL_CURRENT
            + " AND clock_timestamp() < :#{#q.expiresAt()} AND clock_timestamp() < :operationDeadline)";
    static final String INSERT = """
            INSERT INTO {h-schema}ai_model_management_session (session_uuid,actor_uuid,connection_uuid,
                configuration_revision,destination_revision,authentication_revision,action,enabled,expires_at,
                max_calls,max_tokens,reserved_calls,reserved_tokens)
            SELECT :#{#q.sessionId()},:#{#q.actorId()},m.uuid,m.revision,m.destination_revision,m.authentication_revision,
                :#{#q.action().name()},TRUE,:#{#q.expiresAt()},:#{#q.maxCalls()},:#{#q.maxTokens()},0,0
            FROM {h-schema}ai_model_connection m WHERE
            """
            + AiModelDispatchSql.MODEL_CURRENT + """
                     AND clock_timestamp() < :#{#q.expiresAt()} AND clock_timestamp() < :operationDeadline
                    ON CONFLICT (session_uuid) DO NOTHING
                    """;
    static final String CLOSE = """
            UPDATE {h-schema}ai_model_management_session SET enabled=FALSE
            WHERE session_uuid=:id AND enabled AND clock_timestamp() < :operationDeadline
            """;

    private AiModelManagementSessionSql() {
    }
}
