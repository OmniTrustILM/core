package com.otilm.core.dao.repository.ai;

/** Late consumed evidence needs current assigned native membership, never renewed session/work authority. */
final class AiModelManagementOutcomeSql {
    private static final String FROM = """
            FROM {h-schema}ai_model_management_intent i
            JOIN {h-schema}ai_model_management_gateway_assignment a ON a.intent_uuid=i.uuid
            CROSS JOIN (
            """ + AiRuntimeManagementGatewaySql.CURRENT + ") g ";
    private static final String CURRENT = """
            :role='GATEWAY_MANAGEMENT' AND clock_timestamp()<:operationDeadline
            AND a.deployment_revision=g."deploymentRevision" AND a.cluster=:#{#peer.cluster()}
            AND a.namespace_name=:#{#peer.namespace()} AND a.service_account_name=:#{#peer.serviceAccount()}
            AND a.pod_name=:#{#peer.podName()} AND a.pod_uid=:#{#peer.podUid()}
            AND i.uuid=:#{#q.intentId()} AND i.state='CONSUMED' AND i.gateway_correlation=:#{#q.gatewayCorrelation()}
            AND i.actor_uuid=:#{#q.binding().actorId()} AND i.session_uuid=:#{#q.binding().sessionId()}
            AND i.connection_uuid=:#{#q.binding().configurationId()} AND i.configuration_revision=:#{#q.binding().configurationRevision()}
            AND i.action=:#{#q.binding().action().name()} AND i.expires_at=:#{#q.binding().expiresAt()}
            AND i.payload_sha256=:#{#q.payloadSha256()} AND i.payload_sha256=encode(sha256(i.payload),'hex')
            """;
    static final String METADATA = "SELECT i.model_identifier AS \"modelIdentifier\",i.output_tokens AS \"outputTokens\",i.expires_at AS \"expiresAt\" "
            + FROM + " WHERE " + CURRENT;
    static final String APPEND = """
            INSERT INTO {h-schema}ai_model_management_outcome
                (intent_uuid,gateway_correlation,outcome_sha256,request_bytes,transport_code,response_bytes,response_sha256,
                response_byte_count,result_code,result_text,finish,prompt_tokens,completion_tokens,total_tokens)
            SELECT i.uuid,:#{#q.gatewayCorrelation()},:#{#q.outcomeSha256()},:#{#q.requestBytes()},:#{#q.transportCode().name()},
                CAST(:#{#q.responseBytes()} AS bytea),CAST(:#{#q.responseSha256()} AS varchar),:#{#q.responseByteCount()},
                :#{#v.code()},CAST(:#{#v.text()} AS text),CAST(:#{#v.finish()} AS varchar),CAST(:#{#v.promptTokens()} AS bigint),
                CAST(:#{#v.completionTokens()} AS bigint),CAST(:#{#v.totalTokens()} AS bigint)
            """
            + FROM + " WHERE " + CURRENT + " ON CONFLICT(intent_uuid) DO NOTHING";
    static final String RECEIPT = """
            SELECT o.intent_uuid AS "intentId",o.gateway_correlation AS "gatewayCorrelation",o.outcome_sha256 AS "outcomeSha256",
                o.result_version AS "resultVersion",(o.request_bytes=:#{#q.requestBytes()} AND o.outcome_sha256=:#{#q.outcomeSha256()}
                AND o.gateway_correlation=:#{#q.gatewayCorrelation()}) AS exact
            """
            + FROM + " JOIN {h-schema}ai_model_management_outcome o ON o.intent_uuid=i.uuid WHERE " + CURRENT;
    static final String READ = """
            SELECT o.intent_uuid AS "intentId",o.gateway_correlation AS "gatewayCorrelation",o.outcome_sha256 AS "outcomeSha256",
                o.result_version AS "resultVersion",o.result_code AS code,o.result_text AS text,o.finish AS finish,
                o.prompt_tokens AS "promptTokens",o.completion_tokens AS "completionTokens",o.total_tokens AS "totalTokens"
            FROM {h-schema}ai_model_management_outcome o
            JOIN {h-schema}ai_model_management_intent i ON i.uuid=o.intent_uuid
            JOIN {h-schema}ai_model_management_session s ON s.session_uuid=i.session_uuid
            JOIN {h-schema}ai_model_connection m ON m.uuid=s.connection_uuid
            WHERE i.uuid=:intentId AND i.session_uuid=:sessionId AND s.actor_uuid=:authorizedActor AND i.actor_uuid=s.actor_uuid
                AND i.action=s.action AND i.connection_uuid=s.connection_uuid AND i.configuration_revision=s.configuration_revision
                AND i.destination_revision=s.destination_revision AND i.authentication_revision=s.authentication_revision
                AND s.enabled AND clock_timestamp()<s.expires_at AND clock_timestamp()<:operationDeadline
                AND s.configuration_revision=m.revision AND s.destination_revision=m.destination_revision
                AND s.authentication_revision=m.authentication_revision AND
            """
            + AiModelManagementSessionSql.APPROVED;

    private AiModelManagementOutcomeSql() {
    }
}
