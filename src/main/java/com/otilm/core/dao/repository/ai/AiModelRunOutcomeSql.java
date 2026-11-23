package com.otilm.core.dao.repository.ai;

/** Current native registration is inherited from its single registry predicate; no independent allow policy. */
final class AiModelRunOutcomeSql {
    private static final String ASSIGNMENT_JOIN = " JOIN {h-schema}ai_model_run_gateway_assignment a ON a.intent_uuid = i.uuid ";
    private static final String REGISTERED = " CROSS JOIN (" + AiRuntimeGatewaySql.CURRENT + ") g ";
    private static final String INTENT_RUN = " FROM {h-schema}ai_model_run_intent i JOIN {h-schema}ai_runtime_run r ON r.uuid = i.run_uuid ";
    private static final String CURRENT_GENERATION = " r.control_generation = g.\"controlGeneration\" AND :role = 'GATEWAY_RUN' AND clock_timestamp() < :operationDeadline ";
    private static final String EXACT_GATEWAY = """
            a.role = :role AND a.cluster = :#{#peer.cluster()} AND a.namespace_name = :#{#peer.namespace()}
            AND a.service_account_name = :#{#peer.serviceAccount()} AND a.pod_name = :#{#peer.podName()}
            AND a.pod_uid = :#{#peer.podUid()} AND a.control_generation = g."controlGeneration"
            """;
    static final String ASSIGN = """
            INSERT INTO {h-schema}ai_model_run_gateway_assignment
                (intent_uuid, role, cluster, namespace_name, service_account_name, pod_name, pod_uid, control_generation)
            SELECT i.uuid, :role, :#{#peer.cluster()}, :#{#peer.namespace()}, :#{#peer.serviceAccount()},
                :#{#peer.podName()}, :#{#peer.podUid()}, g."controlGeneration"
            """
            + INTENT_RUN + REGISTERED + " WHERE i.uuid = :intentId AND i.state = 'PREPARED' AND " + CURRENT_GENERATION
            + " ON CONFLICT (intent_uuid) DO NOTHING";
    static final String ASSIGNMENT_REPLAY = "SELECT (" + EXACT_GATEWAY + ") AS exact " + INTENT_RUN + ASSIGNMENT_JOIN
            + REGISTERED + " WHERE i.uuid = :intentId AND " + CURRENT_GENERATION;
    static final String ASSIGNED = "SELECT EXISTS (SELECT 1 " + INTENT_RUN + ASSIGNMENT_JOIN + REGISTERED
            + " WHERE i.uuid = :intentId AND " + CURRENT_GENERATION + " AND " + EXACT_GATEWAY + ")";
    private static final String OUTCOME_FROM = INTENT_RUN + ASSIGNMENT_JOIN + REGISTERED;
    private static final String OUTCOME_CURRENT = """
            i.uuid = :#{#q.intentId()} AND i.state = 'CONSUMED' AND i.gateway_correlation = :#{#q.gatewayCorrelation()}
            AND i.run_uuid = :#{#q.binding().runId()} AND i.attempt_uuid = :#{#q.binding().attemptId()}
            AND i.pod_uid = CAST(:#{#q.binding().podUid()} AS text) AND i.claim_uuid = :#{#q.binding().claimId()}
            AND i.fence = :#{#q.binding().fence()} AND i.expires_at = :#{#q.binding().expiresAt()}
            AND i.payload_sha256 = :#{#q.payloadSha256()} AND i.payload_sha256 = encode(sha256(i.payload), 'hex')
            AND
            """ + CURRENT_GENERATION + " AND " + EXACT_GATEWAY;
    static final String METADATA = """
            SELECT i.model_identifier AS "modelIdentifier", i.output_tokens AS "outputTokens", i.expires_at AS "expiresAt"
            """
            + OUTCOME_FROM + " WHERE " + OUTCOME_CURRENT;
    static final String APPEND = """
            INSERT INTO {h-schema}ai_model_run_outcome
                (intent_uuid, gateway_correlation, outcome_sha256, request_bytes, transport_code,
                    response_bytes, response_sha256, response_byte_count, result_code, result_text, finish,
                    prompt_tokens, completion_tokens, total_tokens)
            SELECT i.uuid, :#{#q.gatewayCorrelation()}, :#{#q.outcomeSha256()}, :#{#q.requestBytes()},
                :#{#q.transportCode().name()}, CAST(:#{#q.responseBytes()} AS bytea),
                CAST(:#{#q.responseSha256()} AS varchar), :#{#q.responseByteCount()}, :#{#v.code()},
                CAST(:#{#v.text()} AS text), CAST(:#{#v.finish()} AS varchar),
                CAST(:#{#v.promptTokens()} AS bigint), CAST(:#{#v.completionTokens()} AS bigint), CAST(:#{#v.totalTokens()} AS bigint)
            """
            + OUTCOME_FROM + " WHERE " + OUTCOME_CURRENT + " ON CONFLICT (intent_uuid) DO NOTHING";
    static final String RECEIPT = """
            SELECT o.intent_uuid AS "intentId", o.gateway_correlation AS "gatewayCorrelation",
                o.outcome_sha256 AS "outcomeSha256", o.result_version AS "resultVersion",
                (o.request_bytes = :#{#q.requestBytes()} AND o.outcome_sha256 = :#{#q.outcomeSha256()}
                    AND o.gateway_correlation = :#{#q.gatewayCorrelation()}) AS exact
            """ + OUTCOME_FROM + " JOIN {h-schema}ai_model_run_outcome o ON o.intent_uuid = i.uuid WHERE "
            + OUTCOME_CURRENT;

    private AiModelRunOutcomeSql() {
    }
}
