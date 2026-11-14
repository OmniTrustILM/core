package com.otilm.core.dao.repository.ai;

/** Final database admission predicates; all values are trusted internal component arguments, never wire grants. */
final class AiModelDispatchSql {
    private static final String AND = " AND ";
    static final String MODEL_CURRENT = """
            m.uuid = :#{#q.connection().id()} AND m.model_identifier = :#{#q.connection().modelIdentifier()} AND m.revision = :#{#q.connection().configuration()}
            AND m.destination_revision = :#{#q.connection().destination()}
            AND m.authentication_revision = :#{#q.connection().authentication()} AND m.enabled
            AND m.approved_revision = m.revision AND m.approved_destination_revision = m.destination_revision
            AND m.approved_authentication_revision = m.authentication_revision
            """;
    static final String RUN_BUDGET_CURRENT = """
            b.run_uuid = :#{#e.runId()} AND b.connection_uuid = m.uuid AND b.configuration_revision = m.revision
            AND b.destination_revision = m.destination_revision AND b.authentication_revision = m.authentication_revision
            """;
    static final String TIME_CURRENT = """
            clock_timestamp() < :#{#q.expiresAt()} AND clock_timestamp() < :operationDeadline
            """;
    static final String RUN_CURRENT = AiRuntimeTransitionSql.ADMISSION_CURRENT
            + """
                    AND EXISTS (SELECT 1 FROM {h-schema}ai_runtime_attempt a JOIN {h-schema}ai_runtime_run r ON r.uuid = a.run_uuid
                        WHERE a.uuid = :#{#e.attemptId()} AND r.uuid = :#{#e.runId()} AND r.state = 'RUNNING'
                            AND a.state = 'CLAIMED' AND a.claim_uuid = :#{#q.claim().claimId()}
                            AND a.winner_cluster = :#{#q.claim().workload().cluster()}
                            AND a.winner_pod_uid = :#{#q.claim().workload().podUid()}
                            AND a.fence = :#{#q.claim().fence()} AND r.fence = a.fence)
                    AND EXISTS (SELECT 1 FROM {h-schema}ai_model_connection m JOIN {h-schema}ai_model_run_budget b
                        ON b.connection_uuid = m.uuid WHERE
                    """
            + MODEL_CURRENT + AND + RUN_BUDGET_CURRENT + ") AND " + TIME_CURRENT;
    static final String MANAGEMENT_SESSION_CURRENT = """
            s.session_uuid = :#{#q.sessionId()} AND s.actor_uuid = :#{#q.actorId()}
            AND s.action = :#{#q.action().name()} AND s.enabled AND clock_timestamp() < s.expires_at
            AND s.connection_uuid = m.uuid AND s.configuration_revision = m.revision
            AND s.destination_revision = m.destination_revision AND s.authentication_revision = m.authentication_revision
            """;
    static final String MANAGEMENT_CURRENT = """
            SELECT EXISTS (SELECT 1 FROM {h-schema}ai_model_connection m JOIN {h-schema}ai_model_management_session s
                ON s.connection_uuid = m.uuid WHERE
            """ + MODEL_CURRENT + AND + MANAGEMENT_SESSION_CURRENT + ") AND " + TIME_CURRENT;
    static final String EXACT_MODEL = """
            i.connection_uuid = :#{#q.connection().id()} AND i.model_identifier = :#{#q.connection().modelIdentifier()}
            AND i.configuration_revision = :#{#q.connection().configuration()}
            AND i.destination_revision = :#{#q.connection().destination()}
            AND i.authentication_revision = :#{#q.connection().authentication()}
            """;
    static final String EXACT_CLAIM = """
            i.run_uuid = :#{#e.runId()} AND i.attempt_uuid = :#{#e.attemptId()}
            AND i.claim_uuid = :#{#q.claim().claimId()} AND i.cluster = :#{#q.claim().workload().cluster()}
            AND i.pod_uid = :#{#q.claim().workload().podUid()} AND i.fence = :#{#q.claim().fence()}
            AND i.actor_uuid = (SELECT actor_uuid FROM {h-schema}ai_runtime_run WHERE uuid = :#{#e.runId()})
            """;
    static final String EXACT_SESSION = """
            i.session_uuid = :#{#q.sessionId()} AND i.actor_uuid = :#{#q.actorId()} AND i.action = :#{#q.action().name()}
            """;
    static final String EXACT_PREPARATION = """
            i.payload = :#{#q.payload().bytes()} AND i.payload_sha256 = :#{#q.payload().sha256()}
            AND i.output_tokens = :#{#q.outputTokens()} AND i.expires_at = :#{#q.expiresAt()}
            """;
    static final String EXACT_REDEMPTION = """
            i.payload_sha256 = :#{#q.payloadSha256()} AND i.payload_sha256 = encode(sha256(i.payload), 'hex')
            AND i.expires_at = :#{#q.expiresAt()}
            """;
    static final String RUN_REPLAY = "SELECT i.uuid AS \"intentId\", (" + EXACT_MODEL + AND + EXACT_CLAIM + AND
            + EXACT_PREPARATION + """
                    ) AS exact FROM {h-schema}ai_model_run_intent i
                    WHERE i.run_uuid = :#{#e.runId()} AND i.request_key = :#{#q.requestKey()}
                    """;
    static final String MANAGEMENT_REPLAY = "SELECT i.uuid AS \"intentId\", (" + EXACT_MODEL + AND + EXACT_SESSION + AND
            + EXACT_PREPARATION + """
                    ) AS exact FROM {h-schema}ai_model_management_intent i
                    WHERE i.session_uuid = :#{#q.sessionId()} AND i.request_key = :#{#q.requestKey()}
                    """;
    static final String RESERVE_RUN = """
            UPDATE {h-schema}ai_model_run_budget b SET reserved_calls = b.reserved_calls + 1,
                reserved_tokens = b.reserved_tokens + :#{#q.outputTokens()}
            WHERE b.run_uuid = :#{#e.runId()} AND b.reserved_calls < b.max_calls
                AND :#{#q.outputTokens()} <= b.max_tokens - b.reserved_tokens AND (
            """ + RUN_CURRENT + ")";
    static final String RESERVE_MANAGEMENT = """
            UPDATE {h-schema}ai_model_management_session s SET reserved_calls = s.reserved_calls + 1,
                reserved_tokens = s.reserved_tokens + :#{#q.outputTokens()}
            WHERE s.session_uuid = :#{#q.sessionId()} AND s.reserved_calls < s.max_calls
                AND :#{#q.outputTokens()} <= s.max_tokens - s.reserved_tokens AND (
            """ + MANAGEMENT_CURRENT + ")";
    static final String MODEL_COLUMNS = """
            connection_uuid, model_identifier, configuration_revision, destination_revision, authentication_revision,
            payload, payload_sha256, output_tokens, expires_at
            """;
    static final String MODEL_VALUES = """
            :#{#q.connection().id()}, :#{#q.connection().modelIdentifier()}, :#{#q.connection().configuration()}, :#{#q.connection().destination()},
            :#{#q.connection().authentication()}, :#{#q.payload().bytes()}, :#{#q.payload().sha256()},
            :#{#q.outputTokens()}, :#{#q.expiresAt()}
            """;
    static final String INSERT_RUN = """
            INSERT INTO {h-schema}ai_model_run_intent
                (uuid, request_key, run_uuid, attempt_uuid, actor_uuid, claim_uuid, cluster, pod_uid, fence,
            """ + MODEL_COLUMNS + ") SELECT " + """
                :#{#q.intentId()}, :#{#q.requestKey()}, :#{#e.runId()}, :#{#e.attemptId()}, r.actor_uuid,
                :#{#q.claim().claimId()}, :#{#q.claim().workload().cluster()}, :#{#q.claim().workload().podUid()},
                :#{#q.claim().fence()},
            """ + MODEL_VALUES + " FROM {h-schema}ai_runtime_run r WHERE r.uuid = :#{#e.runId()} AND (" + RUN_CURRENT
            + ")";
    static final String INSERT_MANAGEMENT = """
            INSERT INTO {h-schema}ai_model_management_intent
                (uuid, request_key, actor_uuid, session_uuid, action,
            """ + MODEL_COLUMNS + ") SELECT :#{#q.intentId()}, :#{#q.requestKey()}, :#{#q.actorId()}, "
            + ":#{#q.sessionId()}, :#{#q.action().name()}, " + MODEL_VALUES + " WHERE (" + MANAGEMENT_CURRENT + ")";
    static final String CONSUME_RUN = """
            UPDATE {h-schema}ai_model_run_intent i SET state = 'CONSUMED', consumed_at = clock_timestamp(),
                gateway_correlation = :#{#q.gatewayCorrelation()}
            WHERE i.uuid = :#{#q.intentId()} AND i.state = 'PREPARED' AND
            """ + EXACT_MODEL + AND + EXACT_CLAIM + AND + EXACT_REDEMPTION + " AND (" + RUN_CURRENT + ")";
    static final String CONSUME_RUN_ASSIGNED = CONSUME_RUN + " AND i.uuid = :intentId AND ("
            + AiModelRunOutcomeSql.ASSIGNED + ")";
    static final String CONSUME_MANAGEMENT = """
            UPDATE {h-schema}ai_model_management_intent i SET state = 'CONSUMED', consumed_at = clock_timestamp(),
                gateway_correlation = :#{#q.gatewayCorrelation()}
            WHERE i.uuid = :#{#q.intentId()} AND i.state = 'PREPARED' AND
            """ + EXACT_MODEL + AND + EXACT_SESSION + AND + EXACT_REDEMPTION + " AND (" + MANAGEMENT_CURRENT + ")";
    static final String CONSUME_MANAGEMENT_ASSIGNED = CONSUME_MANAGEMENT + " AND i.uuid=:intentId AND ("
            + AiModelManagementGatewaySql.ASSIGNED + ")";
    static final String DISPATCH_COLUMNS = """
            SELECT i.uuid AS "intentId", i.connection_uuid AS "connectionId", i.model_identifier AS "modelIdentifier",
                i.configuration_revision AS configuration, i.destination_revision AS destination,
                i.authentication_revision AS authentication, i.payload AS payload, i.output_tokens AS "outputTokens", m.origin AS origin,
                m.credential_reference AS "credentialReference", i.expires_at AS "expiresAt",
                i.gateway_correlation AS "gatewayCorrelation"
            """;
    static final String DISPATCH_WHERE = """
            WHERE i.uuid = :intentId AND i.state = 'CONSUMED' AND i.gateway_correlation = :correlation
            """;
    static final String RUN_DISPATCH = DISPATCH_COLUMNS + """
            FROM {h-schema}ai_model_run_intent i JOIN {h-schema}ai_model_connection m ON m.uuid = i.connection_uuid
            """ + DISPATCH_WHERE;
    static final String MANAGEMENT_DISPATCH = DISPATCH_COLUMNS
            + """
                    FROM {h-schema}ai_model_management_intent i JOIN {h-schema}ai_model_connection m ON m.uuid = i.connection_uuid
                    """
            + DISPATCH_WHERE;

    private AiModelDispatchSql() {
    }
}
