package com.otilm.core.dao.repository.ai;

/** Immutable Core delegation; no business permission or role-only bearer grant. */
public final class AiModelManagementGatewaySql {
    private AiModelManagementGatewaySql() {
    }

    public static final String ASSIGNED = """
            SELECT EXISTS(SELECT 1 FROM {h-schema}ai_model_management_gateway_assignment g
            WHERE :role='GATEWAY_MANAGEMENT' AND g.intent_uuid=:intentId
                AND g.cluster=:#{#peer.cluster()} AND g.namespace_name=:#{#peer.namespace()}
                AND g.service_account_name=:#{#peer.serviceAccount()} AND g.pod_name=:#{#peer.podName()}
                AND g.pod_uid=:#{#peer.podUid()} AND g.deployment_revision=(SELECT membership."deploymentRevision" FROM (
            """
            + AiRuntimeManagementGatewaySql.CURRENT + """
                    ) membership))
                    """;
    static final String ASSIGN = """
            INSERT INTO {h-schema}ai_model_management_gateway_assignment
                (intent_uuid,deployment_revision,cluster,namespace_name,service_account_name,pod_name,pod_uid)
            SELECT i.uuid,membership."deploymentRevision",:#{#peer.cluster()},:#{#peer.namespace()},
                :#{#peer.serviceAccount()},:#{#peer.podName()},:#{#peer.podUid()}
            FROM {h-schema}ai_model_management_intent i CROSS JOIN (
            """ + AiRuntimeManagementGatewaySql.CURRENT + """
            ) membership
            WHERE :role='GATEWAY_MANAGEMENT' AND i.uuid=:intentId AND i.state='PREPARED'
                AND clock_timestamp()<i.expires_at AND clock_timestamp()<:operationDeadline
            ON CONFLICT(intent_uuid) DO NOTHING
            """;
    static final String REPLAY = """
            SELECT (
            """ + ASSIGNED + """
            ) AS exact FROM {h-schema}ai_model_management_gateway_assignment g
            JOIN {h-schema}ai_model_management_intent i ON i.uuid=g.intent_uuid
            WHERE g.intent_uuid=:intentId AND i.state='PREPARED' AND clock_timestamp()<i.expires_at
                AND clock_timestamp()<:operationDeadline AND EXISTS (
            """ + AiRuntimeManagementGatewaySql.CURRENT + """
            )
            """;
}
