package com.otilm.core.dao.repository.ai;

/** Independent management deployment lock serializes invalidation with each native admission decision. */
public final class AiRuntimeManagementGatewaySql {
    private AiRuntimeManagementGatewaySql() {
    }

    static final String CONFIGURE = """
                UPDATE {h-schema}ai_management_gateway_deployment SET revision=revision+1, configured=TRUE,
                    image_digest=:#{#p.imageDigest()}, cluster=:#{#p.launch().cluster()},
                    namespace_name=:#{#p.launch().namespaceName()},namespace_uid=:#{#p.launch().namespaceUid()},
                    service_account_name=:#{#p.launch().serviceAccountName()},service_account_uid=:#{#p.launch().serviceAccountUid()},
                    template_digest=:#{#p.launch().templateDigest()},runtime_class=:#{#p.launch().runtimeClass()}
                WHERE id=1 AND revision=:expected AND clock_timestamp()<:operationDeadline
            """;
    static final String DISABLE = """
                UPDATE {h-schema}ai_management_gateway_deployment SET revision=revision+1,configured=FALSE,
                    image_digest=NULL,cluster=NULL,namespace_name=NULL,namespace_uid=NULL,
                    service_account_name=NULL,service_account_uid=NULL,template_digest=NULL,runtime_class=NULL
                WHERE id=1 AND revision=:expected AND clock_timestamp()<:operationDeadline
            """;
    static final String STARTUP_DENY = """
                UPDATE {h-schema}ai_management_gateway_deployment
                SET revision=CASE WHEN revision<9223372036854775807 THEN revision+1 ELSE revision END,
                    configured=FALSE,image_digest=NULL,cluster=NULL,namespace_name=NULL,namespace_uid=NULL,
                    service_account_name=NULL,service_account_uid=NULL,template_digest=NULL,runtime_class=NULL
                WHERE id=1 AND revision=:expected AND configured AND clock_timestamp()<:operationDeadline
            """;
    static final String MATCH_DEPLOYMENT = """
            d.id=1 AND d.configured AND d.revision=:#{#o.deployment().revision()}
            AND d.image_digest=:#{#o.deployment().pins().imageDigest()}
            AND d.cluster=:#{#o.deployment().pins().launch().cluster()}
            AND d.namespace_name=:#{#o.deployment().pins().launch().namespaceName()}
            AND d.namespace_uid=:#{#o.deployment().pins().launch().namespaceUid()}
            AND d.service_account_name=:#{#o.deployment().pins().launch().serviceAccountName()}
            AND d.service_account_uid=:#{#o.deployment().pins().launch().serviceAccountUid()}
            AND d.template_digest=:#{#o.deployment().pins().launch().templateDigest()}
            AND d.runtime_class=:#{#o.deployment().pins().launch().runtimeClass()}
            AND :#{#o.observedAt()}<=clock_timestamp() AND clock_timestamp()<:#{#o.validUntil()}
            AND clock_timestamp()<:operationDeadline
            """;
    static final String OBSERVE = """
            INSERT INTO {h-schema}ai_management_gateway_registration AS old
                (deployment_revision,pod_name,pod_uid,observation_sequence,evidence_id,observed_at,valid_until)
            SELECT d.revision,:#{#o.subject().podName()},:#{#o.subject().podUid()},:#{#o.sequence()},
                :#{#o.evidenceId()},:#{#o.observedAt()},:#{#o.validUntil()}
            FROM {h-schema}ai_management_gateway_deployment d WHERE
            """ + MATCH_DEPLOYMENT + """
            ON CONFLICT(pod_uid) DO UPDATE SET observation_sequence=EXCLUDED.observation_sequence,
                evidence_id=EXCLUDED.evidence_id,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until
            WHERE old.deployment_revision=EXCLUDED.deployment_revision AND old.pod_name=EXCLUDED.pod_name
                AND NOT old.revoked AND clock_timestamp()<old.valid_until
                AND old.observation_sequence<EXCLUDED.observation_sequence AND old.observed_at<=EXCLUDED.observed_at
            """;
    static final String REPLAY = """
            SELECT EXISTS(SELECT 1 FROM {h-schema}ai_management_gateway_deployment d
            JOIN {h-schema}ai_management_gateway_registration w ON w.deployment_revision=d.revision
            WHERE
            """ + MATCH_DEPLOYMENT + """
            AND w.pod_uid=:#{#o.subject().podUid()} AND w.pod_name=:#{#o.subject().podName()}
            AND NOT w.revoked AND w.observation_sequence=:#{#o.sequence()} AND w.evidence_id=:#{#o.evidenceId()}
            AND w.observed_at=:#{#o.observedAt()} AND w.valid_until=:#{#o.validUntil()})
            """;
    public static final String CURRENT = """
            SELECT d.revision AS "deploymentRevision", w.observation_sequence AS "observationSequence",
                w.evidence_id AS "evidenceId",w.valid_until AS "validUntil"
            FROM {h-schema}ai_management_gateway_deployment d
            JOIN {h-schema}ai_management_gateway_registration w ON w.deployment_revision=d.revision
            WHERE d.id=1 AND d.configured AND d.cluster=:#{#peer.cluster()}
                AND d.namespace_name=:#{#peer.namespace()} AND d.service_account_name=:#{#peer.serviceAccount()}
                AND w.pod_name=:#{#peer.podName()} AND w.pod_uid=:#{#peer.podUid()} AND NOT w.revoked
                AND w.observed_at<=clock_timestamp() AND clock_timestamp()<w.valid_until AND clock_timestamp()<:operationDeadline
            """;
    static final String REVOKE = """
            UPDATE {h-schema}ai_management_gateway_registration w SET revoked=TRUE
            FROM {h-schema}ai_management_gateway_deployment d
            WHERE d.id=1 AND w.deployment_revision=d.revision AND d.cluster=:#{#peer.cluster()}
                AND d.namespace_name=:#{#peer.namespace()} AND d.service_account_name=:#{#peer.serviceAccount()}
                AND w.pod_name=:#{#peer.podName()} AND w.pod_uid=:#{#peer.podUid()} AND clock_timestamp()<:operationDeadline
            """;
}
