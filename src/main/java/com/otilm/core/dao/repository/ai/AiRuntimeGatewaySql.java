package com.otilm.core.dao.repository.ai;

final class AiRuntimeGatewaySql {
    static final String CONFIGURE = """
            WITH eligible AS MATERIALIZED (
                SELECT c.generation FROM {h-schema}ai_runtime_control c
                WHERE c.id = 1 AND NOT c.enabled AND c.generation = :#{#d.controlGeneration()}
            ), removed AS (
                DELETE FROM {h-schema}ai_runtime_gateway_registration
                WHERE role = :role AND EXISTS (SELECT 1 FROM eligible)
            )
            INSERT INTO {h-schema}ai_runtime_gateway_deployment
                (role, control_generation, image_digest, cluster, namespace_name, namespace_uid,
                    service_account_name, service_account_uid, template_digest, runtime_class)
            SELECT :role, :#{#d.controlGeneration()}, :#{#d.imageDigest()}, :#{#d.launch().cluster()},
                :#{#d.launch().namespaceName()}, :#{#d.launch().namespaceUid()}, :#{#d.launch().serviceAccountName()},
                :#{#d.launch().serviceAccountUid()}, :#{#d.launch().templateDigest()}, :#{#d.launch().runtimeClass()}
            FROM eligible
            ON CONFLICT (role) DO UPDATE SET
                control_generation = EXCLUDED.control_generation, image_digest = EXCLUDED.image_digest,
                cluster = EXCLUDED.cluster, namespace_name = EXCLUDED.namespace_name, namespace_uid = EXCLUDED.namespace_uid,
                service_account_name = EXCLUDED.service_account_name, service_account_uid = EXCLUDED.service_account_uid,
                template_digest = EXCLUDED.template_digest, runtime_class = EXCLUDED.runtime_class
            """;

    static final String OBSERVE = """
            INSERT INTO {h-schema}ai_runtime_gateway_registration AS existing
                (role, control_generation, pod_name, pod_uid, observation_sequence, evidence_id, observed_at, valid_until)
            SELECT d.role, d.control_generation, :#{#o.subject().podName()}, :#{#o.subject().podUid()},
                :#{#o.sequence()}, :#{#o.evidenceId()}, :#{#o.observedAt()}, :#{#o.validUntil()}
            FROM {h-schema}ai_runtime_gateway_deployment d
            JOIN {h-schema}ai_runtime_control c ON c.id = 1 AND c.generation = d.control_generation
            WHERE d.role = :role
                AND d.control_generation = :#{#o.deployment().controlGeneration()}
                AND d.image_digest = :#{#o.deployment().imageDigest()}
                AND d.cluster = :#{#o.deployment().launch().cluster()}
                AND d.namespace_name = :#{#o.deployment().launch().namespaceName()}
                AND d.namespace_uid = :#{#o.deployment().launch().namespaceUid()}
                AND d.service_account_name = :#{#o.deployment().launch().serviceAccountName()}
                AND d.service_account_uid = :#{#o.deployment().launch().serviceAccountUid()}
                AND d.template_digest = :#{#o.deployment().launch().templateDigest()}
                AND d.runtime_class = :#{#o.deployment().launch().runtimeClass()}
                AND :#{#o.observedAt()} <= clock_timestamp() AND clock_timestamp() < :#{#o.validUntil()}
            ON CONFLICT (role, pod_uid) DO UPDATE SET
                pod_name = EXCLUDED.pod_name, observation_sequence = EXCLUDED.observation_sequence,
                evidence_id = EXCLUDED.evidence_id, observed_at = EXCLUDED.observed_at, valid_until = EXCLUDED.valid_until
            WHERE existing.control_generation = EXCLUDED.control_generation
                AND existing.pod_name = EXCLUDED.pod_name
                AND NOT existing.revoked
                AND existing.observation_sequence < EXCLUDED.observation_sequence
                AND existing.observed_at <= EXCLUDED.observed_at AND clock_timestamp() < existing.valid_until
            """;

    static final String CURRENT = """
            SELECT d.control_generation AS "controlGeneration", w.observation_sequence AS "observationSequence",
                w.evidence_id AS "evidenceId", w.valid_until AS "validUntil"
            FROM {h-schema}ai_runtime_gateway_deployment d
            JOIN {h-schema}ai_runtime_gateway_registration w
                ON w.role = d.role AND w.control_generation = d.control_generation
            JOIN {h-schema}ai_runtime_control c ON c.id = 1 AND c.generation = d.control_generation
            WHERE d.role = :role AND d.cluster = :#{#peer.cluster()}
                AND d.namespace_name = :#{#peer.namespace()} AND d.service_account_name = :#{#peer.serviceAccount()}
                AND w.pod_name = :#{#peer.podName()} AND w.pod_uid = :#{#peer.podUid()}
                AND NOT w.revoked
                AND w.observed_at <= clock_timestamp() AND clock_timestamp() < w.valid_until
                AND c.enabled AND
            """ + AiRuntimeControlSql.FRESH;

    static final String REVOKE = """
            UPDATE {h-schema}ai_runtime_gateway_registration w SET revoked = TRUE
            FROM {h-schema}ai_runtime_gateway_deployment d
            WHERE d.role = w.role AND d.control_generation = w.control_generation
                AND d.control_generation = :generation AND d.role = :role
                AND d.cluster = :#{#peer.cluster()} AND d.namespace_name = :#{#peer.namespace()}
                AND d.service_account_name = :#{#peer.serviceAccount()}
                AND w.pod_name = :#{#peer.podName()} AND w.pod_uid = :#{#peer.podUid()}
            """;

    private AiRuntimeGatewaySql() {
    }
}
