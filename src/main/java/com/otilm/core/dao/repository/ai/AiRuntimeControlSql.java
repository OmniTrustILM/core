package com.otilm.core.dao.repository.ai;

final class AiRuntimeControlSql {
    static final String FRESH = """
            c.evidence_id IS NOT NULL AND c.observation_sequence > 0
            AND c.observed_at <= clock_timestamp() AND clock_timestamp() < c.valid_until
            """;

    static final String ADMISSION = """
            c.enabled AND c.generation = r.control_generation AND a.control_generation = c.generation
            AND c.image_digest = a.image_digest AND c.profile_revision = a.profile_revision
            AND c.security_revision = a.security_revision AND c.trust_revision = a.trust_revision
            AND c.protocol = a.protocol AND c.cluster = l.cluster AND c.namespace_name = l.namespace_name
            AND c.namespace_uid = l.namespace_uid AND c.service_account_name = l.service_account_name
            AND c.service_account_uid = l.service_account_uid AND c.template_digest = l.template_digest
            AND c.runtime_class = l.runtime_class AND
            """ + FRESH;

    static final String CHANGE = """
            UPDATE {h-schema}ai_runtime_control
            SET generation = generation + 1, enabled = FALSE,
                image_digest = :#{#pins.imageDigest()}, profile_revision = :#{#pins.profileRevision()},
                security_revision = :#{#pins.securityRevision()}, trust_revision = :#{#pins.trustRevision()},
                protocol = :#{#pins.protocol()}, cluster = :#{#pins.launch().cluster()},
                namespace_name = :#{#pins.launch().namespaceName()}, namespace_uid = :#{#pins.launch().namespaceUid()},
                service_account_name = :#{#pins.launch().serviceAccountName()},
                service_account_uid = :#{#pins.launch().serviceAccountUid()},
                template_digest = :#{#pins.launch().templateDigest()}, runtime_class = :#{#pins.launch().runtimeClass()},
                observation_sequence = 0, evidence_id = NULL, observed_at = NULL, valid_until = NULL, updated_at = :at
            WHERE id = 1 AND generation = :#{#expected.generation()} AND generation < 9223372036854775807
            """;

    static final String DISABLE = """
            UPDATE {h-schema}ai_runtime_control
            SET generation = CASE WHEN generation < 9223372036854775807 THEN generation + 1 ELSE generation END,
                enabled = FALSE, observation_sequence = 0, evidence_id = NULL, observed_at = NULL,
                valid_until = NULL, updated_at = :at
            WHERE id = 1 AND generation = :#{#expected.generation()}
            """;

    static final String ENABLE = """
            UPDATE {h-schema}ai_runtime_control c SET enabled = TRUE, updated_at = :at
            WHERE c.id = 1 AND c.generation = :#{#expected.generation()}
                AND c.generation < 9223372036854775807 AND NOT c.enabled AND
            """ + FRESH;

    static final String OBSERVE = """
            UPDATE {h-schema}ai_runtime_control c
            SET observation_sequence = :#{#o.sequence()}, evidence_id = :#{#o.evidenceId()},
                observed_at = :#{#o.observedAt()}, valid_until = :#{#o.validUntil()}, updated_at = :at
            WHERE c.id = 1 AND c.generation = :#{#o.expected().generation()}
                AND c.image_digest = :#{#o.observedPins().imageDigest()}
                AND c.profile_revision = :#{#o.observedPins().profileRevision()}
                AND c.security_revision = :#{#o.observedPins().securityRevision()}
                AND c.trust_revision = :#{#o.observedPins().trustRevision()}
                AND c.protocol = :#{#o.observedPins().protocol()} AND c.cluster = :#{#o.observedPins().launch().cluster()}
                AND c.namespace_name = :#{#o.observedPins().launch().namespaceName()}
                AND c.namespace_uid = :#{#o.observedPins().launch().namespaceUid()}
                AND c.service_account_name = :#{#o.observedPins().launch().serviceAccountName()}
                AND c.service_account_uid = :#{#o.observedPins().launch().serviceAccountUid()}
                AND c.template_digest = :#{#o.observedPins().launch().templateDigest()}
                AND c.runtime_class = :#{#o.observedPins().launch().runtimeClass()}
                AND :#{#o.observedAt()} <= clock_timestamp() AND clock_timestamp() < :#{#o.validUntil()}
                AND ((c.observation_sequence = 0 AND NOT c.enabled)
                    OR (c.observation_sequence < :#{#o.sequence()} AND c.observed_at <= :#{#o.observedAt()}
                        AND clock_timestamp() < c.valid_until))
            """;

    private AiRuntimeControlSql() {
    }
}
