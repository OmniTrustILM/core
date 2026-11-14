package com.otilm.core.dao.repository.ai;

/** Separate metadata and protected-input projections; neither grants authority. */
final class AiModelRunInputSql {
    private AiModelRunInputSql() {
    }

    private static final String CURRENT_MODEL = """
            b.configuration_revision = m.revision AND b.destination_revision = m.destination_revision
                AND b.authentication_revision = m.authentication_revision
            """;
    private static final String BINDING = """
            b.connection_uuid = :#{#model.id()} AND b.configuration_revision = :#{#model.configuration()}
                AND b.destination_revision = :#{#model.destination()}
                AND b.authentication_revision = :#{#model.authentication()}
                AND m.model_identifier = :#{#model.modelIdentifier()}
            """;
    static final String CONNECTION = """
            SELECT m.uuid AS id, b.configuration_revision AS configuration,
                b.destination_revision AS destination, b.authentication_revision AS authentication,
                m.model_identifier AS "modelIdentifier"
            FROM {h-schema}ai_model_run_budget b JOIN {h-schema}ai_model_connection m ON m.uuid = b.connection_uuid
            WHERE b.run_uuid = :runId AND (
            """ + CURRENT_MODEL + ")";
    static final String READ = """
            SELECT i.run_uuid AS "runId", i.ra_profile_uuid AS "raProfileUuid",
                i.certificate_uuids AS "certificateUuids", i.instructions, i.prompt,
                i.output_tokens AS "outputTokens"
            FROM {h-schema}ai_model_run_input i JOIN {h-schema}ai_runtime_run r
                ON r.uuid = i.run_uuid AND r.actor_uuid = i.actor_uuid
                JOIN {h-schema}ai_model_run_budget b ON b.run_uuid = i.run_uuid
                JOIN {h-schema}ai_model_connection m ON m.uuid = b.connection_uuid
            WHERE i.run_uuid = :runId AND (
            """ + CURRENT_MODEL + ") AND (" + BINDING + ")";
    static final String INSERT = """
            INSERT INTO {h-schema}ai_model_run_input
                (run_uuid, actor_uuid, ra_profile_uuid, certificate_uuids, instructions, prompt, output_tokens)
            SELECT r.uuid, r.actor_uuid, :#{#input.raProfileUuid()}, CAST(:certificates AS UUID[]),
                :#{#input.instructions()}, :#{#input.prompt()}, :#{#input.outputTokens()}
            FROM {h-schema}ai_runtime_run r WHERE r.uuid = :#{#input.runId()}
            ON CONFLICT (run_uuid) DO NOTHING
            """;
    static final String EXACT = """
            SELECT EXISTS (SELECT 1 FROM {h-schema}ai_model_run_input i JOIN {h-schema}ai_runtime_run r
                ON r.uuid = i.run_uuid AND r.actor_uuid = i.actor_uuid
                WHERE i.run_uuid = :#{#input.runId()} AND i.ra_profile_uuid = :#{#input.raProfileUuid()}
                    AND i.certificate_uuids = CAST(:certificates AS UUID[]) AND i.instructions = :#{#input.instructions()}
                    AND i.prompt = :#{#input.prompt()} AND i.output_tokens = :#{#input.outputTokens()})
            """;
}
