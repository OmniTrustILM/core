package com.otilm.core.util;

import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiRuntimeKernel;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

public final class AiRuntimeFixture {
    private static final String MIGRATION = "db/migration/V202610261200__ai_runtime_kernel.sql";
    private static final String CONTROL_MIGRATION = "db/migration/V202611041200__ai_runtime_control.sql";
    public static final String IMAGE = "sha256:" + "a".repeat(64);
    public static final String TEMPLATE = "sha256:" + "b".repeat(64);

    private AiRuntimeFixture() {
    }

    public static void install(DataSource source) throws Exception {
        try (Connection connection = source.getConnection(); Statement statement = connection.createStatement()) {
            statement
                    .execute(
                            "DROP TABLE IF EXISTS ai_model_management_outcome, ai_model_management_gateway_assignment");
            statement.execute("DROP FUNCTION IF EXISTS ai_model_management_gateway_immutable_guard()");
            statement
                    .execute(
                            "DROP TABLE IF EXISTS ai_management_gateway_registration, ai_management_gateway_deployment");
            statement.execute("DROP TABLE IF EXISTS ai_model_run_outcome, ai_model_run_gateway_assignment");
            statement.execute("DROP FUNCTION IF EXISTS ai_model_run_gateway_immutable_guard()");
            statement.execute("DROP TABLE IF EXISTS ai_runtime_gateway_registration");
            statement.execute("DROP TABLE IF EXISTS ai_runtime_gateway_deployment");
            statement
                    .execute(
                            """
                                    DROP TABLE IF EXISTS ai_model_run_input, ai_model_run_intent, ai_model_management_intent, ai_model_run_budget,
                                        ai_model_management_session, ai_model_connection
                                    """);
            statement.execute("""
                    DROP TABLE IF EXISTS ai_runtime_workload, ai_runtime_launch, ai_runtime_attempt, ai_runtime_run,
                        ai_runtime_control
                    """);
            statement.execute("DROP FUNCTION IF EXISTS ai_model_run_input_immutable_guard()");
            for (String migration : new String[]{MIGRATION, CONTROL_MIGRATION}) {
                String sql = new String(new ClassPathResource(migration).getContentAsByteArray(),
                        StandardCharsets.UTF_8);
                statement.execute(sql);
            }
        }
    }

    /** Explicit fixture facts only: this test window does not select a production readiness TTL or producer. */
    public static ControlVersion enableTestControl(AiRuntimeKernel kernel, Instant at) {
        ControlVersion current = kernel.control().orElseThrow().version();
        ControlPins pins = ControlPins.forAttempt(attempt(at));
        ControlSnapshot configured = kernel.changeControl(current, pins).value().orElseThrow();
        ReadinessObservation evidence = new ReadinessObservation(configured.version(), pins, 1, UUID.randomUUID(), at,
                at.plusSeconds(120));
        assertThat(kernel.observeControl(evidence).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.enableControl(configured.version()).status()).isEqualTo(Status.APPLIED);
        return configured.version();
    }

    public static Instant now(DataSource source) throws Exception {
        try (Connection connection = source.getConnection();
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("SELECT clock_timestamp()")) {
            result.next();
            return result.getTimestamp(1).toInstant();
        }
    }

    public static RunSpec run(Instant now) {
        return new RunSpec(UUID.randomUUID(), Optional.empty(), UUID.randomUUID(), "synthetic", 2, 2, 5,
                now.plusSeconds(120));
    }

    public static AttemptSpec attempt(Instant now) {
        LaunchSpec launch = new LaunchSpec("cluster-one", "ai-proof", "namespace-one", "runner", "account-one",
                TEMPLATE, "sandbox");
        return new AttemptSpec(UUID.randomUUID(), now.plusSeconds(30), now.plusSeconds(60), IMAGE, 1, 1, 1, "v1",
                launch);
    }

    public static Expected expected(RunSnapshot snapshot) {
        return new Expected(snapshot.spec().runId(), snapshot.attempt().spec().attemptId(), snapshot.revision(),
                snapshot.fence());
    }

    public static WorkloadObservation observation(RunSnapshot snapshot, WorkloadRef ref, long sequence,
            boolean registered) {
        return observation(snapshot, ref, sequence, snapshot.attempt().spec().maxDeadline(), registered);
    }

    public static WorkloadObservation observation(RunSnapshot snapshot, WorkloadRef ref, long sequence,
            Instant validUntil, boolean registered) {
        AttemptSpec attempt = snapshot.attempt().spec();
        LaunchSpec launch = attempt.launch();
        return new WorkloadObservation(expected(snapshot), ref.cluster(), launch.namespaceName(), launch.namespaceUid(),
                launch.serviceAccountName(), launch.serviceAccountUid(), snapshot.launch().jobName(), "job-one",
                "runner-" + ref.podUid(), ref.podUid(), attempt.imageDigest(), launch.templateDigest(),
                launch.runtimeClass(), attempt.profileRevision(), attempt.securityRevision(), attempt.trustRevision(),
                attempt.protocol(), sequence, validUntil, registered);
    }
}
