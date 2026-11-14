package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.util.AiModelDispatchFixture;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.time.Instant;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static org.assertj.core.api.Assertions.assertThat;

/** Real database admission and projection checks; no remote authorization or native identity claim. */
class AiModelRunDispatchAuthorityITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiModelDispatchWriter writer;
    @Autowired
    private AiModelDispatchRepository repository;
    private RunSnapshot run;
    private Claim claim;
    private ConnectionVersion model;
    private RunPreparation request;

    @BeforeEach
    void retainedDatabaseFacts() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        model = AiModelDispatchFixture.approvedModel(source);
        Instant now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        run = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        var workload = new WorkloadRef("cluster-one", UUID.randomUUID().toString());
        kernel.observe(AiRuntimeFixture.observation(run, workload, 1, true));
        var current = kernel.snapshot(run.spec().runId()).orElseThrow();
        claim = kernel.bootstrap(expected(current), workload).value().orElseThrow();
        run = kernel.snapshot(run.spec().runId()).orElseThrow();
        AiModelDispatchFixture.runBudget(source, run.spec().runId(), model, 2, 64);
        request = new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(run), claim.binding(), model,
                AiModelDispatchFixture.payload(32, "stored-input"), 32, now.plusSeconds(40));
    }

    @Test
    void nativeProjectionRetainsEveryStoredBindingAndExactPayload() throws Exception {
        assertThat(writer.prepareRun(request, run.spec().actorId(), budget()).status()).isEqualTo(Status.APPLIED);

        var byKey = repository.preparedRunByKey(run.spec().runId(), request.requestKey()).orElseThrow();
        var byId = repository.preparedRunById(run.spec().runId(), request.intentId()).orElseThrow();

        assertThat(byId).isEqualTo(byKey);
        assertThat(byId.intentId()).isEqualTo(request.intentId());
        assertThat(byId.actorId()).isEqualTo(run.spec().actorId());
        assertThat(byId.claim()).isEqualTo(claim.binding());
        assertThat(byId.connection()).isEqualTo(model);
        assertThat(byId.payload()).isEqualTo(request.payload());
        assertThat(byId.outputTokens()).isEqualTo(32);
        assertThat(byId.expiresAt()).isEqualTo(request.expiresAt());
        assertThat(byId.toString()).isEqualTo("RunIntent[redacted]");
        assertThat(repository.preparedRunById(UUID.randomUUID(), request.intentId())).isEmpty();
        assertThat(repository.preparedRunByKey(UUID.randomUUID(), request.requestKey())).isEmpty();
        var redemption = redemption();
        assertThat(writer.consumeRun(redemption, run.spec().actorId(), budget())).isPresent();
        assertThat(writer.consumeRun(redemption, run.spec().actorId(), budget())).isEmpty();
        assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isEqualTo(1);
    }

    @Test
    void actorDriftWithoutRevisionCannotReserveUnderOldAuthorization() throws Exception {
        UUID authorizedActor = run.spec().actorId();
        replaceActor(UUID.randomUUID());
        assertThat(kernel.snapshot(run.spec().runId()).orElseThrow().revision()).isEqualTo(run.revision());
        String before = AiModelDispatchFixture.fingerprint(source);

        assertThat(writer.prepareRun(request, authorizedActor, budget()).status()).isEqualTo(Status.DENIED);

        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isZero();
        assertThat(repository.preparedRunById(run.spec().runId(), request.intentId())).isEmpty();
    }

    @Test
    void actorDriftAfterPreparationCannotConsumeOrReleaseItsReservation() throws Exception {
        UUID authorizedActor = run.spec().actorId();
        assertThat(writer.prepareRun(request, authorizedActor, budget()).status()).isEqualTo(Status.APPLIED);
        replaceActor(UUID.randomUUID());
        String before = AiModelDispatchFixture.fingerprint(source);

        assertThat(writer.consumeRun(redemption(), authorizedActor, budget())).isEmpty();

        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.consumed(source, request.intentId(), false)).isFalse();
        assertThat(AiModelDispatchFixture.reservedCalls(source, run.spec().runId())).isEqualTo(1);
    }

    private RunRedemption redemption() {
        return new RunRedemption(request.intentId(), expected(run), claim.binding(), model, request.payload().sha256(),
                request.expiresAt(), UUID.randomUUID());
    }

    private void replaceActor(UUID actor) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("UPDATE ai_runtime_run SET actor_uuid = ? WHERE uuid = ?")) {
            statement.setObject(1, actor);
            statement.setObject(2, run.spec().runId());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
