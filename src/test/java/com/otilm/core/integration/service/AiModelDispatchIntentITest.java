package com.otilm.core.integration.service;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelDispatchState.ExactPayload;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
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
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

/** Real persistence/kernel component proof. Fixture config/session facts are not modelUSE or native gateway grants. */
class AiModelDispatchIntentITest extends BaseAiSpringBootTest {
    private static final WorkloadRef WORKLOAD = new WorkloadRef("cluster-one", UUID.randomUUID().toString());
    private static final ExactPayload PAYLOAD = AiModelDispatchFixture.payload(32, "fixture");
    @Autowired
    private DataSource source;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiModelDispatchWriter writer;
    private ConnectionVersion model;
    private RunSnapshot created;
    private Claim claim;

    @BeforeEach
    void prepareRealDatabaseFacts() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        model = AiModelDispatchFixture.approvedModel(source);
    }

    @Test
    void partialApprovalSnapshotCannotPersist() throws Exception {
        String before = AiModelDispatchFixture.fingerprint(source);
        Throwable failure = org.assertj.core.api.Assertions
                .catchThrowable(() -> AiModelDispatchFixture.clearOnlyDestinationApproval(source, model.id()));
        assertThat(failure).isInstanceOf(org.postgresql.util.PSQLException.class);
        var sql = (org.postgresql.util.PSQLException) failure;
        assertThat(sql.getSQLState()).isEqualTo("23514");
        assertThat(sql.getServerErrorMessage().getConstraint()).isEqualTo("ai_model_connection_check");
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.approved(source, model.id())).isTrue();
    }

    @Test
    void exactRunIntentConsumesOnceAndDoesNotOfferSendAuthorityOnReplay() throws Exception {
        createRun();
        RunPreparation preparation = prepare(UUID.randomUUID(), UUID.randomUUID(), PAYLOAD);
        assertThat(writer.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        RunRedemption redemption = redeem(preparation, PAYLOAD.sha256());
        var consumed = writer.consumeRun(redemption, budget()).orElseThrow();
        assertThat(consumed.payload().bytes()).containsExactly(PAYLOAD.bytes());
        assertThat(consumed.outputTokens()).isEqualTo(32);
        assertThat(consumed.gatewayCorrelation()).isEqualTo(redemption.gatewayCorrelation());
        assertThat(writer.consumeRun(redemption, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.count(source, "ai_model_run_intent")).isEqualTo(1);
        assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), false)).isTrue();
        assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(1);
    }

    @Test
    void prepareIdempotencyRechecksExactBodyAndReservesOnlyOnce() throws Exception {
        createRun();
        UUID key = UUID.randomUUID();
        RunPreparation first = prepare(UUID.randomUUID(), key, PAYLOAD);
        assertThat(writer.prepareRun(first, budget()).status()).isEqualTo(Status.APPLIED);
        var replay = writer.prepareRun(repeat(first, PAYLOAD), budget());
        assertThat(replay.status()).isEqualTo(Status.REPLAY);
        assertThat(replay.value()).contains(first.intentId());
        String before = AiModelDispatchFixture.fingerprint(source);
        var changed = writer.prepareRun(repeat(first, AiModelDispatchFixture.payload(32, "changed")), budget());
        assertThat(changed.status()).isEqualTo(Status.CONFLICT);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(1);
    }

    @Test
    void alteredDigestDeniesBeforeConsumeAndOriginalStillWorks() throws Exception {
        createRun();
        RunPreparation preparation = prepare(UUID.randomUUID(), UUID.randomUUID(), PAYLOAD);
        assertThat(writer.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeRun(redeem(preparation, "0".repeat(64)), budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.consumeRun(redeem(preparation, PAYLOAD.sha256()), budget())).isPresent();
    }

    @Test
    void configurationChangeRevokesPreparedAuthorityWithoutRetainingApproval() throws Exception {
        createRun();
        RunPreparation preparation = prepare(UUID.randomUUID(), UUID.randomUUID(), PAYLOAD);
        assertThat(writer.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        AiModelDispatchFixture.reviseConnection(source, model.id());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeRun(redeem(preparation, PAYLOAD.sha256()), budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.approved(source, model.id())).isFalse();
    }

    @Test
    void cancellationAfterPreparePreventsConsumeWithoutErasingReservedAllowance() throws Exception {
        createRun();
        RunPreparation preparation = prepare(UUID.randomUUID(), UUID.randomUUID(), PAYLOAD);
        assertThat(writer.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        RunRedemption original = redeem(preparation, PAYLOAD.sha256());
        assertThat(kernel.cancel(created.spec().runId()).status()).isEqualTo(Status.APPLIED);
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeRun(original, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(1);
    }

    @Test
    void managementHasItsOwnActorSessionActionAndNeverCreatesARun() throws Exception {
        UUID actor = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        Instant expiry = AiRuntimeFixture.now(source).plusSeconds(30);
        AiModelDispatchFixture
                .managementSession(source, actor, session, model, ManagementAction.CONNECTION_CHECK, expiry);
        var preparation = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), actor, session,
                ManagementAction.CONNECTION_CHECK, model, PAYLOAD, 32, expiry);
        assertThat(writer.prepareManagement(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        var correct = new ManagementRedemption(preparation.intentId(), actor, session, preparation.action(), model,
                PAYLOAD.sha256(), expiry, UUID.randomUUID());
        UUID secondSession = UUID.randomUUID();
        AiModelDispatchFixture
                .managementSession(source, actor, secondSession, model, ManagementAction.CONNECTION_CHECK, expiry);
        var foreignSession = new ManagementRedemption(preparation.intentId(), actor, secondSession,
                preparation.action(), model, PAYLOAD.sha256(), expiry, UUID.randomUUID());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeManagement(foreignSession, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.consumeManagement(correct, budget())).isPresent();
        assertThat(writer.consumeManagement(correct, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.count(source, "ai_runtime_run")).isZero();
        assertThat(AiModelDispatchFixture.count(source, "ai_model_run_intent")).isZero();
        assertThat(AiModelDispatchFixture.consumed(source, preparation.intentId(), true)).isTrue();
    }

    @Test
    void runIntentCannotBeConsumedAsManagementEvenWithCopiedDigest() throws Exception {
        createRun();
        RunPreparation preparation = prepare(UUID.randomUUID(), UUID.randomUUID(), PAYLOAD);
        assertThat(writer.prepareRun(preparation, budget()).status()).isEqualTo(Status.APPLIED);
        UUID actor = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        AiModelDispatchFixture
                .managementSession(source, actor, session, model, ManagementAction.CAPABILITY_CHECK,
                        preparation.expiresAt());
        var substituted = new ManagementRedemption(preparation.intentId(), actor, session,
                ManagementAction.CAPABILITY_CHECK, model, PAYLOAD.sha256(), preparation.expiresAt(), UUID.randomUUID());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeManagement(substituted, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.consumeRun(redeem(preparation, PAYLOAD.sha256()), budget())).isPresent();
    }

    @Test
    void runCannotChooseAnotherApprovedModelOrDefaultAroundItsPinnedPolicy() throws Exception {
        createRun();
        ConnectionVersion foreign = AiModelDispatchFixture.approvedModel(source);
        var wrong = new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(),
                foreign, PAYLOAD, 32, AiRuntimeFixture.now(source).plusSeconds(30));
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.prepareRun(wrong, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.prepareRun(prepare(UUID.randomUUID(), UUID.randomUUID(), PAYLOAD), budget()).status())
                .isEqualTo(Status.APPLIED);
    }

    private void createRun() throws Exception {
        Instant now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        kernel.observe(observation(current(), WORKLOAD, 1, true));
        claim = kernel.bootstrap(expected(current()), WORKLOAD).value().orElseThrow();
        AiModelDispatchFixture.runBudget(source, created.spec().runId(), model, 3, 128);
    }

    private RunPreparation prepare(UUID intent, UUID key, ExactPayload payload) throws Exception {
        return new RunPreparation(intent, key, expected(current()), claim.binding(), model, payload, 32,
                AiRuntimeFixture.now(source).plusSeconds(30));
    }

    private static RunPreparation repeat(RunPreparation first, ExactPayload payload) {
        return new RunPreparation(UUID.randomUUID(), first.requestKey(), first.expected(), first.claim(),
                first.connection(), payload, first.outputTokens(), first.expiresAt());
    }

    private RunRedemption redeem(RunPreparation preparation, String digest) {
        return new RunRedemption(preparation.intentId(), expected(current()), claim.binding(), model, digest,
                preparation.expiresAt(), UUID.randomUUID());
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
