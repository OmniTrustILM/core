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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/** Real PG evidence integrity/policy facts only; does not grant modelUSE or authenticate a native gateway. */
class AiModelDispatchIntegrityITest extends BaseAiSpringBootTest {
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
    void fixtureFacts() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        model = AiModelDispatchFixture.approvedModel(source);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void destinationAndCredentialCannotChangeWithoutForwardRevisions(boolean credential) throws Exception {
        String before = AiModelDispatchFixture.fingerprint(source);
        assertCheck(() -> AiModelDispatchFixture.mutateWithoutRevision(source, model.id(), credential),
                "ai_model_connection_revision_guard");
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void revisionCannotRollBackAndRearmAnOldApproval() throws Exception {
        AiModelDispatchFixture.advance(source, model.id(), "configuration", false);
        String before = AiModelDispatchFixture.fingerprint(source);
        assertCheck(() -> AiModelDispatchFixture.decreaseRevision(source, model.id()),
                "ai_model_connection_revision_guard");
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void aForwardBoundValueChangeClearsEveryApprovalSnapshot(boolean credential) throws Exception {
        AiModelDispatchFixture.changeBoundValueWithRevisions(source, model.id(), credential);
        assertThat(AiModelDispatchFixture.approvalsCleared(source, model.id())).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://user:canary@provider.invalid",
            "https://provider.invalid/?api_key=canary",
            "https://provider.invalid/#canary",
            "https:///missing"})
    void secretBearingAndHostlessOriginsCannotEnterCore(String origin) throws Exception {
        String before = AiModelDispatchFixture.fingerprint(source);
        assertCheck(() -> AiModelDispatchFixture.insertOrigin(source, origin), "ai_model_connection_origin_check");
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @ParameterizedTest
    @ValueSource(strings = {"configuration", "destination", "authentication"})
    void partialApprovalRejectsTheExactDatabaseConstraint(String axis) throws Exception {
        String before = AiModelDispatchFixture.fingerprint(source);
        assertCheck(() -> AiModelDispatchFixture.clearApproval(source, model.id(), axis), "ai_model_connection_check");
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @ParameterizedTest
    @ValueSource(strings = {"configuration", "destination", "authentication"})
    void reapprovedNewRevisionCannotReviveOldIntentOrReplay(String axis) throws Exception {
        liveRun();
        RunPreparation first = prepare(model, 32, AiModelDispatchFixture.payload(32, "fixture"));
        assertThat(writer.prepareRun(first, budget()).status()).isEqualTo(Status.APPLIED);
        ConnectionVersion changed = AiModelDispatchFixture.advance(source, model.id(), axis, true);
        assertThat(AiModelDispatchFixture.approved(source, model.id())).isTrue();
        AiModelDispatchFixture.updateRunPolicy(source, created.spec().runId(), changed);
        String before = AiModelDispatchFixture.fingerprint(source);
        // Current model, approval, policy and submitted tuple agree; only the persisted intent pins remain old.
        var currentTupleForOldIntent = new RunRedemption(first.intentId(), expected(current()), claim.binding(),
                changed, first.payload().sha256(), first.expiresAt(), UUID.randomUUID());
        assertThat(writer.consumeRun(currentTupleForOldIntent, budget())).isEmpty();
        assertThat(writer.consumeRun(redeem(first), budget())).isEmpty();
        var sameKeyWithCurrentTuple = new RunPreparation(UUID.randomUUID(), first.requestKey(), expected(current()),
                claim.binding(), changed, first.payload(), first.outputTokens(), first.expiresAt());
        assertThat(writer.prepareRun(sameKeyWithCurrentTuple, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(writer.consumeRun(currentTupleForOldIntent, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        RunPreparation current = prepare(changed, 32, AiModelDispatchFixture.payload(32, "fixture"));
        assertThat(writer.prepareRun(current, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.consumeRun(redeem(current), budget())).isPresent();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":100000,\"stream\":false}",
            "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":32,\"n_predict\":100000,\"stream\":false}",
            "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":32,\"max_tokens\":32,\"stream\":false}",
            "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":32,\"n\":2,\"stream\":false}",
            "{\"model\":\"lab\",\"messages\":[{\"role\":\"user\",\"content\":\"x\"}],\"max_tokens\":32,\"stream\":true}",
            "{not-json}"})
    void exactPayloadCannotOverrideTheReservedOutputCap(String json) throws Exception {
        liveRun();
        String before = AiModelDispatchFixture.fingerprint(source);
        RunPreparation invalid = prepare(model, 32, new ExactPayload(json.getBytes(StandardCharsets.UTF_8)));
        assertThat(writer.prepareRun(invalid, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        RunPreparation valid = prepare(model, 32, AiModelDispatchFixture.payload(32, "fixture"));
        assertThat(writer.prepareRun(valid, budget()).status()).isEqualTo(Status.APPLIED);
        var resolved = writer.consumeRun(redeem(valid), budget()).orElseThrow();
        assertThat(resolved.outputTokens()).isEqualTo(32);
        assertThat(resolved.payload().bytes()).isEqualTo(valid.payload().bytes());
        assertThat(AiModelDispatchFixture.reservedTokens(source, created.spec().runId(), false)).isEqualTo(32);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void runAllowanceCannotExceedCallsOrTokens(boolean tokenLimit) throws Exception {
        liveRun();
        AiModelDispatchFixture
                .limits(source, created.spec().runId(), false, tokenLimit ? 10 : 3, tokenLimit ? 40 : 128);
        int count = tokenLimit ? 1 : 3;
        for (int i = 0; i < count; i++) {
            assertThat(writer
                    .prepareRun(prepare(model, 32, AiModelDispatchFixture.payload(32, "fixture")), budget())
                    .status()).isEqualTo(Status.APPLIED);
        }
        assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(count);
        assertThat(AiModelDispatchFixture.reservedTokens(source, created.spec().runId(), false)).isEqualTo(count * 32L);
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(
                writer.prepareRun(prepare(model, 32, AiModelDispatchFixture.payload(32, "fixture")), budget()).status())
                .isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void managementAllowanceCannotExceedCallsOrTokens(boolean tokenLimit) throws Exception {
        UUID actor = UUID.randomUUID(), session = UUID.randomUUID();
        Instant expiry = AiRuntimeFixture.now(source).plusSeconds(30);
        AiModelDispatchFixture
                .managementSession(source, actor, session, model, ManagementAction.CONNECTION_CHECK, expiry);
        AiModelDispatchFixture.limits(source, session, true, tokenLimit ? 10 : 3, tokenLimit ? 40 : 128);
        int count = tokenLimit ? 1 : 3;
        for (int i = 0; i < count; i++) {
            assertThat(writer.prepareManagement(management(actor, session, expiry), budget()).status())
                    .isEqualTo(Status.APPLIED);
        }
        assertThat(AiModelDispatchFixture.reservedTokens(source, session, true)).isEqualTo(count * 32L);
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.prepareManagement(management(actor, session, expiry), budget()).status())
                .isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.count(source, "ai_runtime_run")).isZero();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void realManagementSessionRejectsWrongActorOrAction(boolean wrongActor) throws Exception {
        UUID actor = UUID.randomUUID(), session = UUID.randomUUID();
        Instant expiry = AiRuntimeFixture.now(source).plusSeconds(30);
        AiModelDispatchFixture
                .managementSession(source, actor, session, model, ManagementAction.CONNECTION_CHECK, expiry);
        ManagementPreparation first = management(actor, session, expiry);
        assertThat(writer.prepareManagement(first, budget()).status()).isEqualTo(Status.APPLIED);
        var invalid = new ManagementRedemption(first.intentId(), wrongActor ? UUID.randomUUID() : actor, session,
                wrongActor ? ManagementAction.CONNECTION_CHECK : ManagementAction.CAPABILITY_CHECK, model,
                first.payload().sha256(), expiry, UUID.randomUUID());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeManagement(invalid, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer
                .consumeManagement(new ManagementRedemption(first.intentId(), actor, session, first.action(), model,
                        first.payload().sha256(), expiry, UUID.randomUUID()), budget()))
                .isPresent();
    }

    private void liveRun() throws Exception {
        Instant at = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, at);
        created = kernel.create(control, AiRuntimeFixture.run(at), AiRuntimeFixture.attempt(at));
        var workload = new WorkloadRef("cluster-one", UUID.randomUUID().toString());
        kernel.observe(observation(current(), workload, 1, true));
        claim = kernel.bootstrap(expected(current()), workload).value().orElseThrow();
        AiModelDispatchFixture.runBudget(source, created.spec().runId(), model, 3, 128);
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private RunPreparation prepare(ConnectionVersion connection, int tokens, ExactPayload payload) throws Exception {
        return new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(),
                connection, payload, tokens, AiRuntimeFixture.now(source).plusSeconds(30));
    }

    private RunRedemption redeem(RunPreparation preparation) {
        return new RunRedemption(preparation.intentId(), expected(current()), claim.binding(), preparation.connection(),
                preparation.payload().sha256(), preparation.expiresAt(), UUID.randomUUID());
    }

    private ManagementPreparation management(UUID actor, UUID session, Instant expiry) {
        return new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), actor, session,
                ManagementAction.CONNECTION_CHECK, model, AiModelDispatchFixture.payload(32, "fixture"), 32, expiry);
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }

    private static void assertCheck(org.assertj.core.api.ThrowableAssert.ThrowingCallable operation,
            String constraint) {
        Throwable failure = catchThrowable(operation);
        assertThat(failure).isInstanceOf(PSQLException.class);
        PSQLException sql = (PSQLException) failure;
        assertThat(sql.getSQLState()).isEqualTo("23514");
        assertThat(sql.getServerErrorMessage()).isNotNull();
        assertThat(sql.getServerErrorMessage().getConstraint()).isEqualTo(constraint);
    }
}
