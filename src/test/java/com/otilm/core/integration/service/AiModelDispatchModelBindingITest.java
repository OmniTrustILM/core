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
import java.sql.Connection;
import java.time.Instant;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.assertAll;

/** Real persistence facts only; no actor modelUSE/native gateway/provider grant. */
class AiModelDispatchModelBindingITest extends BaseAiSpringBootTest {
    private static final WorkloadRef WORKLOAD = new WorkloadRef("cluster-one", UUID.randomUUID().toString());
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
    void seedActualCanonicalDefinition() throws Exception {
        AiModelDispatchFixture.drop(source);
        AiRuntimeFixture.install(source);
        AiModelDispatchFixture.install(source);
        model = AiModelDispatchFixture.approvedModel(source);
        assertThat(canonicalIdentifier()).isEqualTo("lab");
    }

    @Test
    void exactCanonicalRunModelPreparesAndConsumesOnce() throws Exception {
        createRun();
        var request = run(payload("lab"));
        assertThat(writer.prepareRun(request, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.consumeRun(redeem(request), budget())).isPresent();
        assertThat(writer.consumeRun(redeem(request), budget())).isEmpty();
        assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(1);
    }

    @Test
    void anotherRunModelCannotReserveAgainstTheApprovedCanonicalDefinition() throws Exception {
        createRun();
        var request = run(payload("other-provider-model"));
        String before = AiModelDispatchFixture.fingerprint(source);
        Status result = writer.prepareRun(request, budget()).status();
        String after = AiModelDispatchFixture.fingerprint(source);
        assertAll(() -> assertThat(result).isEqualTo(Status.DENIED), () -> assertThat(after).isEqualTo(before));
    }

    @Test
    void exactCanonicalManagementModelPreparesAndConsumesOnce() throws Exception {
        var request = management(payload("lab"));
        assertThat(writer.prepareManagement(request, budget()).status()).isEqualTo(Status.APPLIED);
        var redemption = new ManagementRedemption(request.intentId(), request.actorId(), request.sessionId(),
                request.action(), request.connection(), request.payload().sha256(), request.expiresAt(),
                UUID.randomUUID());
        assertThat(writer.consumeManagement(redemption, budget())).isPresent();
        assertThat(writer.consumeManagement(redemption, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.count(source, "ai_runtime_run")).isZero();
    }

    @Test
    void anotherManagementModelCannotReserveAgainstTheApprovedCanonicalDefinition() throws Exception {
        var request = management(payload("other-provider-model"));
        String before = AiModelDispatchFixture.fingerprint(source);
        Status result = writer.prepareManagement(request, budget()).status();
        String after = AiModelDispatchFixture.fingerprint(source);
        assertAll(() -> assertThat(result).isEqualTo(Status.DENIED), () -> assertThat(after).isEqualTo(before));
    }

    @Test
    void modelRenameWithoutConfigurationRevisionIsRejectedByTheRealDatabase() throws Exception {
        String before = AiModelDispatchFixture.fingerprint(source);
        Throwable failure = catchThrowable(this::renameWithoutRevision);
        assertThat(failure).isInstanceOf(PSQLException.class);
        var sql = (PSQLException) failure;
        assertThat(sql.getSQLState()).isEqualTo("23514");
        assertThat(sql.getServerErrorMessage().getConstraint()).isEqualTo("ai_model_connection_revision_guard");
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void jdbcReplacementMustNotMakeMalformedJavaIdentifierAnAcceptedPin() throws Exception {
        String malformed = "\uD800";
        String before = AiModelDispatchFixture.fingerprint(source);
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("SELECT encode(convert_to(CAST(? AS TEXT),'UTF8'),'hex')")) {
            statement.setString(1, malformed);
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getString(1)).isEqualTo("3f");
            }
        }
        UUID connectionId = model.id();
        long configuration = model.configuration();
        long destination = model.destination();
        long authentication = model.authentication();
        Throwable failure = catchThrowable(
                () -> new ConnectionVersion(connectionId, configuration, destination, authentication, malformed));
        assertThat(failure).isInstanceOf(IllegalArgumentException.class);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void postgresRejectsNulBeforeItCanBecomeACanonicalTextPin() throws Exception {
        String identifier = "lab" + (char) 0;
        String before = AiModelDispatchFixture.fingerprint(source);
        try (var connection = source.getConnection();
                var statement = connection.prepareStatement("SELECT CAST(? AS VARCHAR(255))")) {
            statement.setString(1, identifier);
            Throwable failure = catchThrowable(statement::executeQuery);
            assertThat(failure).isInstanceOf(PSQLException.class);
            assertThat(((PSQLException) failure).getSQLState()).isEqualTo("22021");
        }
        UUID connectionId = model.id();
        Throwable failure = catchThrowable(() -> new ConnectionVersion(connectionId, 1, 2, 3, identifier));
        assertThat(failure).isInstanceOf(IllegalArgumentException.class);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
    }

    @Test
    void forgedRunIdentifierPinCannotChooseAnotherModelOnTheSameConnection() throws Exception {
        createRun();
        var forged = new ConnectionVersion(model.id(), model.configuration(), model.destination(),
                model.authentication(), "other-provider-model");
        var request = run(forged, payload("other-provider-model"));
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.prepareRun(request, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.prepareRun(run(payload("lab")), budget()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void forgedManagementIdentifierPinCannotChooseAnotherModelOnTheSameConnection() throws Exception {
        var correct = management(payload("lab"));
        var forged = new ConnectionVersion(model.id(), model.configuration(), model.destination(),
                model.authentication(), "other-provider-model");
        var request = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), correct.actorId(),
                correct.sessionId(), correct.action(), forged, payload("other-provider-model"), 32,
                correct.expiresAt());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.prepareManagement(request, budget()).status()).isEqualTo(Status.DENIED);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(writer.prepareManagement(correct, budget()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void storedRunIdentifierWitnessCannotBeSubstitutedWithOtherwiseCurrentFacts() throws Exception {
        createRun();
        var first = run(payload("lab"));
        assertThat(writer.prepareRun(first, budget()).status()).isEqualTo(Status.APPLIED);
        changeIntentIdentifier(first.intentId(), false, "other-provider-model");
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeRun(redeem(first), budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        changeIntentIdentifier(first.intentId(), false, "lab");
        assertThat(writer.consumeRun(redeem(first), budget())).isPresent();
    }

    @Test
    void storedManagementIdentifierWitnessCannotBeSubstitutedWithOtherwiseCurrentFacts() throws Exception {
        var first = management(payload("lab"));
        assertThat(writer.prepareManagement(first, budget()).status()).isEqualTo(Status.APPLIED);
        changeIntentIdentifier(first.intentId(), true, "other-provider-model");
        var redemption = managementRedemption(first, model, first.payload().sha256());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeManagement(redemption, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        changeIntentIdentifier(first.intentId(), true, "lab");
        assertThat(writer.consumeManagement(redemption, budget())).isPresent();
    }

    @Test
    void storedRunPayloadWithMatchingDigestStillCannotSelectAnotherModelAndConsumeRollsBack() throws Exception {
        createRun();
        var first = run(payload("lab"));
        assertThat(writer.prepareRun(first, budget()).status()).isEqualTo(Status.APPLIED);
        var changed = payload("other-provider-model");
        changeIntentPayload(first.intentId(), false, changed);
        var request = runRedemption(first, model, changed.sha256());
        try (var observer = source.getConnection()) {
            assertThat(observer.getAutoCommit()).isTrue();
            int pid = backendPid(observer);
            String before = AiModelDispatchFixture.fingerprint(observer);
            var operation = budget();
            Throwable failure = catchThrowable(() -> writer.consumeRun(request, operation));
            assertThat(failure).isInstanceOf(IllegalArgumentException.class);
            assertThat(AiModelDispatchFixture.fingerprint(observer)).isEqualTo(before);
            assertThat(backendPid(observer)).isEqualTo(pid);
            System.out.println("MODEL_RUN_ROLLBACK_OBSERVER_PID=" + pid);
        }
        assertThat(AiModelDispatchFixture.consumed(source, first.intentId(), false)).isFalse();
        assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(1);
        changeIntentPayload(first.intentId(), false, first.payload());
        assertThat(writer.consumeRun(redeem(first), budget())).isPresent();
    }

    @Test
    void storedManagementPayloadWithMatchingDigestStillCannotSelectAnotherModelAndConsumeRollsBack() throws Exception {
        var first = management(payload("lab"));
        assertThat(writer.prepareManagement(first, budget()).status()).isEqualTo(Status.APPLIED);
        var changed = payload("other-provider-model");
        changeIntentPayload(first.intentId(), true, changed);
        var request = managementRedemption(first, model, changed.sha256());
        try (var observer = source.getConnection()) {
            assertThat(observer.getAutoCommit()).isTrue();
            int pid = backendPid(observer);
            String before = AiModelDispatchFixture.fingerprint(observer);
            var operation = budget();
            Throwable failure = catchThrowable(() -> writer.consumeManagement(request, operation));
            assertThat(failure).isInstanceOf(IllegalArgumentException.class);
            assertThat(AiModelDispatchFixture.fingerprint(observer)).isEqualTo(before);
            assertThat(backendPid(observer)).isEqualTo(pid);
            System.out.println("MODEL_MANAGEMENT_ROLLBACK_OBSERVER_PID=" + pid);
        }
        assertThat(AiModelDispatchFixture.consumed(source, first.intentId(), true)).isFalse();
        changeIntentPayload(first.intentId(), true, first.payload());
        assertThat(writer.consumeManagement(managementRedemption(first, model, first.payload().sha256()), budget()))
                .isPresent();
    }

    @Test
    void renamedAndReapprovedRunDefinitionCannotReviveOldIntentEvenAfterPolicyAndNameRoundTrip() throws Exception {
        createRun();
        var first = run(payload("lab"));
        assertThat(writer.prepareRun(first, budget()).status()).isEqualTo(Status.APPLIED);
        var changed = renameModel("renamed");
        assertThat(AiModelDispatchFixture.approvalsCleared(source, model.id())).isTrue();
        reapproveModel();
        AiModelDispatchFixture.updateRunPolicy(source, created.spec().runId(), changed);
        var stale = runRedemption(first, changed, first.payload().sha256());
        var replay = new RunPreparation(UUID.randomUUID(), first.requestKey(), first.expected(), first.claim(), changed,
                payload("renamed"), 32, first.expiresAt());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeRun(stale, budget())).isEmpty();
        assertThat(writer.consumeRun(redeem(first), budget())).isEmpty();
        assertThat(writer.prepareRun(replay, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        var fresh = run(changed, payload("renamed"));
        assertThat(writer.prepareRun(fresh, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(writer.consumeRun(runRedemption(fresh, changed, fresh.payload().sha256()), budget())).isPresent();
        assertThat(writer.consumeRun(runRedemption(fresh, changed, fresh.payload().sha256()), budget())).isEmpty();
        var consumedReplay = new RunPreparation(UUID.randomUUID(), fresh.requestKey(), fresh.expected(), fresh.claim(),
                changed, fresh.payload(), fresh.outputTokens(), fresh.expiresAt());
        String consumedBefore = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.prepareRun(consumedReplay, budget()).status()).isEqualTo(Status.REPLAY);
        assertThat(writer.consumeRun(runRedemption(fresh, changed, fresh.payload().sha256()), budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(consumedBefore);
        var returned = renameModel("lab");
        reapproveModel();
        AiModelDispatchFixture.updateRunPolicy(source, created.spec().runId(), returned);
        before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeRun(runRedemption(first, returned, first.payload().sha256()), budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        assertThat(AiModelDispatchFixture.reservedCalls(source, created.spec().runId())).isEqualTo(2);
    }

    @Test
    void renamedAndReapprovedManagementDefinitionCannotReviveOldIntentWithCurrentSession() throws Exception {
        var first = management(payload("lab"));
        assertThat(writer.prepareManagement(first, budget()).status()).isEqualTo(Status.APPLIED);
        var changed = renameModel("renamed");
        assertThat(AiModelDispatchFixture.approvalsCleared(source, model.id())).isTrue();
        reapproveModel();
        updateManagementPolicy(first.sessionId(), changed);
        var stale = managementRedemption(first, changed, first.payload().sha256());
        var replay = new ManagementPreparation(UUID.randomUUID(), first.requestKey(), first.actorId(),
                first.sessionId(), first.action(), changed, payload("renamed"), 32, first.expiresAt());
        String before = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.consumeManagement(stale, budget())).isEmpty();
        assertThat(writer.consumeManagement(managementRedemption(first, model, first.payload().sha256()), budget()))
                .isEmpty();
        assertThat(writer.prepareManagement(replay, budget()).status()).isEqualTo(Status.CONFLICT);
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(before);
        var fresh = new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), first.actorId(), first.sessionId(),
                first.action(), changed, payload("renamed"), 32, first.expiresAt());
        assertThat(writer.prepareManagement(fresh, budget()).status()).isEqualTo(Status.APPLIED);
        var redemption = managementRedemption(fresh, changed, fresh.payload().sha256());
        assertThat(writer.consumeManagement(redemption, budget())).isPresent();
        assertThat(writer.consumeManagement(redemption, budget())).isEmpty();
        var consumedReplay = new ManagementPreparation(UUID.randomUUID(), fresh.requestKey(), fresh.actorId(),
                fresh.sessionId(), fresh.action(), changed, fresh.payload(), fresh.outputTokens(), fresh.expiresAt());
        String consumedBefore = AiModelDispatchFixture.fingerprint(source);
        assertThat(writer.prepareManagement(consumedReplay, budget()).status()).isEqualTo(Status.REPLAY);
        assertThat(writer.consumeManagement(redemption, budget())).isEmpty();
        assertThat(AiModelDispatchFixture.fingerprint(source)).isEqualTo(consumedBefore);
        assertThat(AiModelDispatchFixture.count(source, "ai_runtime_run")).isZero();
    }

    @Test
    void supplementaryUnicodeDefinitionUsesTheSame255CharacterDatabaseBound() throws Exception {
        String name = "\uD83D\uDE00".repeat(255);
        var changed = renameModel(name);
        reapproveModel();
        assertThat(changed.modelIdentifier()).isEqualTo(name);
        assertThat(canonicalIdentifier()).isEqualTo(name);
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "SELECT char_length(model_identifier),octet_length(model_identifier) FROM ai_model_connection WHERE uuid=?")) {
            statement.setObject(1, model.id());
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getInt(1)).isEqualTo(255);
                assertThat(rows.getInt(2)).isEqualTo(1020);
            }
        }
        var first = management(payload(name));
        updateManagementPolicy(first.sessionId(), changed);
        var request = new ManagementPreparation(first.intentId(), first.requestKey(), first.actorId(),
                first.sessionId(), first.action(), changed, first.payload(), 32, first.expiresAt());
        assertThat(writer.prepareManagement(request, budget()).status()).isEqualTo(Status.APPLIED);
        assertThat(
                writer.consumeManagement(managementRedemption(request, changed, request.payload().sha256()), budget()))
                .isPresent();
    }

    private RunPreparation run(ConnectionVersion selected, ExactPayload payload) throws Exception {
        return new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(), selected,
                payload, 32, AiRuntimeFixture.now(source).plusSeconds(30));
    }

    private RunRedemption runRedemption(RunPreparation first, ConnectionVersion selected, String digest) {
        return new RunRedemption(first.intentId(), expected(current()), claim.binding(), selected, digest,
                first.expiresAt(), UUID.randomUUID());
    }

    private static ManagementRedemption managementRedemption(ManagementPreparation first, ConnectionVersion selected,
            String digest) {
        return new ManagementRedemption(first.intentId(), first.actorId(), first.sessionId(), first.action(), selected,
                digest, first.expiresAt(), UUID.randomUUID());
    }

    private void changeIntentIdentifier(UUID id, boolean management, String identifier) throws Exception {
        String table = management ? "ai_model_management_intent" : "ai_model_run_intent";
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("UPDATE " + table + " SET model_identifier=? WHERE uuid=?")) {
            statement.setString(1, identifier);
            statement.setObject(2, id);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private void changeIntentPayload(UUID id, boolean management, ExactPayload payload) throws Exception {
        String table = management ? "ai_model_management_intent" : "ai_model_run_intent";
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("UPDATE " + table + " SET payload=?,payload_sha256=? WHERE uuid=?")) {
            statement.setBytes(1, payload.bytes());
            statement.setString(2, payload.sha256());
            statement.setObject(3, id);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private ConnectionVersion renameModel(String name) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "UPDATE ai_model_connection SET model_identifier=?,revision=revision+1 WHERE uuid=?")) {
            statement.setString(1, name);
            statement.setObject(2, model.id());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "SELECT revision,destination_revision,authentication_revision,model_identifier FROM ai_model_connection WHERE uuid=?")) {
            statement.setObject(1, model.id());
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return new ConnectionVersion(model.id(), rows.getLong(1), rows.getLong(2), rows.getLong(3),
                        rows.getString(4));
            }
        }
    }

    private void reapproveModel() throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "UPDATE ai_model_connection SET approved_revision=revision,approved_destination_revision=destination_revision,approved_authentication_revision=authentication_revision WHERE uuid=?")) {
            statement.setObject(1, model.id());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        assertThat(AiModelDispatchFixture.approved(source, model.id())).isTrue();
    }

    private void updateManagementPolicy(UUID session, ConnectionVersion selected) throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement(
                                "UPDATE ai_model_management_session SET configuration_revision=?,destination_revision=?,authentication_revision=? WHERE session_uuid=?")) {
            statement.setLong(1, selected.configuration());
            statement.setLong(2, selected.destination());
            statement.setLong(3, selected.authentication());
            statement.setObject(4, session);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private static int backendPid(Connection connection) throws Exception {
        try (var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT pg_backend_pid()")) {
            assertThat(rows.next()).isTrue();
            return rows.getInt(1);
        }
    }

    private void renameWithoutRevision() throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("UPDATE ai_model_connection SET model_identifier='renamed' WHERE uuid=?")) {
            statement.setObject(1, model.id());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private String canonicalIdentifier() throws Exception {
        try (var connection = source.getConnection();
                var statement = connection
                        .prepareStatement("SELECT model_identifier FROM ai_model_connection WHERE uuid=?")) {
            statement.setObject(1, model.id());
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return rows.getString(1);
            }
        }
    }

    private void createRun() throws Exception {
        Instant now = AiRuntimeFixture.now(source);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
        kernel.observe(observation(current(), WORKLOAD, 1, true));
        claim = kernel.bootstrap(expected(current()), WORKLOAD).value().orElseThrow();
        AiModelDispatchFixture.runBudget(source, created.spec().runId(), model, 3, 128);
    }

    private RunPreparation run(ExactPayload payload) throws Exception {
        return new RunPreparation(UUID.randomUUID(), UUID.randomUUID(), expected(current()), claim.binding(), model,
                payload, 32, AiRuntimeFixture.now(source).plusSeconds(30));
    }

    private RunRedemption redeem(RunPreparation request) {
        return new RunRedemption(request.intentId(), expected(current()), claim.binding(), model,
                request.payload().sha256(), request.expiresAt(), UUID.randomUUID());
    }

    private ManagementPreparation management(ExactPayload payload) throws Exception {
        UUID actor = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        Instant expires = AiRuntimeFixture.now(source).plusSeconds(30);
        AiModelDispatchFixture
                .managementSession(source, actor, session, model, ManagementAction.CONNECTION_CHECK, expires);
        return new ManagementPreparation(UUID.randomUUID(), UUID.randomUUID(), actor, session,
                ManagementAction.CONNECTION_CHECK, model, payload, 32, expires);
    }

    private static ExactPayload payload(String name) {
        return new ExactPayload(("{\"model\":\"" + name
                + "\",\"messages\":[{\"role\":\"user\",\"content\":\"fixture\"}],\"max_tokens\":32,\"stream\":false}")
                .getBytes(StandardCharsets.UTF_8));
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private static AiRuntimeOperationBudget budget() {
        return AiRuntimeOperationBudget.start();
    }
}
