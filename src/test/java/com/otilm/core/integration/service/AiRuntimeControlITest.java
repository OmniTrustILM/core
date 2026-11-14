package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Synthetic database facts exercise local admission only; they do not attest deployed enforcement. */
class AiRuntimeControlITest extends BaseAiSpringBootTest {
    private static final WorkloadRef POD = new WorkloadRef("cluster-one", "pod-one");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private AiRuntimeRepository repository;
    @Autowired
    private PlatformTransactionManager transactionManager;

    @BeforeEach
    void resetRuntime() throws Exception {
        AiRuntimeFixture.install(dataSource);
    }

    @Test
    void noReadinessAuthorityCannotCreateAnyRuntimeRows() throws Exception {
        var now = AiRuntimeFixture.now(dataSource);
        var run = AiRuntimeFixture.run(now);
        var attempt = AiRuntimeFixture.attempt(now);

        ControlVersion version = new ControlVersion(1);
        assertThatThrownBy(() -> kernel.create(version, run, attempt)).isInstanceOf(AiRuntimeWriter.Rejected.class);

        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("""
                        SELECT (SELECT count(*) FROM ai_runtime_run) + (SELECT count(*) FROM ai_runtime_attempt)
                            + (SELECT count(*) FROM ai_runtime_launch) + (SELECT count(*) FROM ai_runtime_workload)
                        """)) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getLong(1)).isZero();
        }
    }

    @Test
    void configurationAndVerificationNeverAutomaticallyEnable() throws Exception {
        ControlSnapshot initial = currentControl();
        assertThat(initial.version().generation()).isEqualTo(1);
        assertThat(initial.enabled()).isFalse();
        assertThat(initial.pins()).isEmpty();
        assertThat(initial.observation()).isEmpty();

        ControlSnapshot configured = configure();
        assertThat(configured.version().generation()).isEqualTo(2);
        assertThat(configured.enabled()).isFalse();
        assertThat(configured.observation()).isEmpty();
        assertThat(kernel.enableControl(configured.version()).status()).isEqualTo(Status.DENIED);
        assertRejectedCreate(configured.version());

        ReadinessObservation evidence = evidence(configured, 1, now(), now().plusSeconds(90));
        assertThat(kernel.observeControl(evidence).status()).isEqualTo(Status.APPLIED);
        assertThat(currentControl().enabled()).isFalse();
        assertRejectedCreate(configured.version());

        assertThat(kernel.enableControl(configured.version()).status()).isEqualTo(Status.APPLIED);
        ControlSnapshot enabled = currentControl();
        assertThat(enabled.version()).isEqualTo(configured.version());
        assertThat(enabled.observation()).contains(evidence);
        assertThat(enabled.enabled()).isTrue();
        assertThat(kernel.enableControl(configured.version()).status()).isEqualTo(Status.REPLAY);
        assertThat(currentControl()).isEqualTo(enabled);

        RunSnapshot run = createCurrent();
        assertThat(run.controlGeneration()).isEqualTo(2);
        assertThat(run.attempt().controlGeneration()).isEqualTo(2);
    }

    @Test
    void observationReplayAndReorderingCannotChangeRecordedValidity() throws Exception {
        ControlSnapshot configured = configure();
        Instant at = now();
        ReadinessObservation first = evidence(configured, 2, at, at.plusSeconds(60));
        assertThat(kernel.observeControl(first).status()).isEqualTo(Status.APPLIED);
        ControlSnapshot before = currentControl();
        assertThat(kernel.observeControl(first).status()).isEqualTo(Status.REPLAY);
        assertThat(currentControl()).isEqualTo(before);
        ReadinessObservation changed = new ReadinessObservation(configured.version(), first.observedPins(), 2,
                first.evidenceId(), at, at.plusSeconds(61));
        assertThat(kernel.observeControl(changed).status()).isEqualTo(Status.CONFLICT);
        assertThat(kernel.observeControl(evidence(configured, 1, at, at.plusSeconds(60))).status())
                .isEqualTo(Status.STALE);
        assertThat(kernel.observeControl(evidence(configured, 3, at.minusSeconds(1), at.plusSeconds(60))).status())
                .isEqualTo(Status.STALE);
        assertThat(currentControl()).isEqualTo(before);

        ReadinessObservation refreshed = evidence(configured, 3, now(), at.plusSeconds(90));
        assertThat(kernel.observeControl(refreshed).status()).isEqualTo(Status.APPLIED);
        assertThat(currentControl().version()).isEqualTo(configured.version());
        assertThat(currentControl().enabled()).isFalse();
        assertThat(currentControl().observation()).contains(refreshed);
    }

    @Test
    void wrongPinsFutureAndExpiredEvidenceCannotVerify() throws Exception {
        ControlSnapshot configured = configure();
        Instant at = now();
        ControlPins wrong = new ControlPins("sha256:" + "c".repeat(64), 1, 1, 1, "v1",
                configured.pins().orElseThrow().launch());
        ReadinessObservation wrongPins = new ReadinessObservation(configured.version(), wrong, 1, UUID.randomUUID(), at,
                at.plusSeconds(60));
        assertThat(kernel.observeControl(wrongPins).status()).isEqualTo(Status.DENIED);
        assertThat(kernel.observeControl(evidence(configured, 1, at.plusSeconds(10), at.plusSeconds(60))).status())
                .isEqualTo(Status.DENIED);
        assertThat(kernel.observeControl(evidence(configured, 1, at.minusSeconds(2), at.minusSeconds(1))).status())
                .isEqualTo(Status.EXPIRED);
        assertThat(currentControl()).isEqualTo(configured);
    }

    @Test
    void expiredAuthorityNeedsNewGenerationVerificationAndExplicitEnable() throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrent();
        assertThat(kernel.observe(observation(run, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        ControlSnapshot previous = currentControl();
        expireEvidence();

        Instant at = now();
        assertThat(kernel.observeControl(evidence(previous, 2, at, at.plusSeconds(90))).status())
                .isEqualTo(Status.EXPIRED);
        assertThat(kernel.enableControl(previous.version()).status()).isEqualTo(Status.EXPIRED);
        assertRejectedCreate(previous.version());

        ControlSnapshot replacement = kernel
                .changeControl(previous.version(), previous.pins().orElseThrow())
                .value()
                .orElseThrow();
        assertThat(replacement.version().generation()).isEqualTo(previous.version().generation() + 1);
        assertThat(replacement.enabled()).isFalse();
        assertThat(replacement.observation()).isEmpty();
        assertThat(kernel.observeControl(evidence(previous, 3, at, at.plusSeconds(90))).status())
                .isEqualTo(Status.STALE);
        ReadinessObservation fresh = evidence(replacement, 1, now(), now().plusSeconds(90));
        assertThat(kernel.observeControl(fresh).status()).isEqualTo(Status.APPLIED);
        assertRejectedCreate(replacement.version());
        assertThat(kernel.enableControl(replacement.version()).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.bootstrap(expected(current(run)), POD).status()).isEqualTo(Status.STALE);
        assertThat(createCurrent().controlGeneration()).isEqualTo(replacement.version().generation());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void enabledGenerationCannotRecoverMissingEvidence(boolean directSql) throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrent();
        assertThat(kernel.observe(observation(run, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        loseControl(ControlLoss.MISSING_EVIDENCE);
        ControlSnapshot lost = currentControl();
        Instant at = now();
        ReadinessObservation restored = evidence(lost, 2, at, at.plusSeconds(90));

        if (directSql) {
            Integer affected = new TransactionTemplate(transactionManager).execute(status -> {
                repository.configureTransaction();
                return repository.observeControl(restored, at);
            });
            assertThat(affected).isZero();
        } else {
            assertEmpty(kernel.observeControl(restored), Status.DENIED);
        }

        assertThat(currentControl()).isEqualTo(lost);
        assertRejectedCreate(lost.version());
        assertEmpty(kernel.bootstrap(expected(current(run)), POD), Status.DENIED);
    }

    @ParameterizedTest
    @EnumSource(ControlLoss.class)
    void currentControlLossDeniesRegistrationAndBothClaimReplayPaths(ControlLoss loss) throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrent();
        assertThat(kernel.observe(observation(run, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        Claim claim = kernel.bootstrap(expected(current(run)), POD).value().orElseThrow();
        assertThat(kernel.heartbeat(claim.binding(), 1).status()).isEqualTo(Status.APPLIED);
        RunSnapshot before = current(run);
        ControlVersion version = currentControl().version();
        loseControl(loss);

        assertRejectedCreate(version);
        assertEmpty(kernel.observe(observation(before, POD, 2, true)), loss.status);
        assertEmpty(kernel.bootstrap(expected(before), POD), loss.status);
        assertEmpty(kernel.heartbeat(claim.binding(), 1), loss.status);
        assertEmpty(kernel.heartbeat(claim.binding(), 2), loss.status);
        assertThat(current(run)).isEqualTo(before);
    }

    @ParameterizedTest
    @CsvSource({"CANCEL,false", "CANCEL,true", "INVALIDATE,false", "INVALIDATE,true", "EXPIRE,false", "EXPIRE,true"})
    void housekeepingRemainsAvailableWithoutReadiness(String operation, boolean missing) throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrent();
        if (operation.equals("EXPIRE")) {
            execute("UPDATE ai_runtime_attempt SET launch_deadline = clock_timestamp() - interval '1 second'");
        }
        if (missing) {
            execute("DELETE FROM ai_runtime_control");
        } else {
            assertThat(kernel.disableControl(currentControl().version()).status()).isEqualTo(Status.APPLIED);
        }
        RunSnapshot before = current(run);
        Transition<Void> result = switch (operation) {
            case "CANCEL" -> kernel.cancel(run.spec().runId());
            case "INVALIDATE" -> kernel.invalidate(expected(before));
            default -> kernel.expire(expected(before));
        };

        assertThat(result.status()).isEqualTo(Status.APPLIED);
        assertThat(current(run).launch().cleanup()).isEqualTo(CleanupState.DUE);
    }

    @Test
    void claimAndRenewalCannotOutliveCurrentEvidence() throws Exception {
        ControlSnapshot configured = configure();
        Instant at = now();
        ReadinessObservation evidence = evidence(configured, 1, at, at.plusSeconds(3));
        assertThat(kernel.observeControl(evidence).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.enableControl(configured.version()).status()).isEqualTo(Status.APPLIED);
        RunSnapshot run = createCurrent();
        assertThat(kernel.observe(observation(run, POD, 1, true)).status()).isEqualTo(Status.APPLIED);

        Claim claim = kernel.bootstrap(expected(current(run)), POD).value().orElseThrow();
        assertThat(claim.leaseUntil()).isEqualTo(evidence.validUntil());
        Claim renewed = kernel.heartbeat(claim.binding(), 1).value().orElseThrow();
        assertThat(renewed.leaseUntil()).isEqualTo(evidence.validUntil());
    }

    @ParameterizedTest
    @EnumSource(StoredLeasePath.class)
    void shorterEvidenceInvalidatesStoredClaimAuthority(StoredLeasePath path) throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrentWithLongLease();
        assertThat(kernel.observe(observation(run, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        Claim initial = kernel.bootstrap(expected(current(run)), POD).value().orElseThrow();
        assertThat(kernel.bootstrap(expected(current(run)), POD).value()).contains(initial);
        Claim claim = kernel.heartbeat(initial.binding(), 1).value().orElseThrow();
        assertThat(kernel.heartbeat(claim.binding(), 1).value()).contains(claim);
        RunSnapshot before = current(run);
        assertThat(repository.admissionCurrent(expected(before))).isTrue();
        ControlSnapshot control = currentControl();
        ReadinessObservation shorter = evidence(control, 2, now(), claim.leaseUntil().minusSeconds(10));
        assertThat(kernel.observeControl(shorter).status()).isEqualTo(Status.APPLIED);
        assertThat(currentControl().usableAt(now())).isTrue();

        switch (path) {
            case WINNER_REPLAY -> assertEmpty(kernel.bootstrap(expected(before), POD), Status.EXPIRED);
            case HEARTBEAT_REPLAY -> assertEmpty(kernel.heartbeat(claim.binding(), 1), Status.EXPIRED);
            case HEARTBEAT_RENEWAL -> assertEmpty(kernel.heartbeat(claim.binding(), 2), Status.EXPIRED);
            case FINAL_SQL -> {
                assertThat(repository.admissionCurrent(expected(before))).isFalse();
                Integer affected = new TransactionTemplate(transactionManager).execute(status -> {
                    repository.configureTransaction();
                    return repository
                            .heartbeat(expected(before), claim.binding(), 2, shorter.validUntil(),
                                    repository.decisionTime());
                });
                assertThat(affected).isZero();
            }
        }

        assertThat(current(run)).isEqualTo(before);
        assertThat(currentControl().observation()).contains(shorter);
        assertThat(kernel.cancel(run.spec().runId()).status()).isEqualTo(Status.APPLIED);
        assertThat(current(run).launch().cleanup()).isEqualTo(CleanupState.DUE);
    }

    @Test
    void pendingAdmissionSurvivesShorterEvidenceWithoutAStoredLease() throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrentWithLongLease();
        assertThat(kernel.observe(observation(run, POD, 1, false)).status()).isEqualTo(Status.APPLIED);
        assertEmpty(kernel.bootstrap(expected(current(run)), POD), Status.PENDING);
        assertThat(current(run).attempt().claim()).isEmpty();
        ControlSnapshot control = currentControl();
        ReadinessObservation shorter = evidence(control, 2, now(), now().plusSeconds(20));
        assertThat(kernel.observeControl(shorter).status()).isEqualTo(Status.APPLIED);

        assertThat(repository.admissionCurrent(expected(current(run)))).isTrue();
        assertEmpty(kernel.bootstrap(expected(current(run)), POD), Status.PENDING);
        assertThat(kernel.observe(observation(current(run), POD, 2, true)).status()).isEqualTo(Status.APPLIED);
        Claim claim = kernel.bootstrap(expected(current(run)), POD).value().orElseThrow();
        assertThat(claim.leaseUntil()).isEqualTo(shorter.validUntil());
        assertThat(kernel.heartbeat(claim.binding(), 1).value().orElseThrow().leaseUntil())
                .isEqualTo(shorter.validUntil());
    }

    @Test
    void fencedHistoricalLeaseDoesNotBlockReplacementUnderShorterEvidence() throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrentWithLongLease();
        assertThat(kernel.observe(observation(run, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        Claim claim = kernel.bootstrap(expected(current(run)), POD).value().orElseThrow();
        execute("UPDATE ai_runtime_workload SET observation_valid_until = clock_timestamp() - interval '1 second'");
        assertThat(kernel.expire(expected(current(run))).status()).isEqualTo(Status.APPLIED);
        RunSnapshot fenced = current(run);
        assertThat(fenced.attempt().claim()).contains(claim);
        ControlSnapshot control = currentControl();
        ReadinessObservation shorter = evidence(control, 2, now(), claim.leaseUntil().minusSeconds(10));
        assertThat(kernel.observeControl(shorter).status()).isEqualTo(Status.APPLIED);

        assertThat(kernel.replace(expected(fenced), AiRuntimeFixture.attempt(now())).status())
                .isEqualTo(Status.APPLIED);
        assertThat(current(run).controlGeneration()).isEqualTo(fenced.controlGeneration());
        assertThat(current(run).attempt().claim()).isEmpty();
    }

    @Test
    void legacyGenerationNeverAcquiresCurrentAuthority() throws Exception {
        enableSyntheticControl();
        RunSnapshot run = createCurrent();
        assertThat(kernel.observe(observation(run, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            connection.setAutoCommit(false);
            statement.executeUpdate("UPDATE ai_runtime_run SET control_generation = 0");
            statement.executeUpdate("UPDATE ai_runtime_attempt SET control_generation = 0");
            connection.commit();
        }

        RunSnapshot legacy = current(run);
        assertThat(legacy.controlGeneration()).isZero();
        assertThat(legacy.attempt().controlGeneration()).isZero();
        assertEmpty(kernel.bootstrap(expected(legacy), POD), Status.STALE);
        assertThat(kernel.cancel(run.spec().runId()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void generationExhaustionNeverWrapsOrPreventsDisable() throws Exception {
        execute("UPDATE ai_runtime_control SET generation = 9223372036854775806");
        ControlSnapshot terminal = configure();
        assertThat(terminal.version().generation()).isEqualTo(Long.MAX_VALUE);
        Instant at = now();
        assertThat(kernel.observeControl(evidence(terminal, 1, at, at.plusSeconds(60))).status())
                .isEqualTo(Status.APPLIED);
        assertThat(kernel.enableControl(terminal.version()).status()).isEqualTo(Status.LIMIT_REACHED);
        assertThat(kernel.disableControl(terminal.version()).status()).isEqualTo(Status.APPLIED);
        assertThat(currentControl().version()).isEqualTo(terminal.version());
        assertThat(currentControl().observation()).isEmpty();
        assertThat(currentControl().enabled()).isFalse();
        assertThat(kernel.changeControl(terminal.version(), terminal.pins().orElseThrow()).status())
                .isEqualTo(Status.LIMIT_REACHED);
    }

    private ControlSnapshot configure() throws Exception {
        var attempt = AiRuntimeFixture.attempt(now());
        return kernel.changeControl(currentControl().version(), ControlPins.forAttempt(attempt)).value().orElseThrow();
    }

    private void enableSyntheticControl() throws Exception {
        ControlSnapshot configured = configure();
        Instant at = now();
        assertThat(kernel.observeControl(evidence(configured, 1, at, at.plusSeconds(90))).status())
                .isEqualTo(Status.APPLIED);
        assertThat(kernel.enableControl(configured.version()).status()).isEqualTo(Status.APPLIED);
    }

    private ReadinessObservation evidence(ControlSnapshot control, long sequence, Instant observed, Instant expiry) {
        return new ReadinessObservation(control.version(), control.pins().orElseThrow(), sequence, UUID.randomUUID(),
                observed, expiry);
    }

    private ControlSnapshot currentControl() {
        return kernel.control().orElseThrow();
    }

    private RunSnapshot createCurrent() throws Exception {
        Instant at = now();
        return kernel.create(currentControl().version(), AiRuntimeFixture.run(at), AiRuntimeFixture.attempt(at));
    }

    private RunSnapshot createCurrentWithLongLease() throws Exception {
        Instant at = now();
        RunSpec fixture = AiRuntimeFixture.run(at);
        RunSpec run = new RunSpec(fixture.runId(), fixture.conversationRef(), fixture.actorId(), fixture.scopeMarker(),
                fixture.attemptLimit(), fixture.podLimit(), 30, fixture.runDeadline());
        return kernel.create(currentControl().version(), run, AiRuntimeFixture.attempt(at));
    }

    private RunSnapshot current(RunSnapshot run) {
        return kernel.snapshot(run.spec().runId()).orElseThrow();
    }

    private void assertRejectedCreate(ControlVersion version) throws Exception {
        Instant at = now();
        var run = AiRuntimeFixture.run(at);
        var attempt = AiRuntimeFixture.attempt(at);
        assertThatThrownBy(() -> kernel.create(version, run, attempt)).isInstanceOf(AiRuntimeWriter.Rejected.class);
    }

    private static void assertEmpty(Transition<?> result, Status status) {
        assertThat(result.status()).isEqualTo(status);
        assertThat(result.value()).isEmpty();
    }

    private Instant now() throws Exception {
        return AiRuntimeFixture.now(dataSource);
    }

    private void execute(String sql) throws Exception {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate(sql);
        }
    }

    private void expireEvidence() throws Exception {
        execute("""
                UPDATE ai_runtime_control SET observed_at = clock_timestamp() - interval '2 seconds',
                    valid_until = clock_timestamp() - interval '1 second'
                """);
    }

    private void loseControl(ControlLoss loss) throws Exception {
        switch (loss) {
            case DISABLED -> kernel.disableControl(currentControl().version());
            case MISSING -> execute("DELETE FROM ai_runtime_control");
            case MISSING_EVIDENCE -> execute("""
                    UPDATE ai_runtime_control SET observation_sequence = 0, evidence_id = NULL,
                        observed_at = NULL, valid_until = NULL
                    """);
            case EXPIRED -> expireEvidence();
        }
    }

    private enum ControlLoss {
        DISABLED(Status.STALE),
        MISSING(Status.DENIED),
        MISSING_EVIDENCE(Status.DENIED),
        EXPIRED(Status.EXPIRED);

        private final Status status;

        ControlLoss(Status status) {
            this.status = status;
        }
    }

    private enum StoredLeasePath {
        WINNER_REPLAY,
        HEARTBEAT_REPLAY,
        HEARTBEAT_RENEWAL,
        FINAL_SQL
    }
}
