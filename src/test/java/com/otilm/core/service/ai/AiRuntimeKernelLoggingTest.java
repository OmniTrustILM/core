package com.otilm.core.service.ai;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.ReadinessObservation;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.transaction.CannotCreateTransactionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AiRuntimeKernelLoggingTest {
    private static final UUID RUN = UUID.fromString("190e2773-efc1-41fe-a849-ff728fe4387e");
    private static final UUID ACTOR = UUID.fromString("38d94e35-ef38-415f-bae9-5a2ee6333489");
    private static final UUID CLAIM = UUID.fromString("dcaa3302-d0c3-423e-9f8a-09a1ba534b32");
    private static final String CONTENT = "synthetic-ai-content-forbidden-in-operational-log";
    private static final Instant NOW = Instant.parse("2026-11-04T12:00:00Z");
    private final AiRuntimeRepository repository = mock(AiRuntimeRepository.class);
    private final AiRuntimeWriter writer = mock(AiRuntimeWriter.class);
    private final AiRuntimeKernel kernel = new AiRuntimeKernel(repository, writer, new AiFeatureGate(true));
    private final Logger logger = (Logger) LoggerFactory.getLogger(AiRuntimeKernel.class);
    private final ListAppender<ILoggingEvent> events = new ListAppender<>();
    private final RunSpec run = new RunSpec(RUN, Optional.empty(), ACTOR, CONTENT, 2, 2, 5, NOW.plusSeconds(120));
    private final AttemptSpec attempt = AiRuntimeFixture.attempt(NOW);
    private final ControlVersion control = new ControlVersion(2);
    private final Expected expected = new Expected(RUN, attempt.attemptId(), 1, 1);
    private final WorkloadRef workload = new WorkloadRef("cluster-one", "pod-one");
    private final ClaimBinding binding = new ClaimBinding(RUN, attempt.attemptId(), workload, CLAIM, 1);
    private Level previousLevel;
    private boolean previousAdditive;

    @BeforeEach
    void capture() {
        previousLevel = logger.getLevel();
        previousAdditive = logger.isAdditive();
        logger.setLevel(Level.DEBUG);
        logger.setAdditive(false);
        events.start();
        logger.addAppender(events);
    }

    @AfterEach
    void restore() {
        logger.detachAppender(events);
        events.stop();
        logger.setLevel(previousLevel);
        logger.setAdditive(previousAdditive);
    }

    @ParameterizedTest
    @EnumSource(Status.class)
    void bootstrapLogsOnlyCurrentDecisionAndRun(Status status) {
        Transition<Claim> decision = Transition.empty(status);
        when(writer.bootstrap(expected, workload)).thenReturn(decision);

        assertThat(kernel.bootstrap(expected, workload)).isSameAs(decision);

        assertDecision("BOOTSTRAP", status.name());
    }

    @Test
    void heartbeatReturnsClaimWithoutLoggingClaimIdentity() {
        Transition<Claim> decision = Transition.value(Status.APPLIED, new Claim(binding, NOW.plusSeconds(5), 1));
        when(writer.heartbeat(binding, 1)).thenReturn(decision);

        assertThat(kernel.heartbeat(binding, 1)).isSameAs(decision);

        assertDecision("HEARTBEAT", "APPLIED");
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void missingBindingWithNonpositiveHeartbeatStillDenied(long sequence) {
        AiRuntimeKernel realWriterKernel = new AiRuntimeKernel(repository, new AiRuntimeWriter(repository),
                new AiFeatureGate(true));

        Transition<Claim> result = assertDoesNotThrow(() -> realWriterKernel.heartbeat(null, sequence));

        assertThat(result).isEqualTo(Transition.empty(Status.DENIED));
        assertThat(events.list).hasSize(1);
        ILoggingEvent event = events.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
        assertThat(event.getFormattedMessage()).isEqualTo("AI runtime operation=HEARTBEAT status=DENIED run=null");
        assertThat(event.getThrowableProxy()).isNull();
        assertThat(event.getArgumentArray()).containsExactly("HEARTBEAT", "DENIED", null);
        verifyNoInteractions(repository);
    }

    @Test
    void logsOnlyFixedDenialMetadata_whenFeatureIsDisabled() {
        // given
        var disabled = new AiRuntimeKernel(repository, writer, new AiFeatureGate(false));
        var sensitiveWorkload = new WorkloadRef("cluster-one", CONTENT);
        var observation = AiRuntimeFixture.observation(snapshot(), sensitiveWorkload, 1, true);

        // when
        Transition<Void> result = disabled.observe(observation);

        // then
        assertThat(result.status()).isEqualTo(Status.DENIED);
        assertThat(events.list).hasSize(1);
        ILoggingEvent event = events.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
        assertThat(event.getFormattedMessage()).isEqualTo("AI runtime operation=OBSERVE status=DENIED run=null");
        assertThat(event.getArgumentArray()).containsExactly("OBSERVE", "DENIED", null);
        assertThat(event.getFormattedMessage()).doesNotContain(CONTENT, RUN.toString());
        assertThat(event.getThrowableProxy()).isNull();
        verifyNoInteractions(repository, writer);
    }

    @Test
    void createLogsDecisionWithoutSerializingScopeOrActor() {
        RunSnapshot snapshot = snapshot();
        when(writer.create(control, run, attempt)).thenReturn(snapshot);

        assertThat(kernel.create(control, run, attempt)).isSameAs(snapshot);

        assertDecision("CREATE", "APPLIED");
    }

    @Test
    void snapshotLogsPresentDecisionWithoutSerializingSnapshot() {
        Optional<RunSnapshot> result = Optional.of(snapshot());
        when(repository.snapshot(RUN)).thenReturn(result);

        assertThat(kernel.snapshot(RUN)).isSameAs(result);

        assertDecision("SNAPSHOT", "PRESENT");
    }

    @Test
    void absentSnapshotKeepsEmptyOutcomeAndDebugLevel() {
        when(repository.snapshot(RUN)).thenReturn(Optional.empty());

        assertThat(kernel.snapshot(RUN)).isEmpty();

        assertDecision("SNAPSHOT", "ABSENT");
    }

    @Test
    void observationLogsDecisionWithoutObservationData() {
        var observation = AiRuntimeFixture.observation(snapshot(), workload, 1, true);
        Transition<Void> decision = Transition.empty(Status.APPLIED);
        when(writer.observe(observation)).thenReturn(decision);

        assertThat(kernel.observe(observation)).isSameAs(decision);

        assertDecision("OBSERVE", "APPLIED");
    }

    @Test
    void cancellationLogsDecision() {
        Transition<Void> decision = Transition.empty(Status.REPLAY);
        when(writer.cancel(RUN)).thenReturn(decision);

        assertThat(kernel.cancel(RUN)).isSameAs(decision);

        assertDecision("CANCEL", "REPLAY");
    }

    @Test
    void invalidationLogsDecision() {
        Transition<Void> decision = Transition.empty(Status.STALE);
        when(writer.invalidate(expected)).thenReturn(decision);

        assertThat(kernel.invalidate(expected)).isSameAs(decision);

        assertDecision("INVALIDATE", "STALE");
    }

    @Test
    void expiryLogsDecision() {
        Transition<Void> decision = Transition.empty(Status.EXPIRED);
        when(writer.expire(expected)).thenReturn(decision);

        assertThat(kernel.expire(expected)).isSameAs(decision);

        assertDecision("EXPIRE", "EXPIRED");
    }

    @Test
    void replacementLogsDecisionWithoutNewAttemptData() {
        Transition<RunSnapshot> decision = Transition.value(Status.APPLIED, snapshot());
        when(writer.replace(expected, attempt)).thenReturn(decision);

        assertThat(kernel.replace(expected, attempt)).isSameAs(decision);

        assertDecision("REPLACE", "APPLIED");
    }

    @Test
    void affectedRowRejectionRemainsDebugConflictWithoutWarning() {
        when(writer.bootstrap(expected, workload)).thenThrow(new AiRuntimeWriter.Rejected());

        assertThat(kernel.bootstrap(expected, workload)).isEqualTo(Transition.empty(Status.CONFLICT));

        assertDecision("BOOTSTRAP", "CONFLICT");
    }

    @ParameterizedTest
    @MethodSource("persistenceFailures")
    void persistenceFailureReturnsConflictAndWarnsWithoutException(RuntimeException failure) {
        when(writer.heartbeat(binding, 1)).thenThrow(failure);

        assertThat(kernel.heartbeat(binding, 1)).isEqualTo(Transition.empty(Status.CONFLICT));

        assertThat(events.list).hasSize(2);
        assertPersistenceFailure(events.list.getFirst(), "HEARTBEAT");
        assertEvent(events.list.getLast(), Level.DEBUG, "AI runtime operation=HEARTBEAT status=CONFLICT run=" + RUN);
    }

    @Test
    void createPersistenceFailureStillPropagatesWithoutExceptionLogging() {
        DataAccessResourceFailureException failure = new DataAccessResourceFailureException(CONTENT);
        when(writer.create(control, run, attempt)).thenThrow(failure);

        assertThatThrownBy(() -> kernel.create(control, run, attempt)).isSameAs(failure);

        assertThat(events.list).hasSize(1);
        assertPersistenceFailure(events.list.getFirst(), "CREATE");
    }

    @Test
    void snapshotPersistenceFailureStillPropagatesWithoutExceptionLogging() {
        CannotCreateTransactionException failure = new CannotCreateTransactionException(CONTENT);
        when(repository.snapshot(RUN)).thenThrow(failure);

        assertThatThrownBy(() -> kernel.snapshot(RUN)).isSameAs(failure);

        assertThat(events.list).hasSize(1);
        assertPersistenceFailure(events.list.getFirst(), "SNAPSHOT");
    }

    @Test
    void unrelatedWriterFailureStillPropagatesWithoutLoggingContent() {
        IllegalArgumentException failure = new IllegalArgumentException(CONTENT);
        when(writer.cancel(RUN)).thenThrow(failure);

        assertThatThrownBy(() -> kernel.cancel(RUN)).isSameAs(failure);

        assertThat(events.list).isEmpty();
    }

    @Test
    void controlSnapshotLogsNoProjectionOrEvidence() {
        ControlPins pins = ControlPins.forAttempt(attempt);
        ControlSnapshot snapshot = new ControlSnapshot(control, false, Optional.of(pins), Optional.empty(), NOW, NOW);
        Optional<ControlSnapshot> result = Optional.of(snapshot);
        when(repository.control()).thenReturn(result);

        assertThat(kernel.control()).isSameAs(result);

        assertControlDecision("CONTROL_SNAPSHOT", "PRESENT");
    }

    @Test
    void missingControlSnapshotIsAContentFreeDecision() {
        when(repository.control()).thenReturn(Optional.empty());

        assertThat(kernel.control()).isEmpty();

        assertControlDecision("CONTROL_SNAPSHOT", "ABSENT");
    }

    @ParameterizedTest
    @ValueSource(strings = {"CONTROL_CHANGE", "CONTROL_OBSERVE", "CONTROL_ENABLE", "CONTROL_DISABLE"})
    void controlTransitionsLogOnlyFixedMetadata(String operation) {
        ControlPins pins = ControlPins.forAttempt(attempt);
        ReadinessObservation evidence = new ReadinessObservation(control, pins, 1, CLAIM, NOW, NOW.plusSeconds(1));
        when(writer.changeControl(control, pins)).thenReturn(Transition.empty(Status.DENIED));
        when(writer.observeControl(evidence)).thenReturn(Transition.empty(Status.DENIED));
        when(writer.enableControl(control)).thenReturn(Transition.empty(Status.DENIED));
        when(writer.disableControl(control)).thenReturn(Transition.empty(Status.DENIED));

        Transition<?> result = switch (operation) {
            case "CONTROL_CHANGE" -> kernel.changeControl(control, pins);
            case "CONTROL_OBSERVE" -> kernel.observeControl(evidence);
            case "CONTROL_ENABLE" -> kernel.enableControl(control);
            default -> kernel.disableControl(control);
        };

        assertThat(result).isEqualTo(Transition.empty(Status.DENIED));
        assertControlDecision(operation, "DENIED");
    }

    private void assertControlDecision(String operation, String status) {
        assertThat(events.list).hasSize(1);
        ILoggingEvent event = events.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
        assertThat(event.getFormattedMessage())
                .isEqualTo("AI runtime operation=" + operation + " status=" + status + " run=null");
        assertThat(event.getArgumentArray()).containsExactly(operation, status, null);
        assertThat(event.getThrowableProxy()).isNull();
    }

    private static Stream<RuntimeException> persistenceFailures() {
        return Stream
                .of(new DataAccessResourceFailureException(CONTENT),
                        new CannotCreateTransactionException(CONTENT, new IllegalStateException(CONTENT)));
    }

    private RunSnapshot snapshot() {
        return new RunSnapshot(run, RunState.QUEUED, 1, 1, 1,
                new AttemptSnapshot(attempt, 1, AttemptState.LAUNCHING, 1, Optional.empty(), Optional.empty(), 2, NOW,
                        NOW),
                new LaunchSnapshot(attempt.launch(), "ilm-ai-synthetic", Optional.empty(), 0, CleanupState.NONE, NOW,
                        NOW),
                List.of(), 2, NOW, NOW);
    }

    private void assertDecision(String operation, String status) {
        assertThat(events.list).hasSize(1);
        assertEvent(events.list.getFirst(), Level.DEBUG,
                "AI runtime operation=" + operation + " status=" + status + " run=" + RUN);
    }

    private static void assertPersistenceFailure(ILoggingEvent event, String operation) {
        assertEvent(event, Level.WARN,
                "AI runtime persistence failure operation=" + operation + " status=UNAVAILABLE run=" + RUN);
    }

    private static void assertEvent(ILoggingEvent event, Level level, String message) {
        assertThat(event.getLevel()).isEqualTo(level);
        assertThat(event.getFormattedMessage())
                .isEqualTo(message)
                .doesNotContain(CONTENT, ACTOR.toString(), CLAIM.toString());
        assertThat(event.getThrowableProxy()).isNull();
        assertThat(event.getArgumentArray())
                .allSatisfy(argument -> assertThat(argument).isInstanceOfAny(String.class, UUID.class, Status.class));
    }
}
