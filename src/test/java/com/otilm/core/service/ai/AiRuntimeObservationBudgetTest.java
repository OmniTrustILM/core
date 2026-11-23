package com.otilm.core.service.ai;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.ControlSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Delegation and legacy compatibility only; actual SQL bounds are covered by PostgreSQL tests. */
@ExtendWith(MockitoExtension.class)
class AiRuntimeObservationBudgetTest {
    @Mock
    private AiRuntimeRepository repository;
    @Mock
    private AiRuntimeWriter writer;
    private AiRuntimeKernel kernel;
    private final AtomicLong nanos = new AtomicLong();
    private final Expected expected = new Expected(UUID.randomUUID(), UUID.randomUUID(), 1, 1);
    private final AiRuntimeOperationBudget budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(5), nanos::get);
    private final WorkloadObservation observation = observation();

    @BeforeEach
    void createKernel() {
        kernel = new AiRuntimeKernel(repository, writer, new AiFeatureGate(true));
    }

    @Test
    void preservesCallerBudget_whenReadingRunSnapshot() {
        // given
        Optional<RunSnapshot> absent = Optional.empty();
        when(writer.snapshot(expected.runId(), budget)).thenReturn(absent);

        // when
        Optional<RunSnapshot> result = kernel.snapshot(expected.runId(), budget);

        // then
        assertThat(result).isSameAs(absent);
        verify(writer).snapshot(expected.runId(), budget);
        verifyNoInteractions(repository);
    }

    @Test
    void preservesCallerBudget_whenReadingControl() {
        // given
        Optional<ControlSnapshot> absent = Optional.empty();
        when(writer.control(budget)).thenReturn(absent);

        // when
        Optional<ControlSnapshot> result = kernel.control(budget);

        // then
        assertThat(result).isSameAs(absent);
        verify(writer).control(budget);
        verifyNoInteractions(repository);
    }

    @Test
    void preservesCallerBudget_whenStoringObservation() {
        // given
        Transition<Void> decision = Transition.empty(Status.APPLIED);
        when(writer.observe(observation, budget)).thenReturn(decision);

        // when
        Transition<Void> result = kernel.observe(observation, budget);

        // then
        assertThat(result).isSameAs(decision);
        verify(writer).observe(observation, budget);
        verifyNoInteractions(repository);
    }

    @Test
    void preservesCallerBudget_whenInvalidatingCurrentAttempt() {
        // given
        Transition<Void> decision = Transition.empty(Status.APPLIED);
        when(writer.invalidate(expected, budget)).thenReturn(decision);

        // when
        Transition<Void> result = kernel.invalidate(expected, budget);

        // then
        assertThat(result).isSameAs(decision);
        verify(writer).invalidate(expected, budget);
        verifyNoInteractions(repository);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void rejectsExpiredCallerBudgetBeforePersistence_whenOperationIsBounded(Operation operation) {
        // given
        nanos.set(Duration.ofSeconds(5).toNanos());

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable invoke = () -> invoke(operation);

        // then
        assertThatThrownBy(invoke).isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        verifyNoInteractions(repository, writer);
    }

    @ParameterizedTest
    @EnumSource(Operation.class)
    void preservesStorageUncertainty_whenOperationIsBounded(Operation operation) {
        // given
        var failure = new DataAccessResourceFailureException("SYNTHETIC_PRIVATE_DATABASE_CANARY");
        switch (operation) {
            case SNAPSHOT -> when(writer.snapshot(expected.runId(), budget)).thenThrow(failure);
            case CONTROL -> when(writer.control(budget)).thenThrow(failure);
            case OBSERVE -> when(writer.observe(observation, budget)).thenThrow(failure);
            case INVALIDATE -> when(writer.invalidate(expected, budget)).thenThrow(failure);
        }

        // when
        org.assertj.core.api.ThrowableAssert.ThrowingCallable invoke = () -> invoke(operation);

        // then
        assertThatThrownBy(invoke).isSameAs(failure);
        verifyNoInteractions(repository);
    }

    @Test
    void keepsLegacyReadDelegation_whenTrustedMemoryComponentUsesOldArity() {
        // given
        Optional<RunSnapshot> absent = Optional.empty();
        when(repository.snapshot(expected.runId())).thenReturn(absent);

        // when
        Optional<RunSnapshot> result = kernel.snapshot(expected.runId());

        // then
        assertThat(result).isSameAs(absent);
        verifyNoInteractions(writer);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Object invoke(Operation operation) {
        return switch (operation) {
            case SNAPSHOT -> kernel.snapshot(expected.runId(), budget);
            case CONTROL -> kernel.control(budget);
            case OBSERVE -> kernel.observe(observation, budget);
            case INVALIDATE -> kernel.invalidate(expected, budget);
        };
    }

    private WorkloadObservation observation() {
        var attempt = AiRuntimeFixture.attempt(Instant.parse("2026-11-06T12:00:00Z"));
        var launch = attempt.launch();
        return new WorkloadObservation(expected, launch.cluster(), launch.namespaceName(), launch.namespaceUid(),
                launch.serviceAccountName(), launch.serviceAccountUid(), "job-one", "job-uid", "pod-one", "pod-uid",
                attempt.imageDigest(), launch.templateDigest(), launch.runtimeClass(), attempt.profileRevision(),
                attempt.securityRevision(), attempt.trustRevision(), attempt.protocol(), 1, attempt.maxDeadline(),
                true);
    }

    private enum Operation {
        SNAPSHOT,
        CONTROL,
        OBSERVE,
        INVALIDATE
    }
}
