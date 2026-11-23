package com.otilm.core.service.ai;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import java.time.Instant;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AiFeatureKernelAdmissionTest {
    @Mock
    private AiRuntimeRepository repository;
    @Mock
    private AiRuntimeWriter writer;
    private AiRuntimeKernel kernel;
    private final Instant now = Instant.parse("2026-11-06T12:00:00Z");
    private final RunSpec run = AiRuntimeFixture.run(now);
    private final AttemptSpec attempt = AiRuntimeFixture.attempt(now);
    private final Expected expected = new Expected(run.runId(), attempt.attemptId(), 1, 1);
    private final WorkloadRef workload = new WorkloadRef("cluster-one", "pod-one");
    private final ClaimBinding claim = new ClaimBinding(run.runId(), attempt.attemptId(), workload, UUID.randomUUID(),
            1);
    private final AiRuntimeOperationBudget budget = AiRuntimeOperationBudget.start(() -> 0L);

    @BeforeEach
    void disableNewExecution() {
        kernel = new AiRuntimeKernel(repository, writer, new AiFeatureGate(false));
    }

    // ── New operations ────────────────────────────────────────────────────────

    @Nested
    class NewOperations {
        @ParameterizedTest
        @EnumSource(Admission.class)
        void deniesAdmissionBeforePersistence_whenFeatureIsDisabled(Admission admission) {
            // given
            var observation = new WorkloadObservation(expected, workload.cluster(), "ai-proof", "namespace-one",
                    "runner", "account-one", "job-one", "job-uid", "pod-one", workload.podUid(), attempt.imageDigest(),
                    attempt.launch().templateDigest(), "sandbox", 1, 1, 1, "v1", 1, now.plusSeconds(30), true);

            // when
            Transition<?> result = switch (admission) {
                case ENABLE_CONTROL -> kernel.enableControl(new ControlVersion(1));
                case OBSERVE -> kernel.observe(observation);
                case BOUNDED_OBSERVE -> kernel.observe(observation, budget);
                case BOOTSTRAP -> kernel.bootstrap(expected, workload);
                case BOUNDED_BOOTSTRAP -> kernel.bootstrap(expected, workload, budget);
                case HEARTBEAT -> kernel.heartbeat(claim, 1);
                case BOUNDED_HEARTBEAT -> kernel.heartbeat(claim, 1, budget);
                case REPLACE -> kernel.replace(expected, attempt);
            };

            // then
            assertThat(result.status()).isEqualTo(Status.DENIED);
            assertThat(result.value()).isEmpty();
            verifyNoInteractions(repository, writer);
        }

        @Test
        void rejectsRunCreationBeforePersistence_whenFeatureIsDisabled() {
            // given
            var version = new ControlVersion(1);

            // when
            ThrowingCallable create = () -> kernel.create(version, run, attempt);

            // then
            assertThatThrownBy(create).isInstanceOf(AccessDeniedException.class).hasNoCause();
            verifyNoInteractions(repository, writer);
        }
    }

    // ── Safety operations ─────────────────────────────────────────────────────

    @Nested
    class SafetyOperations {
        @Test
        void cancelsExistingRun_whenNewExecutionIsDisabled() {
            // given
            Transition<Void> applied = Transition.empty(Status.APPLIED);
            when(writer.cancel(run.runId())).thenReturn(applied);

            // when
            Transition<Void> result = kernel.cancel(run.runId());

            // then
            assertThat(result).isSameAs(applied);
            verify(writer).cancel(run.runId());
            verifyNoInteractions(repository);
        }

        @Test
        void disablesDurableControl_whenNewExecutionIsDisabled() {
            // given
            var version = new ControlVersion(1);
            Transition<Void> applied = Transition.empty(Status.APPLIED);
            when(writer.disableControl(version)).thenReturn(applied);

            // when
            Transition<Void> result = kernel.disableControl(version);

            // then
            assertThat(result).isSameAs(applied);
            verify(writer).disableControl(version);
        }

        @Test
        void invalidatesExistingAttempt_whenNewExecutionIsDisabled() {
            // given
            Transition<Void> applied = Transition.empty(Status.APPLIED);
            when(writer.invalidate(expected)).thenReturn(applied);

            // when
            Transition<Void> result = kernel.invalidate(expected);

            // then
            assertThat(result).isSameAs(applied);
            verify(writer).invalidate(expected);
        }

        @Test
        void expiresExistingAttempt_whenNewExecutionIsDisabled() {
            // given
            Transition<Void> applied = Transition.empty(Status.APPLIED);
            when(writer.expire(expected)).thenReturn(applied);

            // when
            Transition<Void> result = kernel.expire(expected);

            // then
            assertThat(result).isSameAs(applied);
            verify(writer).expire(expected);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private enum Admission {
        ENABLE_CONTROL,
        OBSERVE,
        BOUNDED_OBSERVE,
        BOOTSTRAP,
        BOUNDED_BOOTSTRAP,
        HEARTBEAT,
        BOUNDED_HEARTBEAT,
        REPLACE
    }
}
