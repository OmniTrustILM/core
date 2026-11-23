package com.otilm.core.model.ai;

import com.otilm.core.model.ai.AiRuntimeState.AttemptSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.ClaimBinding;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadState;
import com.otilm.core.util.AiRuntimeFixture;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeStateTest {
    private static final Instant NOW = Instant.parse("2026-10-29T12:00:00Z");

    @ParameterizedTest
    @MethodSource("records")
    void recordsRejectNullComponents(Class<?> type, Object[] arguments) throws Exception {
        RecordComponent[] components = type.getRecordComponents();
        Constructor<?> constructor = type
                .getDeclaredConstructor(
                        Arrays.stream(components).map(RecordComponent::getType).toArray(Class<?>[]::new));
        assertThat(constructor.newInstance(arguments)).isInstanceOf(type);
        for (int index = 0; index < components.length; index++) {
            if (!components[index].getType().isPrimitive()) {
                Object[] invalid = arguments.clone();
                invalid[index] = null;
                assertThatThrownBy(() -> constructor.newInstance(invalid))
                        .as(type.getSimpleName() + "." + components[index].getName())
                        .isInstanceOf(InvocationTargetException.class)
                        .cause()
                        .isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
            }
        }
    }

    @Test
    void runBoundsAcceptBothEdgesAndRejectAdjacentValues() {
        RunSpec base = AiRuntimeFixture.run(NOW);
        assertThat(withBounds(base, 1, 2, 1)).isNotNull();
        assertThat(withBounds(base, 10, 16, 60)).isNotNull();
        for (int[] values : new int[][]{{0, 2, 1}, {11, 2, 1}, {1, 1, 1}, {1, 17, 1}, {1, 2, 0}, {1, 2, 61}}) {
            assertThatThrownBy(() -> withBounds(base, values[0], values[1], values[2]))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void opaqueReferencesAndDigestsAreBoundedWithoutEchoingValues() {
        for (String invalid : List.of("", " ", "x".repeat(129))) {
            assertThatThrownBy(() -> new WorkloadRef(invalid, "pod"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid runtime identifier length");
            assertThatThrownBy(() -> new WorkloadRef("cluster", invalid)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(new WorkloadRef("x".repeat(128), "y".repeat(128))).isNotNull();
        for (String invalid : List.of("image:latest", "sha256:" + "A".repeat(64), "sha256:" + "a".repeat(63))) {
            assertThatThrownBy(() -> new LaunchSpec("cluster", "namespace", "namespace-id", "account", "account-id",
                    invalid, "sandbox"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid runtime image or template digest");
        }
    }

    @Test
    void attemptOrderingProtocolAndRevisionsCannotBeForged() {
        AttemptSpec base = AiRuntimeFixture.attempt(NOW);
        UUID attemptId = base.attemptId();
        Instant launchDeadline = base.launchDeadline();
        Instant maxDeadline = base.maxDeadline();
        Instant lateLaunch = maxDeadline.plusSeconds(1);
        String imageDigest = base.imageDigest();
        LaunchSpec launch = base.launch();
        assertThatThrownBy(
                () -> new AttemptSpec(attemptId, lateLaunch, maxDeadline, imageDigest, 1, 1, 1, "v1", launch))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                () -> new AttemptSpec(attemptId, launchDeadline, maxDeadline, imageDigest, 1, 1, 1, "v2", launch))
                .isInstanceOf(IllegalArgumentException.class);
        for (long[] revisions : new long[][]{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}}) {
            assertThatThrownBy(() -> new AttemptSpec(attemptId, launchDeadline, maxDeadline, imageDigest, revisions[0],
                    revisions[1], revisions[2], "v1", launch)).isInstanceOf(IllegalArgumentException.class);
        }
        UUID runId = UUID.randomUUID();
        UUID claimId = UUID.randomUUID();
        WorkloadRef ref = new WorkloadRef("cluster", "pod");
        ClaimBinding binding = new ClaimBinding(runId, attemptId, ref, claimId, 1);
        assertThatThrownBy(() -> new ClaimBinding(runId, attemptId, ref, claimId, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Claim(binding, NOW, -1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectedTransitionsNeverCarryProtectedValues() {
        for (Status status : Status.values()) {
            assertThat(Transition.empty(status).value()).isEmpty();
            if (status == Status.APPLIED || status == Status.REPLAY) {
                assertThat(Transition.value(status, "stored-claim").value()).contains("stored-claim");
            } else {
                assertThatThrownBy(() -> Transition.value(status, "stored-claim"))
                        .isInstanceOf(IllegalArgumentException.class);
            }
        }
    }

    @Test
    void expectedRevisionsAndObservationProtocolAreValidated() {
        UUID runId = UUID.randomUUID();
        UUID attemptId = UUID.randomUUID();
        assertThatThrownBy(() -> new Expected(runId, attemptId, 0, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Expected(runId, attemptId, 1, 0)).isInstanceOf(IllegalArgumentException.class);
        AttemptSpec attempt = AiRuntimeFixture.attempt(NOW);
        Expected expected = new Expected(runId, attemptId, 1, 1);
        assertThat(observationWithProtocol(expected, attempt, "v1")).isNotNull();
        assertThatThrownBy(() -> observationWithProtocol(expected, attempt, "v2"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static RunSpec withBounds(RunSpec source, int attempts, int pods, int leaseSeconds) {
        return new RunSpec(source.runId(), source.conversationRef(), source.actorId(), source.scopeMarker(), attempts,
                pods, leaseSeconds, source.runDeadline());
    }

    private static WorkloadObservation observationWithProtocol(Expected expected, AttemptSpec attempt,
            String protocol) {
        LaunchSpec launch = attempt.launch();
        return new WorkloadObservation(expected, launch.cluster(), launch.namespaceName(), launch.namespaceUid(),
                launch.serviceAccountName(), launch.serviceAccountUid(), "ilm-ai-job", "job-uid", "pod", "pod-uid",
                attempt.imageDigest(), launch.templateDigest(), launch.runtimeClass(), 1, 1, 1, protocol, 1,
                NOW.plusSeconds(1), true);
    }

    static Stream<Arguments> records() {
        RunSpec run = AiRuntimeFixture.run(NOW);
        AttemptSpec attempt = AiRuntimeFixture.attempt(NOW);
        LaunchSpec launch = attempt.launch();
        WorkloadRef ref = new WorkloadRef("cluster-one", "pod-one");
        ClaimBinding binding = new ClaimBinding(run.runId(), attempt.attemptId(), ref, UUID.randomUUID(), 1);
        AttemptSnapshot attemptSnapshot = new AttemptSnapshot(attempt, 1, AttemptState.LAUNCHING, 1, Optional.empty(),
                Optional.empty(), 0, NOW, NOW);
        LaunchSnapshot launchSnapshot = new LaunchSnapshot(launch, "ilm-ai-job", Optional.empty(), 0, CleanupState.NONE,
                NOW, NOW);
        RunSnapshot snapshot = new RunSnapshot(run, RunState.QUEUED, 1, 1, 1, attemptSnapshot, launchSnapshot,
                List.of(), 0, NOW, NOW);
        WorkloadObservation observation = AiRuntimeFixture.observation(snapshot, ref, 1, true);
        return Stream
                .of(Arguments
                        .of(RunSpec.class,
                                new Object[]{
                                        run.runId(),
                                        run.conversationRef(),
                                        run.actorId(),
                                        run.scopeMarker(),
                                        2,
                                        2,
                                        5,
                                        run.runDeadline()}),
                        Arguments
                                .of(LaunchSpec.class,
                                        new Object[]{
                                                launch.cluster(),
                                                launch.namespaceName(),
                                                launch.namespaceUid(),
                                                launch.serviceAccountName(),
                                                launch.serviceAccountUid(),
                                                launch.templateDigest(),
                                                launch.runtimeClass()}),
                        Arguments
                                .of(AttemptSpec.class,
                                        new Object[]{
                                                attempt.attemptId(),
                                                attempt.launchDeadline(),
                                                attempt.maxDeadline(),
                                                attempt.imageDigest(),
                                                1L,
                                                1L,
                                                1L,
                                                "v1",
                                                launch}),
                        Arguments.of(Expected.class, new Object[]{run.runId(), attempt.attemptId(), 1L, 1L}),
                        Arguments.of(Transition.class, new Object[]{Status.APPLIED, Optional.empty()}),
                        Arguments
                                .of(WorkloadObservation.class,
                                        new Object[]{
                                                observation.expected(),
                                                observation.cluster(),
                                                observation.namespaceName(),
                                                observation.namespaceUid(),
                                                observation.serviceAccountName(),
                                                observation.serviceAccountUid(),
                                                observation.jobName(),
                                                observation.jobUid(),
                                                observation.podName(),
                                                observation.podUid(),
                                                observation.imageDigest(),
                                                observation.templateDigest(),
                                                observation.runtimeClass(),
                                                observation.profileRevision(),
                                                observation.securityRevision(),
                                                observation.trustRevision(),
                                                observation.protocol(),
                                                observation.sequence(),
                                                observation.validUntil(),
                                                observation.registered()}),
                        Arguments.of(WorkloadRef.class, new Object[]{ref.cluster(), ref.podUid()}),
                        Arguments
                                .of(ClaimBinding.class,
                                        new Object[]{binding.runId(), binding.attemptId(), ref, binding.claimId(), 1L}),
                        Arguments.of(Claim.class, new Object[]{binding, NOW, 0L}),
                        Arguments
                                .of(AttemptSnapshot.class,
                                        new Object[]{
                                                attempt,
                                                1,
                                                AttemptState.LAUNCHING,
                                                1L,
                                                Optional.empty(),
                                                Optional.empty(),
                                                0L,
                                                NOW,
                                                NOW}),
                        Arguments
                                .of(LaunchSnapshot.class,
                                        new Object[]{
                                                launch,
                                                "ilm-ai-job",
                                                Optional.empty(),
                                                0L,
                                                CleanupState.NONE,
                                                NOW,
                                                NOW}),
                        Arguments
                                .of(WorkloadSnapshot.class,
                                        new Object[]{
                                                ref,
                                                "pod",
                                                "job",
                                                WorkloadState.ELIGIBLE,
                                                1L,
                                                NOW,
                                                Optional.empty(),
                                                Optional.empty(),
                                                0,
                                                Optional.empty(),
                                                NOW,
                                                NOW}),
                        Arguments
                                .of(RunSnapshot.class,
                                        new Object[]{
                                                run,
                                                RunState.QUEUED,
                                                1L,
                                                1L,
                                                1,
                                                attemptSnapshot,
                                                launchSnapshot,
                                                List.of(),
                                                0L,
                                                NOW,
                                                NOW}));
    }
}
