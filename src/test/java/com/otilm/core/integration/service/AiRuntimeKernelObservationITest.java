package com.otilm.core.integration.service;

import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.Claim;
import com.otilm.core.model.ai.AiRuntimeState.FailureReason;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.lang.reflect.RecordComponent;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

class AiRuntimeKernelObservationITest extends BaseAiSpringBootTest {
    private static final WorkloadRef FIRST = new WorkloadRef("cluster-one", "pod-one");
    private static final WorkloadRef SECOND = new WorkloadRef("cluster-one", "pod-two");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeKernel kernel;
    private RunSnapshot created;

    @BeforeEach
    void createRun() throws Exception {
        AiRuntimeFixture.install(dataSource);
        Instant now = AiRuntimeFixture.now(dataSource);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
    }

    @ParameterizedTest(name = "{0} mismatch cannot register a workload")
    @MethodSource("pinMismatches")
    void everyImmutableObservationPinIsCheckedBeforeAnyWrite(String component, Object wrong) throws Exception {
        WorkloadObservation different = changed(observation(created, FIRST, 1, true), component, wrong);

        assertThat(kernel.observe(different).status()).isEqualTo(Status.DENIED);

        assertThat(current()).isEqualTo(created);
    }

    static Stream<Arguments> pinMismatches() {
        return Stream
                .of(Arguments.of("cluster", "different-cluster"), Arguments.of("namespaceName", "different-namespace"),
                        Arguments.of("namespaceUid", "different-namespace-uid"),
                        Arguments.of("serviceAccountName", "different-account"),
                        Arguments.of("serviceAccountUid", "different-account-uid"),
                        Arguments.of("jobName", "different-job"),
                        Arguments.of("imageDigest", "sha256:" + "c".repeat(64)),
                        Arguments.of("templateDigest", "sha256:" + "c".repeat(64)),
                        Arguments.of("runtimeClass", "different-sandbox"), Arguments.of("profileRevision", 2L),
                        Arguments.of("securityRevision", 2L), Arguments.of("trustRevision", 2L));
    }

    @Test
    void unclaimedForeignJobUidFencesInsteadOfAdoptingNewJob() throws Exception {
        assertThat(kernel.observe(observation(created, FIRST, 1, true)).status()).isEqualTo(Status.APPLIED);
        RunSnapshot before = current();
        WorkloadObservation foreign = changed(observation(before, SECOND, 1, true), "jobUid", "different-job-uid");

        assertThat(kernel.observe(foreign).status()).isEqualTo(Status.CONFLICT);

        RunSnapshot fenced = current();
        assertThat(fenced.state()).isEqualTo(RunState.FAILED);
        assertThat(fenced.attempt().state()).isEqualTo(AttemptState.FENCED);
        assertThat(fenced.attempt().failure()).contains(FailureReason.JOB_CONFLICT);
        assertThat(fenced.launch().jobUid()).isEqualTo(before.launch().jobUid());
        assertThat(fenced.revision()).isEqualTo(before.revision() + 1);
        assertThat(fenced.fence()).isEqualTo(before.fence() + 1);
        assertThat(fenced.workloads()).hasSize(1);
        assertThat(kernel.bootstrap(expected(fenced), FIRST).value()).isEmpty();
    }

    @Test
    void foreignJobUidFromLoserCannotFenceEstablishedWinner() throws Exception {
        assertThat(kernel.observe(observation(created, FIRST, 1, true)).status()).isEqualTo(Status.APPLIED);
        Claim winner = kernel.bootstrap(expected(current()), FIRST).value().orElseThrow();
        RunSnapshot before = current();
        WorkloadObservation foreign = changed(observation(before, SECOND, 1, true), "jobUid", "different-job-uid");

        assertThat(kernel.observe(foreign).status()).isEqualTo(Status.CONFLICT);

        assertThat(current()).isEqualTo(before);
        assertThat(current().attempt().claim()).contains(winner);
    }

    @Test
    void observationCannotChangePodNameSequenceOrRegistrationHistory() throws Exception {
        assertThat(kernel.observe(observation(created, FIRST, 2, true)).status()).isEqualTo(Status.APPLIED);
        RunSnapshot before = current();
        List<WorkloadObservation> conflicts = List
                .of(observation(before, FIRST, 1, true), observation(before, FIRST, 2, false),
                        observation(before, FIRST, 3, false),
                        changed(observation(before, FIRST, 3, true), "podName", "different-pod-name"));
        for (WorkloadObservation conflict : conflicts) {
            assertThat(kernel.observe(conflict).status()).isEqualTo(Status.CONFLICT);
            assertThat(current()).isEqualTo(before);
        }
    }

    @Test
    void expiredAndOverlongObservationCannotSetAnyBinding() throws Exception {
        Instant now = AiRuntimeFixture.now(dataSource);
        assertThat(kernel.observe(observation(created, FIRST, 1, now.minusSeconds(1), true)).status())
                .isEqualTo(Status.DENIED);
        assertThat(kernel
                .observe(observation(created, FIRST, 1, created.attempt().spec().maxDeadline().plusSeconds(1), true))
                .status()).isEqualTo(Status.DENIED);
        assertThat(current()).isEqualTo(created);
    }

    @Test
    void closedPodsBlockReplacementWithoutSpendingAttemptBudget() throws Exception {
        assertThat(kernel.observe(observation(created, FIRST, 1, true)).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.observe(observation(current(), SECOND, 1, true)).status()).isEqualTo(Status.APPLIED);
        expireLaunch();
        RunSnapshot fenced = current();

        assertThat(kernel.replace(expected(fenced), replacement()).status()).isEqualTo(Status.LIMIT_REACHED);
        assertThat(current()).isEqualTo(fenced);
        assertThat(kernel.replace(expected(fenced), replacement()).status()).isEqualTo(Status.LIMIT_REACHED);
        assertThat(current()).isEqualTo(fenced);
    }

    @Test
    void oldPodUidCannotMoveToReplacementWhenAnotherSlotIsAvailable() throws Exception {
        assertThat(kernel.observe(observation(created, FIRST, 1, true)).status()).isEqualTo(Status.APPLIED);
        expireLaunch();
        assertThat(kernel.replace(expected(current()), replacement()).status()).isEqualTo(Status.APPLIED);
        RunSnapshot replaced = current();

        assertThat(kernel.observe(observation(replaced, FIRST, 2, true)).status()).isEqualTo(Status.DENIED);
        assertThat(current()).isEqualTo(replaced);
        assertThat(current().workloads()).isEmpty();
        assertThat(kernel.observe(observation(replaced, SECOND, 1, true)).status()).isEqualTo(Status.APPLIED);
        assertThat(current().workloads()).singleElement().satisfies(row -> assertThat(row.ref()).isEqualTo(SECOND));
    }

    private void expireLaunch() throws Exception {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        UPDATE ai_runtime_attempt SET launch_deadline = clock_timestamp() - interval '1 second'
                        WHERE uuid = ?
                        """)) {
            statement.setObject(1, created.attempt().spec().attemptId());
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
        assertThat(kernel.expire(expected(current())).status()).isEqualTo(Status.APPLIED);
    }

    private AttemptSpec replacement() {
        AttemptSpec original = created.attempt().spec();
        return new AttemptSpec(UUID.randomUUID(), original.launchDeadline(), original.maxDeadline(),
                original.imageDigest(), original.profileRevision(), original.securityRevision(),
                original.trustRevision(), original.protocol(), original.launch());
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private static WorkloadObservation changed(WorkloadObservation source, String field, Object value)
            throws Exception {
        RecordComponent[] fields = WorkloadObservation.class.getRecordComponents();
        Object[] values = new Object[fields.length];
        boolean found = false;
        for (int i = 0; i < fields.length; i++) {
            values[i] = fields[i].getAccessor().invoke(source);
            if (fields[i].getName().equals(field)) {
                values[i] = value;
                found = true;
            }
        }
        assertThat(found).as("requested observation component exists").isTrue();
        return WorkloadObservation.class
                .getDeclaredConstructor(Arrays.stream(fields).map(RecordComponent::getType).toArray(Class<?>[]::new))
                .newInstance(values);
    }
}
