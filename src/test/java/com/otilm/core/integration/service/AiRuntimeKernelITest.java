package com.otilm.core.integration.service;

import com.otilm.core.model.ai.AiRuntimeState.AttemptSpec;
import com.otilm.core.model.ai.AiRuntimeState.AttemptState;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.service.ai.AiRuntimeKernel;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeKernelITest extends BaseAiSpringBootTest {
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeKernel kernel;
    private ControlVersion control;

    @BeforeEach
    void installActualMigration() throws Exception {
        AiRuntimeFixture.install(dataSource);
        control = AiRuntimeFixture.enableTestControl(kernel, AiRuntimeFixture.now(dataSource));
    }

    @Test
    void createIsAtomicAndSnapshotDetached() throws Exception {
        Instant before = AiRuntimeFixture.now(dataSource);
        RunSpec run = AiRuntimeFixture.run(before);
        AttemptSpec attempt = AiRuntimeFixture.attempt(before);

        RunSnapshot created = kernel.create(control, run, attempt);

        assertThat(created.spec()).isEqualTo(run);
        assertThat(created.state()).isEqualTo(RunState.QUEUED);
        assertThat(created.revision()).isEqualTo(1);
        assertThat(created.fence()).isEqualTo(1);
        assertThat(created.attemptsUsed()).isEqualTo(1);
        assertThat(created.attempt().spec()).isEqualTo(attempt);
        assertThat(created.attempt().state()).isEqualTo(AttemptState.LAUNCHING);
        assertThat(created.attempt().claim()).isEmpty();
        assertThat(created.launch().jobName()).isEqualTo("ilm-ai-" + attempt.attemptId().toString().replace("-", ""));
        assertThat(created.launch().jobUid()).isEmpty();
        assertThat(created.launch().cleanup()).isEqualTo(CleanupState.NONE);
        assertThat(created.createdAt()).isAfterOrEqualTo(before);
        assertThat(created.updatedAt()).isEqualTo(created.createdAt());
        assertThat(created.workloads()).isEmpty();
        assertRows(1, 1, 1, 0);

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE ai_runtime_run SET revision = 2");
        }
        assertThat(created.revision()).isEqualTo(1);
        assertThat(kernel.snapshot(run.runId()).orElseThrow().revision()).isEqualTo(2);
        assertThat(kernel.snapshot(UUID.randomUUID())).isEmpty();
        var workloads = created.workloads();
        assertThatThrownBy(() -> workloads.add(null)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void duplicateCreationCannotLeaveAnotherAttemptOrLaunch() throws Exception {
        Instant now = AiRuntimeFixture.now(dataSource);
        RunSpec run = AiRuntimeFixture.run(now);
        AttemptSpec first = AiRuntimeFixture.attempt(now);
        kernel.create(control, run, first);

        AttemptSpec second = AiRuntimeFixture.attempt(now);
        assertThatThrownBy(() -> kernel.create(control, run, second))
                .isInstanceOf(DataIntegrityViolationException.class);

        assertRows(1, 1, 1, 0);
        assertThat(kernel.snapshot(run.runId()).orElseThrow().attempt().spec()).isEqualTo(first);
    }

    @Test
    void expiredOrInconsistentDeadlinesLeaveNoPartialState() throws Exception {
        Instant now = AiRuntimeFixture.now(dataSource);
        RunSpec ordinary = AiRuntimeFixture.run(now);
        RunSpec expired = new RunSpec(ordinary.runId(), ordinary.conversationRef(), ordinary.actorId(),
                ordinary.scopeMarker(), ordinary.attemptLimit(), ordinary.podLimit(), ordinary.leaseSeconds(),
                now.minusSeconds(1));

        AttemptSpec initial = AiRuntimeFixture.attempt(now);
        assertThatThrownBy(() -> kernel.create(control, expired, initial))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Runtime deadlines do not permit creation");
        assertRows(0, 0, 0, 0);

        AttemptSpec tooLong = new AttemptSpec(initial.attemptId(), initial.launchDeadline(),
                ordinary.runDeadline().plusSeconds(1), initial.imageDigest(), initial.profileRevision(),
                initial.securityRevision(), initial.trustRevision(), initial.protocol(), initial.launch());
        assertThatThrownBy(() -> kernel.create(control, ordinary, tooLong))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Runtime deadlines do not permit creation");
        assertRows(0, 0, 0, 0);
    }

    private void assertRows(int runs, int attempts, int launches, int workloads) throws Exception {
        String[] tables = {"ai_runtime_run", "ai_runtime_attempt", "ai_runtime_launch", "ai_runtime_workload"};
        int[] counts = {runs, attempts, launches, workloads};
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            for (int index = 0; index < tables.length; index++) {
                try (ResultSet result = statement.executeQuery("SELECT count(*) FROM " + tables[index])) {
                    assertThat(result.next()).isTrue();
                    assertThat(result.getInt(1)).as(tables[index]).isEqualTo(counts[index]);
                }
            }
        }
    }
}
