package com.otilm.core.tasks;

import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.cbom.pqc.PqcVerdictSweeper;
import com.otilm.core.model.ScheduledTaskResult;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * What the operator reads in the scheduler history, which is the only place this job reports anything.
 *
 * <p>
 * The history row has to separate the three ways a row can leave the work list unwritten, because they call for
 * different actions: a refused row needs none, a failed write needs looking at, and a sweep that stopped early needs
 * both. And the row has to exist at all -- a failure of the sweep's own connection would otherwise propagate out of
 * {@code performJob}, roll the listener's transaction back with the STARTED row inside it, and leave a gap where an
 * operator would look for a failure.
 */
class CryptoAssetPqcSweepTaskTest {

    private final PqcVerdictSweeper sweeper = mock(PqcVerdictSweeper.class);

    private final CryptoAssetPqcSweepTask task = task();

    @Test
    void aSweepThatReadNothingIsSkippedRatherThanRecordedAsASuccess() {
        when(sweeper.sweep()).thenReturn(new PqcVerdictSweeper.SweepOutcome(true, false, 0, 0, 0, 0, 0));

        assertThatExceptionOfType(ScheduledJobSkippedException.class).isThrownBy(this::performJob);
    }

    @Test
    void aContendedSweepIsSkipped() {
        when(sweeper.sweep()).thenReturn(new PqcVerdictSweeper.SweepOutcome(false, false, 0, 0, 0, 0, 0));

        assertThatExceptionOfType(ScheduledJobSkippedException.class).isThrownBy(this::performJob);
    }

    /** Rows the guard refused are ordinary and retried next sweep, so they are reported without failing the run. */
    @Test
    void refusedRowsAreReportedAndDoNotFailTheRun() {
        when(sweeper.sweep()).thenReturn(new PqcVerdictSweeper.SweepOutcome(true, false, 5, 3, 0, 0, 1));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.SUCCESS);
        assertThat(result.getResultMessage())
                .contains("Read 5 stale cryptographic asset(s) in 1 batch(es)")
                .contains("3 verdict(s) written")
                .contains("2 refused and left for the next sweep");
    }

    /** Only stamps that landed are reported as recorded, so the count comes from the outcome and not from the reads. */
    @Test
    void aRowRecordedAsUnknownFailsTheRun() {
        when(sweeper.sweep()).thenReturn(new PqcVerdictSweeper.SweepOutcome(true, false, 4, 4, 1, 0, 1));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.FAILED);
        assertThat(result.getResultMessage()).contains("of which 1 recorded as UNKNOWN");
    }

    @Test
    void aRowThatCouldNotBeWrittenFailsTheRun() {
        when(sweeper.sweep()).thenReturn(new PqcVerdictSweeper.SweepOutcome(true, false, 4, 3, 0, 1, 1));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.FAILED);
        assertThat(result.getResultMessage()).contains("1 could not be written");
    }

    @Test
    void aSweepThatStoppedEarlyFailsTheRunWhateverItManagedToWrite() {
        when(sweeper.sweep()).thenReturn(new PqcVerdictSweeper.SweepOutcome(true, true, 2, 2, 0, 0, 1));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.FAILED);
        assertThat(result.getResultMessage()).startsWith("The sweep stopped before completing.");
    }

    /**
     * The sweep's own transaction can fail where it cannot report -- a failover, a pooler restart, an
     * {@code idle_in_transaction_session_timeout} killing a session that is idle between batches. Without this the
     * history has no row at all for the run, and the text is fixed because it reaches the Scheduler API.
     */
    @Test
    void aSweepThatCouldNotReportIsRecordedAsAFailureWithNoExceptionTextOnTheWire() {
        when(sweeper.sweep())
                .thenThrow(new IllegalStateException("Unable to rollback against JDBC Connection: core.crypto_asset"));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.FAILED);
        assertThat(result.getResultMessage())
                .isEqualTo("The sweep failed before it could report its outcome; see the application log");
    }

    private ScheduledTaskResult performJob() {
        return task.performJob(null, null);
    }

    private CryptoAssetPqcSweepTask task() {
        CryptoAssetPqcSweepTask created = new CryptoAssetPqcSweepTask();
        created.setSweeper(sweeper);
        return created;
    }
}
