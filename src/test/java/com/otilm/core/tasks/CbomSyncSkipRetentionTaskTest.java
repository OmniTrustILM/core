package com.otilm.core.tasks;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.api.ScheduledJobSkippedException;
import com.otilm.core.cbom.sync.CbomSyncSkipRetentionSweeper;
import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.settings.SettingsCache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * What the operator reads in the scheduler history, the one place this job reports anything. The settings cache is
 * JVM-wide static state, so the retention the task should read is seeded here and the previous entry put back after.
 */
class CbomSyncSkipRetentionTaskTest {

    private static final int RETENTION_DAYS = 45;

    private final CbomSyncSkipRetentionSweeper sweeper = mock(CbomSyncSkipRetentionSweeper.class);
    private final CbomSyncSkipRetentionTask task = task();
    private PlatformSettingsDto originalPlatformSettings;

    @BeforeEach
    void seedTheRetention() {
        originalPlatformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        UtilsSettingsDto utils = new UtilsSettingsDto();
        utils.setCbomSyncSkipRetentionDays(RETENTION_DAYS);
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setUtils(utils);
        new SettingsCache().cacheSettings(SettingsSection.PLATFORM, platform);
    }

    @AfterEach
    void restoreTheCache() {
        new SettingsCache()
                .cacheSettings(SettingsSection.PLATFORM,
                        originalPlatformSettings != null ? originalPlatformSettings : new PlatformSettingsDto());
    }

    @Test
    void aContendedSweepIsSkipped() {
        when(sweeper.sweep(anyInt())).thenReturn(CbomSyncSkipRetentionSweeper.SweepOutcome.skipped());

        assertThatExceptionOfType(ScheduledJobSkippedException.class).isThrownBy(this::performJob);
    }

    @Test
    void aSweepThatRemovedNothingIsSkippedRatherThanRecordedAsASuccess() {
        when(sweeper.sweep(anyInt()))
                .thenReturn(new CbomSyncSkipRetentionSweeper.SweepOutcome(true, false, 0, 1, false));

        assertThatExceptionOfType(ScheduledJobSkippedException.class).isThrownBy(this::performJob);
    }

    @Test
    void aSweepThatRemovedRecordsReportsHowManyAndTheRetentionItApplied() {
        when(sweeper.sweep(RETENTION_DAYS))
                .thenReturn(new CbomSyncSkipRetentionSweeper.SweepOutcome(true, false, 12, 1, false));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.SUCCESS);
        assertThat(result.getResultMessage())
                .contains("Removed 12 record(s)")
                .contains(RETENTION_DAYS + " day(s)")
                .contains("1 batch(es)");
        assertThat(result.getResultObjectType()).isEqualTo(Resource.CBOM);
    }

    @Test
    void aCappedSweepSaysTheRestGoesOnTheNextRun() {
        when(sweeper.sweep(anyInt()))
                .thenReturn(new CbomSyncSkipRetentionSweeper.SweepOutcome(true, false, 10_000, 20, true));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.SUCCESS);
        assertThat(result.getResultMessage()).contains("next run");
    }

    @Test
    void anAbortedSweepFailsTheRunWhateverItManagedToRemove() {
        when(sweeper.sweep(anyInt()))
                .thenReturn(new CbomSyncSkipRetentionSweeper.SweepOutcome(true, true, 500, 1, false));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.FAILED);
        assertThat(result.getResultMessage()).contains("stopped before completing").contains("Removed 500 record(s)");
    }

    /** The text is fixed: an exception message here would reach the scheduler API. */
    @Test
    void aSweeperThatThrowsFailsTheRunWithAFixedMessage() {
        when(sweeper.sweep(anyInt())).thenThrow(new IllegalStateException("driver text that must not be served"));

        ScheduledTaskResult result = performJob();

        assertThat(result.getStatus()).isEqualTo(SchedulerJobExecutionStatus.FAILED);
        assertThat(result.getResultMessage()).doesNotContain("driver text").contains("application log");
    }

    @Test
    void theJobIsADailySystemJob() {
        assertThat(task.getDefaultJobName()).isEqualTo(CbomSyncSkipRetentionTask.NAME);
        assertThat(task.isSystemJob()).isTrue();
        assertThat(task.isDefaultOneTimeJob()).isFalse();
        assertThat(task.getDefaultCronExpression()).isEqualTo("0 15 3 ? * *");
    }

    private CbomSyncSkipRetentionTask task() {
        CbomSyncSkipRetentionTask created = new CbomSyncSkipRetentionTask();
        created.setSweeper(sweeper);
        return created;
    }

    private ScheduledTaskResult performJob() {
        return task.performJob(new ScheduledJobInfo(CbomSyncSkipRetentionTask.NAME, null, null), null);
    }
}
