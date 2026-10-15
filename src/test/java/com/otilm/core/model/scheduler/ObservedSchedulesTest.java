package com.otilm.core.model.scheduler;

import com.otilm.api.model.core.scheduler.ScheduledJobScheduleState;
import com.otilm.api.model.scheduler.SchedulerJobDto;
import com.otilm.api.model.scheduler.SchedulerResponseDto;
import com.otilm.api.model.scheduler.SchedulerStatus;
import com.otilm.api.model.scheduler.SchedulerTriggerState;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The pure half of the scheduler read: what one answer says about a job, and what no answer says. */
class ObservedSchedulesTest {

    private static final Instant NEXT = Instant.parse("2026-09-29T12:30:00Z");
    private static final Instant PREVIOUS = Instant.parse("2026-09-29T11:30:00Z");

    @Test
    void anUnreadSchedulerLeavesEveryJobUnknown() {
        ObservedSchedules observed = ObservedSchedules.unavailable();

        assertFalse(observed.isAvailable());
        assertSame(ObservedSchedule.UNKNOWN, observed.forJob("CryptoAssetPqcSweepTask"));
    }

    @Test
    void anEmptyBodyIsAnUnreadScheduler() {
        assertFalse(ObservedSchedules.of(null).isAvailable());
    }

    @Test
    void anAnswerWithoutAJobListIsAnUnreadScheduler() {
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.OK);

        assertFalse(ObservedSchedules.of(response).isAvailable());
    }

    @Test
    void anAnswerThatIsNotOkIsAnUnreadScheduler() {
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.ERROR);
        response.setSchedulerJobList(List.of(live("CryptoAssetPqcSweepTask")));

        assertFalse(ObservedSchedules.of(response).isAvailable());
        assertSame(ObservedSchedule.UNKNOWN, ObservedSchedules.of(response).forJob("CryptoAssetPqcSweepTask"));
    }

    @Test
    void aJobTheSchedulerDoesNotHoldIsNotScheduled() {
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.OK);
        response.setSchedulerJobList(List.of());

        ObservedSchedules observed = ObservedSchedules.of(response);

        assertTrue(observed.isAvailable());
        assertSame(ObservedSchedule.NOT_SCHEDULED, observed.forJob("CryptoAssetPqcSweepTask"));
    }

    @Test
    void aLiveTriggerIsScheduledWithItsFireTimes() {
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.OK);
        response.setSchedulerJobList(List.of(live("CryptoAssetPqcSweepTask")));

        ObservedSchedule schedule = ObservedSchedules.of(response).forJob("CryptoAssetPqcSweepTask");

        assertEquals(ScheduledJobScheduleState.SCHEDULED, schedule.state());
        assertEquals(NEXT, schedule.nextFireTime());
        assertEquals(PREVIOUS, schedule.previousFireTime());
    }

    @ParameterizedTest
    @CsvSource({
            "NORMAL,SCHEDULED",
            "PAUSED,PAUSED",
            "BLOCKED,BLOCKED",
            "ERROR,ERROR",
            "COMPLETE,COMPLETE",
            "NONE,NOT_SCHEDULED"})
    void everyTriggerStateHasAScheduleState(SchedulerTriggerState triggerState, ScheduledJobScheduleState expected) {
        SchedulerJobDto job = live("job");
        job.setTriggerState(triggerState);

        assertEquals(expected, ObservedSchedule.of(job).state());
    }

    /**
     * Pausing leaves Quartz's next fire time frozen at an instant the trigger will not fire at, and once that instant
     * passes it would read as a scheduler that stopped firing. None is served while paused; the last fire still stands.
     */
    @Test
    void aPausedTriggerServesNoNextFireTimeButKeepsItsLastFire() {
        SchedulerJobDto job = live("job");
        job.setTriggerState(SchedulerTriggerState.PAUSED);

        ObservedSchedule schedule = ObservedSchedule.of(job);

        assertEquals(ScheduledJobScheduleState.PAUSED, schedule.state());
        assertNull(schedule.nextFireTime());
        assertEquals(PREVIOUS, schedule.previousFireTime());
    }

    /**
     * Quartz keeps the stored next fire time when it moves a trigger to ERROR and never acquires an errored trigger
     * again, so that instant will not happen either. None is served; the last fire still stands.
     */
    @Test
    void anErroredTriggerServesNoNextFireTimeButKeepsItsLastFire() {
        SchedulerJobDto job = live("job");
        job.setTriggerState(SchedulerTriggerState.ERROR);

        ObservedSchedule schedule = ObservedSchedule.of(job);

        assertEquals(ScheduledJobScheduleState.ERROR, schedule.state());
        assertNull(schedule.nextFireTime());
        assertEquals(PREVIOUS, schedule.previousFireTime());
    }

    /** A scheduler that predates the field answers no state: as good as unread for that job, not "no trigger". */
    @Test
    void aJobWithoutATriggerStateIsUnknown() {
        SchedulerJobDto job = new SchedulerJobDto("job", "0 30 * ? * *", "com.otilm.core.tasks.Task");

        ObservedSchedule schedule = ObservedSchedule.of(job);

        assertEquals(ScheduledJobScheduleState.UNKNOWN, schedule.state());
        assertNull(schedule.nextFireTime());
    }

    /**
     * The scheduler reads a trigger and then its state, so a trigger deleted between the two reads reports NONE with
     * the fire times of the trigger it no longer holds. They are not served.
     */
    @Test
    void aTriggerReportedAsGoneServesNoFireTimes() {
        SchedulerJobDto job = live("job");
        job.setTriggerState(SchedulerTriggerState.NONE);

        ObservedSchedule schedule = ObservedSchedule.of(job);

        assertEquals(ScheduledJobScheduleState.NOT_SCHEDULED, schedule.state());
        assertNull(schedule.nextFireTime());
        assertNull(schedule.previousFireTime());
    }

    /** Fire times beside no state are not vouched for by the scheduler that sent them, and are not served. */
    @Test
    void aJobWithoutATriggerStateServesNoFireTimes() {
        SchedulerJobDto job = live("job");
        job.setTriggerState(null);

        ObservedSchedule schedule = ObservedSchedule.of(job);

        assertEquals(ScheduledJobScheduleState.UNKNOWN, schedule.state());
        assertNull(schedule.nextFireTime());
        assertNull(schedule.previousFireTime());
    }

    /**
     * A scheduler that predates the trigger fields lists its jobs without a state, and says nothing about the jobs it
     * does not list either: read as not scheduled, those would contradict the listed ones read as unknown. One listed
     * job without a state makes the whole answer unread.
     */
    @Test
    void anAnswerListingAJobWithoutATriggerStateIsAnUnreadScheduler() {
        SchedulerJobDto withoutState = live("CryptoAssetPqcSweepTask");
        withoutState.setTriggerState(null);
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.OK);
        response.setSchedulerJobList(List.of(live("CbomSyncTask"), withoutState));

        ObservedSchedules observed = ObservedSchedules.of(response);

        assertFalse(observed.isAvailable());
        assertSame(ObservedSchedule.UNKNOWN, observed.forJob("CryptoAssetPqcSweepTask"));
        assertSame(ObservedSchedule.UNKNOWN, observed.forJob("CbomSyncTask"));
        assertSame(ObservedSchedule.UNKNOWN, observed.forJob("CbomReconcileTask"));
    }

    /** An entry that names no job cannot be any job's: it is passed over, and the rest of the answer still counts. */
    @Test
    void anEntryWithoutAJobIsIgnored() {
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.OK);
        response.setSchedulerJobList(Arrays.asList(null, live(null), live("job")));

        ObservedSchedules observed = ObservedSchedules.of(response);

        assertTrue(observed.isAvailable());
        assertEquals(ScheduledJobScheduleState.SCHEDULED, observed.forJob("job").state());
        assertSame(ObservedSchedule.NOT_SCHEDULED, observed.forJob(null));
    }

    @Test
    void theFirstOfTwoEntriesForOneJobNameWins() {
        SchedulerJobDto first = live("job");
        SchedulerJobDto second = live("job");
        second.setTriggerState(SchedulerTriggerState.PAUSED);
        SchedulerResponseDto response = new SchedulerResponseDto(SchedulerStatus.OK);
        response.setSchedulerJobList(List.of(first, second));

        assertEquals(ScheduledJobScheduleState.SCHEDULED, ObservedSchedules.of(response).forJob("job").state());
    }

    private static SchedulerJobDto live(String jobName) {
        SchedulerJobDto job = new SchedulerJobDto(jobName, "0 30 * ? * *", "com.otilm.core.tasks.Task");
        job.setTriggerState(SchedulerTriggerState.NORMAL);
        job.setNextFireTime(NEXT);
        job.setPreviousFireTime(PREVIOUS);
        return job;
    }
}
