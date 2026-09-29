package com.otilm.core.model.scheduler;

import com.otilm.api.model.core.scheduler.ScheduledJobScheduleState;
import com.otilm.api.model.scheduler.SchedulerJobDto;
import com.otilm.api.model.scheduler.SchedulerTriggerState;
import java.time.Instant;

/**
 * What the scheduler observes for one job: the state of its trigger and when it last fired and next fires. Two values
 * stand for what the scheduler did not say -- {@link #UNKNOWN} when it could not be read, {@link #NOT_SCHEDULED} when
 * it holds nothing for the job.
 */
public record ObservedSchedule(ScheduledJobScheduleState state, Instant nextFireTime, Instant previousFireTime) {

    public static final ObservedSchedule UNKNOWN = new ObservedSchedule(ScheduledJobScheduleState.UNKNOWN, null, null);

    public static final ObservedSchedule NOT_SCHEDULED = new ObservedSchedule(ScheduledJobScheduleState.NOT_SCHEDULED,
            null, null);

    /**
     * A paused trigger serves no next fire time: pausing leaves Quartz's frozen at an instant the trigger will not fire
     * at, which once passed would read as a scheduler that stopped firing. Its last fire still stands.
     */
    public static ObservedSchedule of(SchedulerJobDto job) {
        final ScheduledJobScheduleState state = stateOf(job.getTriggerState());
        final Instant nextFireTime = state == ScheduledJobScheduleState.PAUSED ? null : job.getNextFireTime();
        return new ObservedSchedule(state, nextFireTime, job.getPreviousFireTime());
    }

    /** Quartz's own state folded onto the operator's; a scheduler that reports none predates the field. */
    private static ScheduledJobScheduleState stateOf(SchedulerTriggerState triggerState) {
        if (triggerState == null) {
            return ScheduledJobScheduleState.UNKNOWN;
        }
        return switch (triggerState) {
            case NORMAL -> ScheduledJobScheduleState.SCHEDULED;
            case PAUSED -> ScheduledJobScheduleState.PAUSED;
            case BLOCKED -> ScheduledJobScheduleState.BLOCKED;
            case ERROR -> ScheduledJobScheduleState.ERROR;
            case COMPLETE -> ScheduledJobScheduleState.COMPLETE;
            case NONE -> ScheduledJobScheduleState.NOT_SCHEDULED;
        };
    }
}
