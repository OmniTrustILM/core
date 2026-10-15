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
     * A paused or errored trigger serves no next fire time: Quartz leaves the stored one in place, and the trigger will
     * not fire at it -- a paused one until it is resumed, an errored one at all, since Quartz never acquires it again.
     * Once passed, that instant would read as a scheduler that stopped firing. The last fire still stands.
     *
     * <p>
     * A job read as not scheduled or unknown serves neither fire time, whatever came beside the state. The scheduler
     * reads a trigger and then its state, so a trigger deleted between the two reads reports NONE with the fire times
     * of the trigger it no longer holds; and a scheduler that reports no state does not vouch for the times it sends.
     */
    public static ObservedSchedule of(SchedulerJobDto job) {
        final ScheduledJobScheduleState state = stateOf(job.getTriggerState());
        return switch (state) {
            case NOT_SCHEDULED, UNKNOWN -> new ObservedSchedule(state, null, null);
            case PAUSED, ERROR -> new ObservedSchedule(state, null, job.getPreviousFireTime());
            default -> new ObservedSchedule(state, job.getNextFireTime(), job.getPreviousFireTime());
        };
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
