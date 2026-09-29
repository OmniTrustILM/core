package com.otilm.core.model.scheduler;

import com.otilm.api.model.scheduler.SchedulerJobDto;
import com.otilm.api.model.scheduler.SchedulerResponseDto;
import com.otilm.api.model.scheduler.SchedulerStatus;
import java.util.HashMap;
import java.util.Map;

/**
 * One read of the scheduler, keyed by job name: the answer to "what do you hold for this job" for every job on a page,
 * so a page costs one call rather than one per job.
 */
public final class ObservedSchedules {

    private static final ObservedSchedules UNAVAILABLE = new ObservedSchedules(null);

    /** Null when the scheduler could not be read; an empty map when it answered and holds no job. */
    private final Map<String, ObservedSchedule> byJobName;

    private ObservedSchedules(Map<String, ObservedSchedule> byJobName) {
        this.byJobName = byJobName;
    }

    /** The scheduler could not be read: every job is {@link ObservedSchedule#UNKNOWN}. */
    public static ObservedSchedules unavailable() {
        return UNAVAILABLE;
    }

    /**
     * An answer that carries no job list -- an empty body, a status other than OK -- is a scheduler that could not be
     * read, not one that holds no job.
     */
    public static ObservedSchedules of(SchedulerResponseDto response) {
        if (response == null || response.getSchedulerStatus() != SchedulerStatus.OK
                || response.getSchedulerJobList() == null) {
            return UNAVAILABLE;
        }
        final Map<String, ObservedSchedule> byJobName = new HashMap<>();
        for (SchedulerJobDto job : response.getSchedulerJobList()) {
            if (job != null && job.getJobName() != null) {
                byJobName.putIfAbsent(job.getJobName(), ObservedSchedule.of(job));
            }
        }
        return new ObservedSchedules(byJobName);
    }

    public boolean isAvailable() {
        return byJobName != null;
    }

    /** {@link ObservedSchedule#UNKNOWN} while unread; {@link ObservedSchedule#NOT_SCHEDULED} for a job not held. */
    public ObservedSchedule forJob(String jobName) {
        if (byJobName == null) {
            return ObservedSchedule.UNKNOWN;
        }
        return byJobName.getOrDefault(jobName, ObservedSchedule.NOT_SCHEDULED);
    }
}
