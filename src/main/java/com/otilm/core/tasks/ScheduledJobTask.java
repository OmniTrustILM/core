package com.otilm.core.tasks;

import com.otilm.core.model.ScheduledTaskResult;

public interface ScheduledJobTask {

    String getDefaultJobName();

    String getDefaultCronExpression();

    boolean isDefaultOneTimeJob();

    /**
     * The class the scheduler stores in {@code scheduled_job.job_class_name} and resolves a run back through.
     *
     * <p>
     * Defaulted because every implementation answered it identically, and the one answer that is correct: the concrete
     * class, so a subclass is stored as itself rather than as whatever base it inherits the plumbing from.
     */
    default String getJobClassName() {
        return this.getClass().getName();
    }

    boolean isSystemJob();

    ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData);

}
