package com.otilm.core.tasks;

import com.otilm.core.model.ScheduledTaskResult;

public interface ScheduledJobTask {

    String getDefaultJobName();

    String getDefaultCronExpression();

    boolean isDefaultOneTimeJob();

    String getJobClassName();

    boolean isSystemJob();

    ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData);

}
