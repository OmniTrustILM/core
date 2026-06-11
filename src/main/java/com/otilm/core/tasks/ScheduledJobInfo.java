package com.otilm.core.tasks;

import java.io.Serializable;
import java.util.UUID;

public record ScheduledJobInfo(String jobName, UUID jobUuid, UUID jobHistoryUuid) implements Serializable {

    public ScheduledJobInfo(String jobName) {
        this(jobName, null, null);
    }
}
