package com.otilm.core.events.transaction;

import com.otilm.core.model.ScheduledTaskResult;
import com.otilm.core.tasks.ScheduledJobInfo;

public record ScheduledJobFinishedEvent(ScheduledJobInfo scheduledJobInfo, ScheduledTaskResult result) {
}
