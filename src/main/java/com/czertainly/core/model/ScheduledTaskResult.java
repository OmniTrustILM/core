package com.czertainly.core.model;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScheduledTaskResult {

    private SchedulerJobExecutionStatus status;
    private String resultMessage;
    private Resource resultObjectType;
    private String resultObjectIdentification;

    public ScheduledTaskResult(SchedulerJobExecutionStatus status, String resultMessage) {
        this.status = status;
        this.resultMessage = resultMessage;
    }

}
