package com.otilm.core.messaging.model;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import lombok.Data;

import java.util.UUID;

@Data
public class ActionMessage {
    private Resource resource;

    private ResourceAction resourceAction;

    private UUID resourceUuid;

    private UUID userUuid;

    private Object data;

    private Resource approvalProfileResource;

    private UUID approvalProfileResourceUuid;

    private UUID approvalUuid;

    private ApprovalStatusEnum approvalStatus;

}
