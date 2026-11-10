package com.otilm.core.messaging.model;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import java.util.UUID;
import lombok.Data;

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

    /**
     * The certificate request an issue was queued for. A registration whose completion was undone can take another
     * completion before the undone one's issue arrives, so that issue must not act on the request it finds. Null on
     * other actions, on the action an approval decision sends, and on messages queued before this field.
     */
    private UUID certificateRequestUuid;

}
