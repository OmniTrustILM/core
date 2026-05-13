package com.czertainly.core.messaging.model;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.other.ResourceEvent;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;
import java.util.UUID;

@Getter
@ToString
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class NotificationMessage {

    private ResourceEvent event;

    private Resource resource;

    private UUID objectUuid;

    private List<UUID> notificationProfileUuids;

    private List<NotificationRecipient> recipients;

    private UUID triggerHistoryUuid;

    private UUID executionUuid;

    private Object data;

    public NotificationMessage(ResourceEvent event, Resource resource, UUID objectUuid, List<UUID> notificationProfileUuids, List<NotificationRecipient> recipients, Object data) {
        this.event = event;
        this.resource = resource;
        this.objectUuid = objectUuid;
        this.notificationProfileUuids = notificationProfileUuids;
        this.recipients = recipients;
        this.data = data;
    }

    public NotificationMessage(ResourceEvent event, Resource resource, UUID objectUuid, List<UUID> notificationProfileUuids, List<NotificationRecipient> recipients, Object data,  UUID triggerHistoryUuid, UUID executionUuid) {
        this(event, resource, objectUuid, notificationProfileUuids, recipients, data);
        this.triggerHistoryUuid = triggerHistoryUuid;
        this.executionUuid = executionUuid;
    }

}
