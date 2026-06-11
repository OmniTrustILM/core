package com.otilm.core.dao.repository.notifications;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.notifications.PendingNotification;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface PendingNotificationRepository extends SecurityFilterRepository<PendingNotification, UUID> {

    PendingNotification findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(UUID notificationProfileUuid, Resource resource, UUID objectUuid, ResourceEvent event);

}
