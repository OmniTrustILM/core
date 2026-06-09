package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.Notification;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;
import java.util.UUID;

@Repository
public interface NotificationRepository extends SecurityFilterRepository<Notification, UUID> {

}
