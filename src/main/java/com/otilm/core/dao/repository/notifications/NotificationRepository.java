package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.Notification;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface NotificationRepository extends SecurityFilterRepository<Notification, UUID> {

}
