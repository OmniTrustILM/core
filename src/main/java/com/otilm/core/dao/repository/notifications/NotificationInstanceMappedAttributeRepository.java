package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface NotificationInstanceMappedAttributeRepository extends SecurityFilterRepository<NotificationInstanceMappedAttributes, UUID> {
}
