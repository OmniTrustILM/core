package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface NotificationInstanceMappedAttributeRepository
        extends
            SecurityFilterRepository<NotificationInstanceMappedAttributes, UUID> {
}
