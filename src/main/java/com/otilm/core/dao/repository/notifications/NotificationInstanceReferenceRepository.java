package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface NotificationInstanceReferenceRepository extends SecurityFilterRepository<NotificationInstanceReference, UUID> {

    Optional<NotificationInstanceReference> findByUuid(UUID uuid);

    Optional<NotificationInstanceReference> findByName(String name);
}
