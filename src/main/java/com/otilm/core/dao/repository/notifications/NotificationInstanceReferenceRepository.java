package com.otilm.core.dao.repository.notifications;

import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Repository;

@Repository
public interface NotificationInstanceReferenceRepository
        extends
            SecurityFilterRepository<NotificationInstanceReference, UUID> {

    Optional<NotificationInstanceReference> findByUuid(UUID uuid);

    /**
     * Loads the reference with its mapped attributes fetched eagerly, for callers that run without an ambient
     * transaction and would otherwise hit the lazy association detached.
     */
    @EntityGraph(attributePaths = "mappedAttributes")
    Optional<NotificationInstanceReference> findWithMappedAttributesByUuid(UUID uuid);

    Optional<NotificationInstanceReference> findByName(String name);
}
