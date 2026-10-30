package com.otilm.core.service.writer;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writer half of the notification listener's orchestrator/writer pair. Records a successful notification delivery --
 * external, internal, or both -- as an atomic upsert so concurrent notification consumers cannot create duplicate
 * suppression rows for one (profile, resource, object, event). REQUIRED propagation so it composes: joins an ambient
 * transaction when present, starts a short one otherwise.
 */
@Service
public class PendingNotificationWriter {

    private final PendingNotificationRepository pendingNotificationRepository;

    @Autowired
    public PendingNotificationWriter(PendingNotificationRepository pendingNotificationRepository) {
        this.pendingNotificationRepository = pendingNotificationRepository;
    }

    @Transactional
    public void recordSent(UUID notificationProfileUuid, Resource resource, UUID objectUuid, ResourceEvent event,
            int pinnedVersion) {
        // Application clock, matching the frequency-eligibility comparison in the listener --
        // one clock source for both the write and the read keeps suppression windows skew-free.
        pendingNotificationRepository
                .upsertSent(UUID.randomUUID(), notificationProfileUuid, resource.name(), objectUuid, event.name(),
                        pinnedVersion, OffsetDateTime.now());
    }
}
