package com.otilm.core.dao.repository.notifications;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.notifications.PendingNotification;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface PendingNotificationRepository extends SecurityFilterRepository<PendingNotification, UUID> {

    PendingNotification findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(UUID notificationProfileUuid,
            Resource resource, UUID objectUuid, ResourceEvent event);

    /**
     * Records a successful send atomically: the first send inserts the suppression row with one repetition, every
     * conflicting send increments the count and refreshes {@code last_sent_at}. The pinned profile {@code version} is
     * deliberately never updated on conflict -- it anchors monitoring-stream continuity. {@code last_sent_at} is bound
     * by the caller from the application clock: the frequency-eligibility check compares it against application time,
     * so writing database time here would shift suppression windows by the clock skew.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}pending_notification (uuid, notification_profile_uuid, resource, object_uuid, event, version, repetitions, last_sent_at)
            VALUES (:uuid, :profileUuid, :resource, :objectUuid, :event, :version, 1, :lastSentAt)
            ON CONFLICT (notification_profile_uuid, resource, object_uuid, event)
            DO UPDATE SET repetitions = pending_notification.repetitions + 1, last_sent_at = EXCLUDED.last_sent_at
            """,
            nativeQuery = true)
    void upsertSent(@Param("uuid") UUID uuid, @Param("profileUuid") UUID profileUuid,
            @Param("resource") String resource, @Param("objectUuid") UUID objectUuid, @Param("event") String event,
            @Param("version") int version, @Param("lastSentAt") OffsetDateTime lastSentAt);

}
