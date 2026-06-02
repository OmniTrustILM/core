package com.czertainly.core.dao.repository.notifications;

import com.czertainly.core.dao.entity.notifications.NotificationProfileVersion;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface NotificationProfileVersionRepository extends SecurityFilterRepository<NotificationProfileVersion, UUID> {

    @EntityGraph(attributePaths = {"notificationProfile", "notificationInstance"})
    Optional<NotificationProfileVersion> findByNotificationProfileUuidAndVersion(UUID notificationProfileUuid, int version);

    @EntityGraph(attributePaths = {"notificationProfile", "notificationInstance"})
    Optional<NotificationProfileVersion> findTopByNotificationProfileUuidOrderByVersionDesc(UUID notificationProfileUuid);

    @Query("""
            SELECT np.name
            FROM NotificationProfileVersion npv JOIN npv.notificationProfile np
            WHERE npv.notificationInstanceRefUuid = :uuid
            AND npv.version = (
                SELECT MAX(npv2.version) FROM NotificationProfileVersion npv2
                WHERE npv2.notificationProfileUuid = npv.notificationProfileUuid
            )
            """)
    List<String> findCurrentVersionProfileNamesByNotificationInstanceRefUuid(@Param("uuid") UUID uuid);

    @Query("""
            UPDATE NotificationProfileVersion npv SET npv.notificationInstanceRefUuid = NULL
            WHERE npv.notificationInstanceRefUuid = :uuid
            AND npv.version < (
                SELECT MAX(npv2.version) FROM NotificationProfileVersion npv2
                WHERE npv2.notificationProfileUuid = npv.notificationProfileUuid
            )
            """)
    @Modifying
    void detachHistoricalInstanceReferencesByNotificationInstanceRefUuid(@Param("uuid") UUID uuid);

    @Query("""
            UPDATE NotificationProfileVersion npv SET npv.notificationInstanceRefUuid = NULL
            WHERE npv.notificationInstanceRefUuid = :uuid
            """)
    @Modifying
    int detachNotificationInstanceRefUuid(@Param("uuid") UUID uuid);
}
