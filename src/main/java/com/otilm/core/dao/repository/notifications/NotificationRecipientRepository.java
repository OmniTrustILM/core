package com.otilm.core.dao.repository.notifications;

import com.otilm.api.model.client.notification.NotificationDto;
import com.otilm.core.dao.entity.notifications.NotificationRecipient;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface NotificationRecipientRepository extends JpaRepository<NotificationRecipient, UUID> {

    @Query("""
            SELECT new com.otilm.api.model.client.notification.NotificationDto(
                n.uuid, n.message, n.detail, nr.readAt, n.sentAt, n.targetObjectType, n.targetObjectIdentification)
                FROM NotificationRecipient nr
                JOIN Notification n ON n.uuid = nr.notificationUuid
                WHERE nr.userUuid = ?1
                ORDER BY n.sentAt DESC
            """)
    Page<NotificationDto> findByUserUuid(UUID userUuid, Pageable pageable);

    @Query("""
            SELECT new com.otilm.api.model.client.notification.NotificationDto(
                n.uuid, n.message, n.detail, nr.readAt, n.sentAt, n.targetObjectType, n.targetObjectIdentification)
                FROM NotificationRecipient nr
                JOIN Notification n ON n.uuid = nr.notificationUuid
                WHERE nr.userUuid = ?1 AND nr.readAt IS NULL
                ORDER BY n.sentAt DESC
            """)
    Page<NotificationDto> findUnreadByUserUuid(UUID userUuid, Pageable pageable);

}
